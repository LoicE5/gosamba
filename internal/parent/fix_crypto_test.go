package parent

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/ntlm"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// --- client-side handshake harness -----------------------------------------
//
// These tests play the client half of NEGOTIATE + SESSION_SETUP so the keys the
// server derives can be compared against keys computed independently here.

// fixCryptoNegotiate builds a 3.1.1 NEGOTIATE request advertising SHA-512
// preauth and exactly one cipher, so the test picks what gets negotiated.
func fixCryptoNegotiate(cipher smb2.Cipher) []byte {
	hdr := make([]byte, smb2.HeaderSize)
	_ = smb2.EncodeHeader(hdr, smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandNegotiate,
	})

	fixed := make([]byte, 36)
	fixed[0] = 36 // StructureSize
	fixed[2] = 1  // DialectCount
	fixed[4] = byte(smb2.NegotiateSigningEnabled)
	fixed[8] = byte(smb2.CapEncryption)
	for i := range 16 {
		fixed[12+i] = 0xBB // ClientGuid
	}
	binary.LittleEndian.PutUint32(fixed[28:], uint32(smb2.HeaderSize+40)) // ctx offset
	binary.LittleEndian.PutUint16(fixed[32:], 2)                          // ctx count

	body := append([]byte(nil), fixed...)
	body = append(body, 0x11, 0x03) // dialect 3.1.1
	body = append(body, 0x00, 0x00) // pad to the context offset

	preauth := append([]byte{0x01, 0x00, 0x20, 0x00, 0x01, 0x00}, bytes.Repeat([]byte{0xC1}, 32)...)
	ctx := make([]byte, 8)
	binary.LittleEndian.PutUint16(ctx[0:], uint16(smb2.CtxPreauthIntegrityCaps))
	binary.LittleEndian.PutUint16(ctx[2:], uint16(len(preauth)))
	body = append(body, ctx...)
	body = append(body, preauth...)
	for len(body)%8 != 0 {
		body = append(body, 0x00)
	}

	enc := make([]byte, 4)
	binary.LittleEndian.PutUint16(enc[0:], 1) // CipherCount
	binary.LittleEndian.PutUint16(enc[2:], uint16(cipher))
	ctx2 := make([]byte, 8)
	binary.LittleEndian.PutUint16(ctx2[0:], uint16(smb2.CtxEncryptionCaps))
	binary.LittleEndian.PutUint16(ctx2[2:], uint16(len(enc)))
	body = append(body, ctx2...)
	body = append(body, enc...)

	return append(hdr, body...)
}

// fixCryptoHarness is one negotiated connection plus the handler under test.
//
// It is wired the way ServeConn wires a real connection — its own session
// table, a dispatcher that owns the connection-scoped tables, and a sessionHost
// registered in a SessionIndex — so PreviousSessionId behaves here exactly as
// it does in production. index is shared between two harnesses by
// fixSessionConnectedPair to model two TCP connections on one server.
type fixCryptoHarness struct {
	h     *SessionSetupHandler
	conn  *Connection
	pipe  *rwPipe
	out   *bytes.Buffer
	index *SessionIndex
	host  *sessionHost
	disp  *Dispatcher
	// basePreauth is the connection preauth chain right after NEGOTIATE,
	// snapshotted before any SESSION_SETUP so the expected per-session chains
	// can be rebuilt without trusting the server's own bookkeeping.
	basePreauth *smb2.PreauthHash
}

func newFixCryptoHarness(t *testing.T, cipher smb2.Cipher, users []config.UserConfig) *fixCryptoHarness {
	t.Helper()
	return newFixCryptoHarnessIndexed(t, cipher, users, NewSessionIndex())
}

// newFixCryptoHarnessIndexed is newFixCryptoHarness with the server-scoped
// session index supplied, so two harnesses can model two TCP connections on one
// server — which is what a cross-connection PreviousSessionId needs.
func newFixCryptoHarnessIndexed(t *testing.T, cipher smb2.Cipher, users []config.UserConfig,
	index *SessionIndex) *fixCryptoHarness {
	t.Helper()
	in := &bytes.Buffer{}
	if err := transport.WriteFrame(in, fixCryptoNegotiate(cipher)); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	pipe := &rwPipe{in: in, out: out}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))

	conn, err := Negotiate(pipe, NegotiatorOptions{}, lg)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if conn.Selection.Cipher != cipher {
		t.Fatalf("negotiated cipher 0x%04x, want 0x%04x", conn.Selection.Cipher, cipher)
	}
	if _, err := transport.ReadFrame(out, transport.MaxFrameSize); err != nil {
		t.Fatalf("drain negotiate response: %v", err)
	}

	tbl := NewSessionTable()
	disp := &Dispatcher{
		Conn:     conn,
		Sessions: tbl,
		Log:      lg,
		locks:    sharedLockManager,
		async:    &asyncTable{},
		Index:    index,
	}
	host := &sessionHost{sessions: tbl, disp: disp, conn: conn, log: lg}
	return &fixCryptoHarness{
		h: &SessionSetupHandler{
			Conn:     conn,
			Sessions: tbl,
			Users:    users,
			Log:      lg,
			Index:    index,
			Host:     host,
		},
		conn:        conn,
		pipe:        pipe,
		out:         out,
		index:       index,
		host:        host,
		disp:        disp,
		basePreauth: forkPreauth(conn.Preauth),
	}
}

// sessionSetupFrame wraps an NTLMSSP blob in a SESSION_SETUP request frame.
func sessionSetupFrame(secBuf []byte, msgID, sessID uint64) (smb2.Header, []byte, []byte) {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 25) // StructureSize
	body[3] = byte(smb2.NegotiateSigningEnabled)
	binary.LittleEndian.PutUint16(body[12:], uint16(smb2.HeaderSize+24)) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[14:], uint16(len(secBuf)))
	body = append(body, secBuf...)

	hdr := smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandSessionSetup,
		MessageID:    msgID,
		SessionID:    sessID,
	}
	frame := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(frame[:smb2.HeaderSize], hdr)
	copy(frame[smb2.HeaderSize:], body)
	return hdr, body, frame
}

// fixCryptoLeg1 runs the NTLMSSP type-1 leg and returns the negotiate message
// sent, the challenge message received, the request/response frames (for
// rebuilding the preauth chain) and the allocated session id.
type fixCryptoLeg1 struct {
	negotiate  []byte
	challenge  []byte
	reqFrame   []byte
	respFrame  []byte
	sessionID  uint64
	challenge8 [8]byte
}

func (hs *fixCryptoHarness) leg1(t *testing.T, msgID uint64) fixCryptoLeg1 {
	t.Helper()
	// Drop any already-consumed response still sitting in the write buffer so
	// the challenge below is the first frame we read back.
	hs.out.Reset()

	// A 40-byte NEGOTIATE_MESSAGE: fixed part plus the Version field, with
	// empty domain/workstation — what a real client sends.
	neg := make([]byte, 40)
	copy(neg[0:8], ntlm.Signature[:])
	binary.LittleEndian.PutUint32(neg[8:], ntlm.MessageTypeNegotiate)
	binary.LittleEndian.PutUint32(neg[12:], ntlm.NegotiateUnicode|ntlm.NegotiateNTLM|
		ntlm.NegotiateExtendedSessionSecurity|ntlm.NegotiateAlwaysSign|ntlm.NegotiateVersion)

	hdr, body, frame := sessionSetupFrame(neg, msgID, 0)
	sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
	if err != nil {
		t.Fatalf("type-1 leg: %v", err)
	}
	if sess != nil {
		t.Fatal("type-1 leg returned an authenticated session")
	}

	resp, err := transport.ReadFrame(hs.out, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	respHdr, err := smb2.DecodeHeader(resp[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if smb2.Status(respHdr.Status) != smb2.StatusMoreProcessingReq {
		t.Fatalf("challenge status 0x%08X", respHdr.Status)
	}
	// WrapNTLMResp puts the responseToken last, so everything from the NTLMSSP
	// signature to the end of the frame is exactly the CHALLENGE_MESSAGE.
	chal, err := smb2.UnwrapNTLM(resp[smb2.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}

	out := fixCryptoLeg1{
		negotiate: neg,
		challenge: chal,
		reqFrame:  frame,
		respFrame: resp,
		sessionID: respHdr.SessionID,
	}
	copy(out.challenge8[:], chal[24:32])
	return out
}

// fixCryptoAuth is a fully-built client AUTHENTICATE plus the session key the
// client would derive from it.
type fixCryptoAuth struct {
	message    []byte // the AUTHENTICATE_MESSAGE alone
	secBuf     []byte // what goes in the SESSION_SETUP security buffer
	sessionKey []byte // ExportedSessionKey (no key exchange: == SessionBaseKey)
}

// buildAuthenticate assembles an NTLMv2 AUTHENTICATE for user/password against
// the given challenge. withMIC sets the MsvAvFlags MIC bit and fills in a MIC
// computed here, by hand, rather than through the ntlm package — so the test
// checks the server's verification against the spec formula, not against
// itself. spnegoTail appends bytes after the message, standing in for the
// mechListMIC a real SPNEGO negTokenResp carries.
func buildAuthenticate(t *testing.T, leg fixCryptoLeg1, user, domain, password string, withMIC bool, spnegoTail []byte) fixCryptoAuth {
	t.Helper()
	ntHash := userdb.NTHash(password)
	ntowf := ntlm.NTOWFv2(ntHash, user, domain)

	temp := make([]byte, 28)
	temp[0], temp[1] = 0x01, 0x01 // RespType, HiRespType
	binary.LittleEndian.PutUint64(temp[8:], 0x01D0000000000000)
	copy(temp[16:24], []byte("clichal8"))

	avs := []ntlm.AVPair{{ID: ntlm.AVNbDomainName, Value: ntlm.UTF16LE("GOSAMBA")}}
	if withMIC {
		v := make([]byte, 4)
		binary.LittleEndian.PutUint32(v, ntlm.AVFlagMICPresent)
		avs = append(avs, ntlm.AVPair{ID: ntlm.AVFlags, Value: v})
	}
	temp = append(temp, ntlm.EncodeAVList(avs)...)

	proof := hmacMD5(ntowf[:], leg.challenge8[:], temp)
	ntResp := append(append([]byte(nil), proof...), temp...)
	sessionKey := hmacMD5(ntowf[:], proof)

	const fixedLen = 88 // 64 + Version(8) + MIC(16)
	msg := make([]byte, fixedLen)
	copy(msg[0:8], ntlm.Signature[:])
	binary.LittleEndian.PutUint32(msg[8:], ntlm.MessageTypeAuthenticate)
	binary.LittleEndian.PutUint32(msg[60:], ntlm.NegotiateUnicode|ntlm.NegotiateNTLM|
		ntlm.NegotiateExtendedSessionSecurity|ntlm.NegotiateVersion)

	put := func(fieldOff int, payload []byte) {
		binary.LittleEndian.PutUint16(msg[fieldOff:], uint16(len(payload)))
		binary.LittleEndian.PutUint16(msg[fieldOff+2:], uint16(len(payload)))
		binary.LittleEndian.PutUint32(msg[fieldOff+4:], uint32(len(msg)))
		msg = append(msg, payload...)
	}
	put(12, nil) // LmChallengeResponse
	put(20, ntResp)
	put(28, ntlm.UTF16LE(domain))
	put(36, ntlm.UTF16LE(user))
	put(44, ntlm.UTF16LE("CLIENT"))
	put(52, nil) // EncryptedRandomSessionKey (no NEGOTIATE_KEY_EXCH)

	if withMIC {
		// MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE ||
		// AUTHENTICATE-with-MIC-zeroed), MS-NLMP §3.1.5.1.2.
		mic := hmacMD5(sessionKey, leg.negotiate, leg.challenge, msg)
		copy(msg[ntlm.MICFieldOffset:ntlm.MICFieldOffset+16], mic)
	}

	return fixCryptoAuth{
		message:    msg,
		secBuf:     append(append([]byte(nil), msg...), spnegoTail...),
		sessionKey: sessionKey,
	}
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

func fixCryptoUsers(password string) []config.UserConfig {
	return []config.UserConfig{{
		Name:        "alice",
		NTHash:      userdb.NTHash(password),
		SystemUser:  "nobody",
		SystemUID:   65534,
		SystemGID:   65534,
		AllowShares: []string{"*"},
	}}
}

// --- finding 1: AES-256 key length -----------------------------------------

// TestFixCrypto_CipherKeyLengthMatchesNegotiatedCipher is the regression test
// for AES-256 sessions being dead on arrival: the ciphers were advertised
// 256-bit-first but every key was derived at 128 bits, so newAEAD rejected them
// and no encrypted frame could be produced at all.
func TestFixCrypto_CipherKeyLengthMatchesNegotiatedCipher(t *testing.T) {
	cases := []struct {
		cipher smb2.Cipher
		keyLen int
	}{
		{smb2.CipherAES256GCM, 32},
		{smb2.CipherAES128GCM, 16},
		{smb2.CipherAES128CCM, 16},
	}
	for _, tc := range cases {
		hs := newFixCryptoHarness(t, tc.cipher, fixCryptoUsers("test123"))
		leg := hs.leg1(t, 1)
		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)

		hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
		sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
		if err != nil {
			t.Fatalf("cipher 0x%04x: type-3 leg: %v", tc.cipher, err)
		}
		if sess == nil {
			t.Fatalf("cipher 0x%04x: no session returned", tc.cipher)
		}

		if len(sess.S2CCipherKey) != tc.keyLen {
			t.Errorf("cipher 0x%04x: S2C key %d bytes, want %d", tc.cipher, len(sess.S2CCipherKey), tc.keyLen)
		}
		if len(sess.C2SCipherKey) != tc.keyLen {
			t.Errorf("cipher 0x%04x: C2S key %d bytes, want %d", tc.cipher, len(sess.C2SCipherKey), tc.keyLen)
		}
		// Signing stays AES-128-CMAC/GMAC whatever the cipher is.
		if len(sess.SigningKey) != 16 {
			t.Errorf("cipher 0x%04x: signing key %d bytes, want 16", tc.cipher, len(sess.SigningKey))
		}
		if len(sess.ApplicationKey) != 16 {
			t.Errorf("cipher 0x%04x: application key %d bytes, want 16", tc.cipher, len(sess.ApplicationKey))
		}

		// The keys must actually work end to end.
		plain := []byte("an encrypted SMB2 message body")
		enc, err := smb3.EncryptTransform(uint16(tc.cipher), sess.S2CCipherKey, sess.ID, plain)
		if err != nil {
			t.Fatalf("cipher 0x%04x: encrypt: %v", tc.cipher, err)
		}
		got, sid, err := smb3.DecryptTransform(uint16(tc.cipher), sess.S2CCipherKey, enc)
		if err != nil {
			t.Fatalf("cipher 0x%04x: decrypt: %v", tc.cipher, err)
		}
		if sid != sess.ID || !bytes.Equal(got, plain) {
			t.Errorf("cipher 0x%04x: round trip mismatch", tc.cipher)
		}
	}
}

// TestFixCrypto_KeysMatchClientDerivation checks the derived keys against an
// independent SP800-108 derivation, including the L=256 value that AES-256
// mixes into the PRF input (a 256-bit key is not the 128-bit key extended).
func TestFixCrypto_KeysMatchClientDerivation(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
	leg := hs.leg1(t, 1)
	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)

	hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
	sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
	if err != nil {
		t.Fatalf("type-3 leg: %v", err)
	}

	chain := forkPreauth(hs.basePreauth)
	chain.Update(leg.reqFrame)
	chain.Update(leg.respFrame)
	chain.Update(frame)
	sum := chain.Sum()

	wantS2C := smb3.KDF(auth.sessionKey, []byte("SMBS2CCipherKey\x00"), sum[:], 256)
	if !bytes.Equal(sess.S2CCipherKey, wantS2C) {
		t.Errorf("S2C key %x, want %x", sess.S2CCipherKey, wantS2C)
	}
	wantSign := smb3.KDF(auth.sessionKey, []byte("SMBSigningKey\x00"), sum[:], 128)
	if !bytes.Equal(sess.SigningKey, wantSign) {
		t.Errorf("signing key %x, want %x", sess.SigningKey, wantSign)
	}
	// The old code's 128-bit derivation is a different key, not a prefix.
	short := smb3.KDF(auth.sessionKey, []byte("SMBS2CCipherKey\x00"), sum[:], 128)
	if bytes.HasPrefix(wantS2C, short) {
		t.Error("L=256 derivation is a prefix of the L=128 one; the L value is not reaching the PRF")
	}
}

// --- finding 5: per-session preauth chain -----------------------------------

// TestFixCrypto_PreauthForksPerSession drives two type-1 legs on one connection
// and authenticates the second. Its keys must come from a chain containing only
// its own SESSION_SETUP messages; with the old connection-scoped chain they
// were salted with the first session's handshake, so the client and server
// derived different keys and every signed or encrypted frame failed.
func TestFixCrypto_PreauthForksPerSession(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))

	first := hs.leg1(t, 1)  // abandoned mid-handshake
	second := hs.leg1(t, 2) // the one we complete
	if first.sessionID == second.sessionID {
		t.Fatal("both legs got the same session id")
	}

	auth := buildAuthenticate(t, second, "alice", "WORKGROUP", "test123", true, nil)
	hdr, body, frame := sessionSetupFrame(auth.secBuf, 3, second.sessionID)
	sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
	if err != nil {
		t.Fatalf("type-3 leg: %v", err)
	}

	// Correct: NEGOTIATE chain + this session's own three messages.
	perSession := forkPreauth(hs.basePreauth)
	perSession.Update(second.reqFrame)
	perSession.Update(second.respFrame)
	perSession.Update(frame)
	wantSum := perSession.Sum()
	want := smb3.KDF(auth.sessionKey, []byte("SMBSigningKey\x00"), wantSum[:], 128)

	// Buggy: the same chain polluted by the first session's leg.
	polluted := forkPreauth(hs.basePreauth)
	polluted.Update(first.reqFrame)
	polluted.Update(first.respFrame)
	polluted.Update(second.reqFrame)
	polluted.Update(second.respFrame)
	polluted.Update(frame)
	pollutedSum := polluted.Sum()
	bad := smb3.KDF(auth.sessionKey, []byte("SMBSigningKey\x00"), pollutedSum[:], 128)

	if bytes.Equal(want, bad) {
		t.Fatal("test is not discriminating: both chains produced the same key")
	}
	if bytes.Equal(sess.SigningKey, bad) {
		t.Error("session keys derived from the connection-scoped (polluted) preauth chain")
	}
	if !bytes.Equal(sess.SigningKey, want) {
		t.Errorf("signing key %x, want %x", sess.SigningKey, want)
	}

	// The connection chain itself must stay at the post-NEGOTIATE state so any
	// further session forks from a clean base.
	baseSum := hs.basePreauth.Sum()
	connSum := hs.conn.Preauth.Sum()
	if baseSum != connSum {
		t.Error("SESSION_SETUP messages leaked into the connection preauth chain")
	}
}

// --- finding 4: NTLMSSP AUTHENTICATE MIC ------------------------------------

// TestFixCrypto_MICAccepted proves a correct MIC still authenticates, including
// when the security buffer carries a SPNEGO tail after the message (a real
// negTokenResp puts a mechListMIC there, and hashing it would break every
// MIC-sending client).
func TestFixCrypto_MICAccepted(t *testing.T) {
	tail := append([]byte{0xa3, 0x12, 0x04, 0x10}, bytes.Repeat([]byte{0x5E}, 16)...)
	for _, spnegoTail := range [][]byte{nil, tail} {
		hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
		leg := hs.leg1(t, 1)
		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, spnegoTail)

		hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
		sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
		if err != nil {
			t.Fatalf("tail=%d: correct MIC rejected: %v", len(spnegoTail), err)
		}
		if sess == nil || !sess.Authenticated {
			t.Fatalf("tail=%d: session not authenticated", len(spnegoTail))
		}
	}
}

// TestFixCrypto_MICTamperedRejected flips a bit in the NEGOTIATE_MESSAGE the
// server saw, which is exactly the field NTLMv2 leaves unauthenticated. The MIC
// must catch it; before the fix the MIC was parsed and thrown away.
func TestFixCrypto_MICTamperedRejected(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
	leg := hs.leg1(t, 1)

	// The client computes its MIC over the NEGOTIATE it really sent; the server
	// holds a version an attacker edited in flight.
	tampered := append([]byte(nil), leg.negotiate...)
	tampered[12] ^= 0x20 // clear a negotiate flag
	sess := hs.h.Sessions.Get(leg.sessionID)
	if sess == nil {
		t.Fatal("no half-open session")
	}
	sess.ntlmNegotiate = tampered

	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
	hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
	if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame); err == nil {
		t.Fatal("tampered handshake authenticated")
	}
	if st := respStatus(t, hs.out); st != smb2.StatusLogonFailure {
		t.Errorf("status 0x%08X, want LOGON_FAILURE", st)
	}
}

// TestFixCrypto_MICStrippedRejected covers the downgrade an attacker would
// actually try: zero out the MIC field and hope the server shrugs. The MsvAvFlags
// bit demanding a MIC lives inside the NTProofStr-protected AV pairs, so it
// cannot be cleared to match.
func TestFixCrypto_MICStrippedRejected(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
	leg := hs.leg1(t, 1)
	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)

	stripped := append([]byte(nil), auth.secBuf...)
	for i := ntlm.MICFieldOffset; i < ntlm.MICFieldOffset+16; i++ {
		stripped[i] = 0
	}
	hdr, body, frame := sessionSetupFrame(stripped, 2, leg.sessionID)
	if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame); err == nil {
		t.Fatal("authenticated with the MIC stripped out")
	}
}

// TestFixCrypto_NoMICStillAuthenticates keeps the door open for clients that
// never compute a MIC: nothing is required of them, and nothing changes.
func TestFixCrypto_NoMICStillAuthenticates(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
	leg := hs.leg1(t, 1)
	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", false, nil)

	hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
	sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
	if err != nil {
		t.Fatalf("client without a MIC was rejected: %v", err)
	}
	if sess == nil || !sess.Authenticated {
		t.Fatal("session not authenticated")
	}
}

// TestFixCrypto_WrongPasswordStillRejected is a guard against the MIC work
// accidentally becoming the only check that matters.
func TestFixCrypto_WrongPasswordStillRejected(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
	leg := hs.leg1(t, 1)
	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "wrongpass", true, nil)

	hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
	if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame); err == nil {
		t.Fatal("wrong password authenticated")
	}
}

// --- finding 6: half-open session flood -------------------------------------

// TestFixCrypto_HalfOpenSessionCap covers the table-level accounting: each
// unfinished NTLM handshake holds a slot, finishing or removing one gives it
// back, and the cap refuses the rest.
func TestFixCrypto_HalfOpenSessionCap(t *testing.T) {
	tbl := NewSessionTable()
	ids := make([]uint64, 0, maxHalfOpenSessions)
	for i := range maxHalfOpenSessions {
		s, err := tbl.NewHalfOpen()
		if err != nil {
			t.Fatalf("half-open session %d refused: %v", i, err)
		}
		ids = append(ids, s.ID)
	}
	if got := tbl.HalfOpenCount(); got != maxHalfOpenSessions {
		t.Errorf("half-open count %d, want %d", got, maxHalfOpenSessions)
	}
	if _, err := tbl.NewHalfOpen(); !errors.Is(err, ErrTooManyHalfOpenSessions) {
		t.Fatalf("session past the cap: err = %v, want ErrTooManyHalfOpenSessions", err)
	}

	// Completing a handshake frees the slot...
	tbl.MarkAuthenticated(ids[0])
	if got := tbl.HalfOpenCount(); got != maxHalfOpenSessions-1 {
		t.Errorf("half-open count after auth %d, want %d", got, maxHalfOpenSessions-1)
	}
	tbl.MarkAuthenticated(ids[0]) // idempotent
	if got := tbl.HalfOpenCount(); got != maxHalfOpenSessions-1 {
		t.Errorf("half-open count after repeat auth %d, want %d", got, maxHalfOpenSessions-1)
	}
	if _, err := tbl.NewHalfOpen(); err != nil {
		t.Fatalf("freed slot not reusable: %v", err)
	}

	// ...and so does dropping one (LOGOFF).
	if _, err := tbl.NewHalfOpen(); !errors.Is(err, ErrTooManyHalfOpenSessions) {
		t.Fatal("expected the table to be full again")
	}
	tbl.Remove(ids[1])
	if _, err := tbl.NewHalfOpen(); err != nil {
		t.Fatalf("slot freed by Remove not reusable: %v", err)
	}
}

// TestFixCrypto_SessionSetupFloodBounded is the end-to-end version: an
// anonymous peer that only ever sends NTLMSSP type-1 messages used to add a
// session per message with nothing ever removing them.
func TestFixCrypto_SessionSetupFloodBounded(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))

	neg := make([]byte, 40)
	copy(neg[0:8], ntlm.Signature[:])
	binary.LittleEndian.PutUint32(neg[8:], ntlm.MessageTypeNegotiate)
	binary.LittleEndian.PutUint32(neg[12:], ntlm.NegotiateUnicode|ntlm.NegotiateNTLM)

	var lastErr error
	for i := range maxHalfOpenSessions + 8 {
		hdr, body, frame := sessionSetupFrame(neg, uint64(i+1), 0)
		if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame); err != nil {
			lastErr = err
			break
		}
	}
	if !errors.Is(lastErr, ErrTooManyHalfOpenSessions) {
		t.Fatalf("type-1 flood was not capped: err = %v", lastErr)
	}
	if got := hs.h.Sessions.HalfOpenCount(); got > maxHalfOpenSessions {
		t.Errorf("half-open sessions %d exceed the cap %d", got, maxHalfOpenSessions)
	}
}

// TestFixCrypto_AuthenticationFreesHalfOpenSlot makes sure a long-lived
// connection that re-authenticates does not creep toward the cap.
func TestFixCrypto_AuthenticationFreesHalfOpenSlot(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
	for i := range 4 {
		leg := hs.leg1(t, uint64(2*i+1))
		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
		hdr, body, frame := sessionSetupFrame(auth.secBuf, uint64(2*i+2), leg.sessionID)
		if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame); err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if got := hs.h.Sessions.HalfOpenCount(); got != 0 {
			t.Fatalf("handshake %d left %d half-open sessions", i, got)
		}
	}
}

// readSessionFlags pulls SessionFlags out of the last SESSION_SETUP response
// the handler wrote to the harness pipe.
func readSessionFlags(t *testing.T, hs *fixCryptoHarness) uint16 {
	t.Helper()
	var flags uint16
	var found bool
	for {
		frame, err := transport.ReadFrame(hs.out, transport.MaxFrameSize)
		if err != nil {
			break
		}
		hdr, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
		if err != nil || hdr.Command != smb2.CommandSessionSetup {
			continue
		}
		body := frame[smb2.HeaderSize:]
		if len(body) < 4 {
			continue
		}
		flags = binary.LittleEndian.Uint16(body[2:])
		found = true
	}
	if !found {
		t.Fatal("no SESSION_SETUP response frame found")
	}
	return flags
}

// TestFixCrypto_EncryptDataFlagAdvertised is the regression test for a server
// that required encryption but never told the client to encrypt.
//
// The dispatcher refuses cleartext once a session is up, so without
// SMB2_SESSION_FLAG_ENCRYPT_DATA in the SESSION_SETUP response the client keeps
// sending in the clear and every request is denied — the session authenticates
// and then dies on the first CREATE. Observed against the macOS client, which
// negotiates AES-256-GCM:
//
//	"session authenticated" ... smb_user=ahmet
//	"unencrypted request but encryption required — denying" cmd=CREATE
func TestFixCrypto_EncryptDataFlagAdvertised(t *testing.T) {
	for _, cipher := range []smb2.Cipher{smb2.CipherAES256GCM, smb2.CipherAES128GCM, smb2.CipherAES128CCM} {
		hs := newFixCryptoHarness(t, cipher, fixCryptoUsers("test123"))
		hs.h.RequireEncryption = true

		leg := hs.leg1(t, 1)
		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
		hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
		sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
		if err != nil || sess == nil {
			t.Fatalf("cipher 0x%04x: session setup failed: %v", cipher, err)
		}

		flags := readSessionFlags(t, hs)
		if flags&smb2.SessionFlagEncryptData == 0 {
			t.Errorf("cipher 0x%04x: SESSION_SETUP flags=0x%04x, missing ENCRYPT_DATA — the client is never told to encrypt", cipher, flags)
		}
		if flags&smb2.SessionFlagIsGuest != 0 {
			t.Errorf("cipher 0x%04x: authenticated session wrongly marked guest", cipher)
		}
	}
}

// TestFixCrypto_NoEncryptDataWhenNotRequired keeps the flag off when the
// operator did not ask for encryption, so --no-encryption deployments are not
// forced into it.
func TestFixCrypto_NoEncryptDataWhenNotRequired(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixCryptoUsers("test123"))
	hs.h.RequireEncryption = false

	leg := hs.leg1(t, 1)
	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
	hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
	if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame); err != nil {
		t.Fatalf("session setup failed: %v", err)
	}
	if flags := readSessionFlags(t, hs); flags&smb2.SessionFlagEncryptData != 0 {
		t.Errorf("ENCRYPT_DATA set (flags=0x%04x) although encryption is not required", flags)
	}
}
