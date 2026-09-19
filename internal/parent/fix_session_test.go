package parent

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// --- every advertised cipher must work end to end ---------------------------

// TestFixSession_EverySupportedCipherNegotiatesAndEncrypts walks
// smb2.SupportedCiphers rather than a hand-written list, so a cipher can never
// be advertised without a session actually being able to use it. AES-256-CCM
// was the case that mattered: it was implemented and keyed correctly but left
// out of the advertised list, so a client offering only that cipher negotiated
// no encryption context at all and the connection died on its first transform
// frame.
func TestFixSession_EverySupportedCipherNegotiatesAndEncrypts(t *testing.T) {
	for _, cipher := range smb2.SupportedCiphers {
		hs := newFixCryptoHarness(t, cipher, fixCryptoUsers("test123"))
		leg := hs.leg1(t, 1)
		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)

		hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
		sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
		if err != nil {
			t.Fatalf("cipher 0x%04x: type-3 leg: %v", cipher, err)
		}
		if sess == nil || !sess.Authenticated {
			t.Fatalf("cipher 0x%04x: session not authenticated", cipher)
		}
		wantLen := int(smb3.CipherKeyBits(uint16(cipher)) / 8)
		if len(sess.C2SCipherKey) != wantLen {
			t.Fatalf("cipher 0x%04x: C2S key %d bytes, want %d", cipher, len(sess.C2SCipherKey), wantLen)
		}

		plain := []byte("a message encrypted under the negotiated cipher")
		enc, err := smb3.EncryptTransform(uint16(cipher), sess.S2CCipherKey, sess.ID, plain)
		if err != nil {
			t.Fatalf("cipher 0x%04x: encrypt: %v", cipher, err)
		}
		got, sid, err := smb3.DecryptTransform(uint16(cipher), sess.S2CCipherKey, enc)
		if err != nil {
			t.Fatalf("cipher 0x%04x: decrypt: %v", cipher, err)
		}
		if sid != sess.ID || !bytes.Equal(got, plain) {
			t.Errorf("cipher 0x%04x: transform round trip mismatch", cipher)
		}
	}
}

// --- SPNEGO-wrapped type-1 and the NTLMSSP MIC ------------------------------

func derTagP(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch {
	case len(content) < 0x80:
		out = append(out, byte(len(content)))
	case len(content) < 0x100:
		out = append(out, 0x81, byte(len(content)))
	default:
		out = append(out, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	return append(out, content...)
}

// spnegoInit wraps an NTLMSSP NEGOTIATE in a NegTokenInit, optionally followed
// by a mechListMIC — trailing DER that is not part of the message the client
// hashed into its MIC.
func spnegoInit(mechToken, mechListMIC []byte) []byte {
	ntlmsspOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	inner := derTagP(0xa0, derTagP(0x30, ntlmsspOID))
	inner = append(inner, derTagP(0xa2, derTagP(0x04, mechToken))...)
	if len(mechListMIC) > 0 {
		inner = append(inner, derTagP(0xa3, derTagP(0x04, mechListMIC))...)
	}
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	body := append(append([]byte(nil), spnegoOID...), derTagP(0xa0, derTagP(0x30, inner))...)
	return derTagP(0x60, body)
}

// TestFixSession_SPNEGOWrappedTypeOneKeepsMICValid is the end-to-end regression
// test for the unwrap: the server must retain exactly the NEGOTIATE_MESSAGE the
// client MIC'd. When the unwrap returned everything from the NTLMSSP signature
// to the end of the token, a NegTokenInit with anything after the mechToken
// poisoned the retained bytes and the AUTHENTICATE MIC could never match.
func TestFixSession_SPNEGOWrappedTypeOneKeepsMICValid(t *testing.T) {
	for _, tail := range [][]byte{nil, bytes.Repeat([]byte{0x5E}, 16)} {
		hs := newFixCryptoHarness(t, smb2.CipherAES256CCM, fixCryptoUsers("test123"))
		leg, retained := fixSessionLeg1SPNEGO(t, hs, 1, tail)
		// What the server retained must be the message alone.
		if !bytes.Equal(leg.negotiate, retained) {
			t.Fatalf("mechListMIC=%d bytes: server retained %d bytes, want the %d-byte NEGOTIATE_MESSAGE",
				len(tail), len(retained), len(leg.negotiate))
		}

		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
		hdr, body, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
		sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
		if err != nil {
			t.Fatalf("mechListMIC=%d bytes: MIC rejected after a SPNEGO-wrapped type-1: %v", len(tail), err)
		}
		if sess == nil || !sess.Authenticated {
			t.Fatalf("mechListMIC=%d bytes: session not authenticated", len(tail))
		}
	}
}

// libsmb2 6.1 (the version bundled by VLC for iOS 4.0.0-a24) starts NTLMSSP
// with a bare type-1 token. It expects the challenge in the same form and
// aborts with "no message type in NTLMSSP blob" if the server changes that
// bare exchange into SPNEGO halfway through.
func TestSessionSetup_PreservesBareNTLMSSPForLibsmb2(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES128CCM, fixCryptoUsers("test123"))
	leg := hs.leg1(t, 1)

	body := leg.respFrame[smb2.HeaderSize:]
	off := int(binary.LittleEndian.Uint16(body[4:])) - smb2.HeaderSize
	length := int(binary.LittleEndian.Uint16(body[6:]))
	if off < 0 || off+length > len(body) {
		t.Fatalf("challenge security buffer out of bounds: off=%d len=%d body=%d", off, length, len(body))
	}
	securityBuffer := body[off : off+length]
	if !bytes.HasPrefix(securityBuffer, []byte("NTLMSSP\x00")) {
		t.Fatalf("bare type-1 received a wrapped challenge: %x", securityBuffer[:min(len(securityBuffer), 16)])
	}

	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
	hdr, reqBody, frame := sessionSetupFrame(auth.secBuf, 2, leg.sessionID)
	if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, reqBody, frame); err != nil {
		t.Fatalf("bare NTLMSSP authentication: %v", err)
	}
	final, err := transport.ReadFrame(hs.out, transport.MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(final[smb2.HeaderSize+6:]); got != 0 {
		t.Errorf("bare NTLMSSP final SecurityBufferLength = %d, want 0", got)
	}
}

// fixSessionLeg1SPNEGO runs the type-1 leg with the NEGOTIATE_MESSAGE wrapped
// in a real SPNEGO NegTokenInit (what macOS and Windows actually send) instead
// of the bare message the other harness tests use. It also returns the bytes
// the server retained for the MIC computation.
func fixSessionLeg1SPNEGO(t *testing.T, hs *fixCryptoHarness, msgID uint64, mechListMIC []byte) (fixCryptoLeg1, []byte) {
	t.Helper()
	hs.out.Reset()

	neg := make([]byte, 40)
	copy(neg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(neg[8:], 1) // NEGOTIATE
	binary.LittleEndian.PutUint32(neg[12:], 0x00088207)

	hdr, body, frame := sessionSetupFrame(spnegoInit(neg, mechListMIC), msgID, 0)
	if _, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame); err != nil {
		t.Fatalf("type-1 leg: %v", err)
	}
	resp, err := transport.ReadFrame(hs.out, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	respHdr, err := smb2.DecodeHeader(resp[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	chal, err := smb2.UnwrapNTLM(resp[smb2.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot what the server kept, so the test can assert on it directly.
	var retained []byte
	if s := hs.h.Sessions.Get(respHdr.SessionID); s != nil {
		retained = append([]byte(nil), s.ntlmNegotiate...)
	}

	out := fixCryptoLeg1{
		negotiate: neg,
		challenge: chal,
		reqFrame:  frame,
		respFrame: resp,
		sessionID: respHdr.SessionID,
	}
	copy(out.challenge8[:], chal[24:32])
	return out, retained
}

// --- PreviousSessionId (MS-SMB2 §3.3.5.5.3) ---------------------------------

// sessionSetupFrameWithPrev is sessionSetupFrame plus the PreviousSessionId
// field a reconnecting client fills in.
func sessionSetupFrameWithPrev(secBuf []byte, msgID, sessID, prevID uint64) (smb2.Header, []byte, []byte) {
	hdr, body, _ := sessionSetupFrame(secBuf, msgID, sessID)
	binary.LittleEndian.PutUint64(body[16:], prevID)
	frame := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(frame[:smb2.HeaderSize], hdr)
	copy(frame[smb2.HeaderSize:], body)
	return hdr, body, frame
}

func fixSessionUsers() []config.UserConfig {
	mk := func(name, pw string) config.UserConfig {
		return config.UserConfig{
			Name: name, NTHash: userdb.NTHash(pw),
			SystemUser: "nobody", SystemUID: 65534, SystemGID: 65534,
			AllowShares: []string{"*"},
		}
	}
	return []config.UserConfig{mk("alice", "test123"), mk("bob", "hunter2")}
}

// fixSessionAuthenticate runs a complete handshake for user/password, naming
// prevID in PreviousSessionId, and returns the resulting session.
func fixSessionAuthenticate(t *testing.T, hs *fixCryptoHarness, msgID uint64, user, pw string, prevID uint64) *Session {
	t.Helper()
	leg := hs.leg1(t, msgID)
	auth := buildAuthenticate(t, leg, user, "WORKGROUP", pw, true, nil)
	hdr, body, frame := sessionSetupFrameWithPrev(auth.secBuf, msgID+1, leg.sessionID, prevID)
	sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
	if err != nil {
		t.Fatalf("%s: session setup: %v", user, err)
	}
	if sess == nil || !sess.Authenticated {
		t.Fatalf("%s: session not authenticated", user)
	}
	return sess
}

// giveSessionAnOpen attaches a real descriptor to a session so the teardown can
// be observed: a reconnect must not leave the old session's fds (and, with
// them, its byte-range locks and notify watches) in place.
func giveSessionAnOpen(t *testing.T, sess *Session) *Open {
	t.Helper()
	path := filepath.Join(t.TempDir(), "held.txt")
	if err := os.WriteFile(path, []byte("held"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	o := &Open{Path: path, File: f, GrantedAccess: 0x001F01FF}
	o.FileID[0] = 0x77
	o.Tree = sess.AddTree(config.ShareConfig{Name: "share", Path: filepath.Dir(path)})
	sess.AddOpen(o)
	return o
}

// assertSessionAlive fails unless the session is still reachable everywhere it
// should be and still owns the handle it was given.
func assertSessionAlive(t *testing.T, hs *fixCryptoHarness, sess *Session, held *Open, what string) {
	t.Helper()
	if hs.index.get(sess.ID) == nil {
		t.Errorf("%s: session %d was dropped from the server index", what, sess.ID)
	}
	if hs.h.Sessions.Get(sess.ID) == nil {
		t.Errorf("%s: session %d was dropped from its connection table", what, sess.ID)
	}
	if sess.OpenCount() != 1 {
		t.Errorf("%s: session %d holds %d opens, want 1", what, sess.ID, sess.OpenCount())
	}
	if held != nil && held.File == nil {
		t.Errorf("%s: session %d had its descriptor closed", what, sess.ID)
	}
}

// assertSessionClosed fails unless the session is gone from both tables and has
// given up everything it owned.
func assertSessionClosed(t *testing.T, hs *fixCryptoHarness, sess *Session, held *Open) {
	t.Helper()
	if hs.index.get(sess.ID) != nil {
		t.Errorf("session %d is still in the server index after being superseded", sess.ID)
	}
	if hs.h.Sessions.Get(sess.ID) != nil {
		t.Errorf("session %d is still usable on its connection after being superseded", sess.ID)
	}
	if sess.OpenCount() != 0 {
		t.Errorf("superseded session still holds %d opens", sess.OpenCount())
	}
	if held != nil && held.File != nil {
		t.Error("superseded session's descriptor was not closed")
	}
}

// TestFixSession_PreviousSessionIdClosesOldSession is the regression test:
// PreviousSessionId was decoded and then ignored, so a client that reconnected
// because its own side had broken left the old session's descriptors, locks and
// change-notify watches behind until the idle reaper ran — and those stale locks
// blocked the new session.
func TestFixSession_PreviousSessionIdClosesOldSession(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixSessionUsers())

	first := fixSessionAuthenticate(t, hs, 1, "alice", "test123", 0)
	held := giveSessionAnOpen(t, first)

	second := fixSessionAuthenticate(t, hs, 3, "alice", "test123", first.ID)
	if second.ID == first.ID {
		t.Fatal("reconnect reused the previous session id")
	}
	assertSessionClosed(t, hs, first, held)
	if hs.h.Sessions.Get(second.ID) == nil {
		t.Error("the new session is not in the table")
	}
	if hs.index.get(second.ID) == nil {
		t.Error("the new session is not in the server index")
	}
}

// TestFixSession_PreviousSessionIdIgnoredForOtherUsers is the security half:
// naming someone else's SessionId must not close their session.
func TestFixSession_PreviousSessionIdIgnoredForOtherUsers(t *testing.T) {
	hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixSessionUsers())

	victim := fixSessionAuthenticate(t, hs, 1, "alice", "test123", 0)
	held := giveSessionAnOpen(t, victim)

	fixSessionAuthenticate(t, hs, 3, "bob", "hunter2", victim.ID)
	assertSessionAlive(t, hs, victim, held, "bob named alice's SessionId")
}

// TestFixSession_PreviousSessionIdEdgeCases covers the ids that must do
// nothing: zero, an unknown id, the session's own id, and a half-open session
// that never finished authenticating.
func TestFixSession_PreviousSessionIdEdgeCases(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixSessionUsers())
		first := fixSessionAuthenticate(t, hs, 1, "alice", "test123", 0)
		held := giveSessionAnOpen(t, first)
		fixSessionAuthenticate(t, hs, 3, "alice", "test123", 0)
		assertSessionAlive(t, hs, first, held, "PreviousSessionId of zero")
	})

	t.Run("unknown id", func(t *testing.T) {
		hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixSessionUsers())
		first := fixSessionAuthenticate(t, hs, 1, "alice", "test123", 0)
		held := giveSessionAnOpen(t, first)
		// An id that names nothing must be a silent no-op, never an error:
		// after a server restart every client's saved SessionId is unknown.
		fixSessionAuthenticate(t, hs, 3, "alice", "test123", 0xDEADBEEF)
		assertSessionAlive(t, hs, first, held, "unknown PreviousSessionId")
	})

	t.Run("names itself", func(t *testing.T) {
		hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixSessionUsers())
		leg := hs.leg1(t, 1)
		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
		hdr, body, frame := sessionSetupFrameWithPrev(auth.secBuf, 2, leg.sessionID, leg.sessionID)
		sess, err := hs.h.HandleSessionSetup(hs.pipe, hdr, body, frame)
		if err != nil {
			t.Fatalf("session setup: %v", err)
		}
		held := giveSessionAnOpen(t, sess)
		assertSessionAlive(t, hs, sess, held, "a session naming itself")
	})

	t.Run("half-open previous session", func(t *testing.T) {
		hs := newFixCryptoHarness(t, smb2.CipherAES256GCM, fixSessionUsers())
		// A type-1 leg with no type-3: the session exists but is not
		// authenticated, so nobody owns it and it must not be closable.
		halfOpen := hs.leg1(t, 1)
		fixSessionAuthenticate(t, hs, 3, "alice", "test123", halfOpen.sessionID)
		if hs.h.Sessions.Get(halfOpen.sessionID) == nil {
			t.Error("the half-open session was removed")
		}
		if hs.index.get(halfOpen.sessionID) != nil {
			t.Error("a half-open session was registered in the server index")
		}
	})
}

// --- durable reclaim must not downgrade a handle ----------------------------

// TestFixSession_DurableReclaimRefusesReadOnlyDowngrade is the regression test
// for a reclaim that reported SUCCESS while quietly handing back a read-only
// descriptor under a GrantedAccess that still promised write. The client does
// no post-reclaim validation, so the lie surfaced as a failed WRITE mid-stream.
func TestFixSession_DurableReclaimRefusesReadOnlyDowngrade(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens read-only files O_RDWR, so the downgrade cannot be provoked")
	}
	shareDir := t.TempDir()
	path := filepath.Join(shareDir, "rw.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, _, tbl := newDurableDispatcher(t, shareDir)

	fileID, createGuid := fixSessionDurableCreate(t, d, sess, "rw.txt")
	open := sess.GetOpen(fileID)
	if open == nil {
		t.Fatal("durable open missing from the session")
	}
	if open.GrantedAccess&durableWriteAccess == 0 {
		t.Fatalf("GrantedAccess 0x%08X carries no write bit; the test proves nothing", open.GrantedAccess)
	}

	// Drop the connection, then make the file unwritable underneath us.
	sess.RemoveOpen(fileID)
	tbl.Detach(d.Conn.ClientGuid, createGuid)
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	sess2 := &Session{}
	sess2.AddTree(d.Shares[0])
	status, _ := fixSessionDurableReconnect(t, d, sess2, "rw.txt", fileID, createGuid)
	if status != smb2.StatusObjectNameNotFound {
		t.Fatalf("reclaim status = 0x%08X, want OBJECT_NAME_NOT_FOUND (the client must re-open fresh)", status)
	}
	if sess2.OpenCount() != 0 {
		t.Error("a refused reclaim still installed a handle in the session")
	}
}

// TestFixSession_DurableReclaimStillWorksWhenWritable is the positive control:
// the refusal must be limited to the downgrade case.
func TestFixSession_DurableReclaimStillWorksWhenWritable(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "rw.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, _, tbl := newDurableDispatcher(t, shareDir)
	fileID, createGuid := fixSessionDurableCreate(t, d, sess, "rw.txt")

	sess.RemoveOpen(fileID)
	tbl.Detach(d.Conn.ClientGuid, createGuid)
	sess2 := &Session{}
	sess2.AddTree(d.Shares[0])

	status, gotID := fixSessionDurableReconnect(t, d, sess2, "rw.txt", fileID, createGuid)
	if status != smb2.StatusSuccess {
		t.Fatalf("reclaim status = 0x%08X, want SUCCESS", status)
	}
	if gotID != fileID {
		t.Fatalf("reclaimed FileID %x, want %x", gotID, fileID)
	}
	reclaimed := sess2.GetOpen(fileID)
	if reclaimed == nil || reclaimed.File == nil {
		t.Fatal("reclaimed handle has no descriptor")
	}
	if _, err := reclaimed.File.WriteAt([]byte("H"), 0); err != nil {
		t.Errorf("reclaimed handle reports write access but cannot write: %v", err)
	}
}

// TestFixSession_DurableReclaimReadOnlyShareStillReclaims keeps the read-only
// path open: a handle that was never granted write can still be served from a
// read-only descriptor, because it never promised anything more.
func TestFixSession_DurableReclaimReadOnlyShareStillReclaims(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens read-only files O_RDWR")
	}
	shareDir := t.TempDir()
	path := filepath.Join(shareDir, "ro.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o444); err != nil {
		t.Fatal(err)
	}
	d, sess, tbl := newReadOnlyDurableDispatcher(t, shareDir)

	fileID, createGuid := fixSessionDurableCreate(t, d, sess, "ro.txt")
	open := sess.GetOpen(fileID)
	if open == nil {
		t.Fatal("durable open missing from the session")
	}
	if open.GrantedAccess&durableWriteAccess != 0 {
		t.Fatalf("read-only share granted write bits (0x%08X)", open.GrantedAccess)
	}

	sess.RemoveOpen(fileID)
	tbl.Detach(d.Conn.ClientGuid, createGuid)
	sess2 := &Session{}
	sess2.AddTree(d.Shares[0])
	status, _ := fixSessionDurableReconnect(t, d, sess2, "ro.txt", fileID, createGuid)
	if status != smb2.StatusSuccess {
		t.Fatalf("read-only reclaim status = 0x%08X, want SUCCESS", status)
	}
}

// newReadOnlyDurableDispatcher mirrors newDurableDispatcher but serves the
// share read-only, so CREATE grants FILE_GENERIC_READ|EXECUTE and no write bit.
func newReadOnlyDurableDispatcher(t *testing.T, shareDir string) (*Dispatcher, *Session, *DurableTable) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir, ReadOnly: true}
	tbl := NewDurableTable()
	conn := &Connection{}
	conn.ClientGuid[0] = 0xC2
	conn.Durable = tbl
	conn.DurableTimeout = time.Minute
	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{share},
		Conn:   conn,
	}
	sess := &Session{}
	sess.AddTree(share)
	return d, sess, tbl
}

// fixSessionDurableCreate performs a durable (DH2Q) CREATE and returns the
// granted FileID and the CreateGuid it was registered under.
func fixSessionDurableCreate(t *testing.T, d *Dispatcher, sess *Session, name string) ([16]byte, [16]byte) {
	t.Helper()
	var dh2q [32]byte
	binary.LittleEndian.PutUint32(dh2q[0:], 30000)
	var createGuid [16]byte
	createGuid[0], createGuid[1] = 0x4D, byte(len(name))
	copy(dh2q[16:32], createGuid[:])
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2Q, Data: dh2q[:]}})
	body := buildCreateBody(name, smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	if sess.GetTree(2) == nil {
		t.Fatal("no tree with id 2 in the session")
	}
	if !d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: 2}, body, sess) {
		t.Fatal("durable create returned false")
	}
	hdr, resp, _ := readCreateResponse(t, &buf)
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("durable create status = 0x%08X", hdr.Status)
	}
	return resp.FileID, createGuid
}

// fixSessionDurableReconnect issues a DH2C reconnect and reports the response
// status plus the FileID it handed back.
func fixSessionDurableReconnect(t *testing.T, d *Dispatcher, sess *Session, name string, fileID, createGuid [16]byte) (smb2.Status, [16]byte) {
	t.Helper()
	var dh2c [36]byte
	copy(dh2c[0:16], fileID[:])
	copy(dh2c[16:32], createGuid[:])
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2C, Data: dh2c[:]}})
	body := buildCreateBody(name, smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	if !d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: 2}, body, sess) {
		t.Fatal("reconnect create returned false")
	}
	hdr, resp, _ := readCreateResponse(t, &buf)
	return smb2.Status(hdr.Status), resp.FileID
}
