package parent

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// VLC probes with an SMB1 multi-protocol NEGOTIATE (through libdsm) and also
// opens a direct SMB2 connection (through libsmb2). This fixed wire fixture is
// deliberately not built with gosamba's encoders: it contains the NBSS-framed
// SMB1 probe followed by a libsmb2-shaped SMB 3.1.1 NEGOTIATE with SHA-512 and
// AES-128-CCM contexts.
const vlcMultiProtocolWireFixture = "" +
	"00000045ff534d4272000000000000000000000000000000000000000000000000000000002200" +
	"024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00" +
	"000000b0fe534d4240000000000000000000000800000000000000000100000000000000fffe" +
	"0000000000000000000000000000000000000000000000000000000000002400050001000000" +
	"44000000101112131415161718191a1b1c1d1e1f7000000002000000020210020003020311030000" +
	"0100260000000000010020000100a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5" +
	"a5a5a5a5a5a5a5a5a5a5000002000800000000000100010000000000"

func TestNegotiate_VLCMultiProtocolWireFixture(t *testing.T) {
	wire, err := hex.DecodeString(vlcMultiProtocolWireFixture)
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	pipe := &rwPipe{in: bytes.NewBuffer(wire), out: out}
	conn, err := Negotiate(pipe, NegotiatorOptions{
		RequireEncryption: true,
		RequireSigning:    true,
		MaxIOSize:         2 << 20,
		ServerStartTime:   0x01D5_1234_5678_9ABC,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Negotiate fixture: %v", err)
	}

	upgrade, err := transport.ReadFrame(out, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read wildcard response: %v", err)
	}
	final, err := transport.ReadFrame(out, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read final response: %v", err)
	}
	finalHdr, err := smb2.DecodeHeader(final[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if finalHdr.MessageID != 1 {
		t.Errorf("final response MessageId = %d, want 1", finalHdr.MessageID)
	}
	if finalHdr.CreditCharge != 0 {
		t.Errorf("final response CreditCharge = %d, want request value 0", finalHdr.CreditCharge)
	}
	upgradeHdr, err := smb2.DecodeHeader(upgrade[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if upgradeHdr.CreditCharge != 0 || upgradeHdr.CreditResponse != 1 || upgradeHdr.MessageID != 0 {
		t.Errorf("wildcard header credits/message id = charge %d response %d id %d",
			upgradeHdr.CreditCharge, upgradeHdr.CreditResponse, upgradeHdr.MessageID)
	}
	body := upgrade[smb2.HeaderSize:]
	if got := binary.LittleEndian.Uint16(body[0:]); got != 65 {
		t.Errorf("StructureSize = %d, want 65", got)
	}
	if got := binary.LittleEndian.Uint16(body[4:]); got != 0x02ff {
		t.Errorf("DialectRevision = 0x%04x, want 0x02ff", got)
	}
	if got := binary.LittleEndian.Uint16(body[6:]); got != 0 {
		t.Errorf("NegotiateContextCount = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint16(body[2:]); got != smb2.NegotiateSigningEnabled|smb2.NegotiateSigningRequired {
		t.Errorf("SecurityMode = 0x%04x", got)
	}
	if got := smb2.Capabilities(binary.LittleEndian.Uint32(body[24:])); got != smb2.CapLargeMTU {
		t.Errorf("Capabilities = 0x%08x, want LARGE_MTU", got)
	}
	for _, off := range []int{28, 32, 36} {
		if got := binary.LittleEndian.Uint32(body[off:]); got != 2<<20 {
			t.Errorf("max size at %d = %d, want %d", off, got, 2<<20)
		}
	}
	secOff := int(binary.LittleEndian.Uint16(body[56:])) - smb2.HeaderSize
	secLen := int(binary.LittleEndian.Uint16(body[58:]))
	if secOff < 0 || secOff+secLen > len(body) {
		t.Fatalf("security blob out of bounds: off=%d len=%d body=%d", secOff, secLen, len(body))
	}
	if !bytes.Equal(body[secOff:secOff+secLen], smb2.NegotiateSecurityBlob) {
		t.Errorf("wildcard response did not advertise the normal SPNEGO mechanisms")
	}
	if binary.LittleEndian.Uint32(body[60:]) != 0 {
		t.Errorf("wildcard response unexpectedly has negotiate contexts")
	}
	if binary.LittleEndian.Uint64(body[48:]) != 0 {
		t.Errorf("wildcard ServerStartTime must be zero")
	}
	if !bytes.Equal(body[8:24], final[smb2.HeaderSize+8:smb2.HeaderSize+24]) || !bytes.Equal(body[8:24], conn.ServerGuid[:]) {
		t.Errorf("ServerGuid changed between wildcard and final response")
	}
}

func TestNegotiate_ServerGuidIsServerGlobal(t *testing.T) {
	negotiate := func() [16]byte {
		in := &bytes.Buffer{}
		if err := transport.WriteFrame(in, buildClientNegotiate311()); err != nil {
			t.Fatal(err)
		}
		conn, err := Negotiate(&rwPipe{in: in, out: &bytes.Buffer{}}, NegotiatorOptions{},
			slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		return conn.ServerGuid
	}
	first, second := negotiate(), negotiate()
	if first != second {
		t.Fatalf("ServerGuid changed between connections: %x != %x", first, second)
	}
}

// rwPipe is an io.ReadWriter that reads from one buffer and writes to another.
type rwPipe struct {
	in  *bytes.Buffer
	out *bytes.Buffer
}

func (p *rwPipe) Read(b []byte) (int, error)  { return p.in.Read(b) }
func (p *rwPipe) Write(b []byte) (int, error) { return p.out.Write(b) }

// buildClientNegotiate311 builds an SMB2 NEGOTIATE request frame
// (header + body) advertising 3.1.1 + SHA-512 + AES-256-GCM.
func buildClientNegotiate311() []byte {
	hdr := make([]byte, smb2.HeaderSize)
	_ = smb2.EncodeHeader(hdr, smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandNegotiate,
		MessageID:    0,
	})
	body := make([]byte, 0, 256)
	fixed := make([]byte, 36)
	fixed[0] = 36
	fixed[2] = 1
	fixed[4] = byte(smb2.NegotiateSigningEnabled)
	fixed[8] = byte(smb2.CapEncryption)
	for i := 0; i < 16; i++ {
		fixed[12+i] = 0xAA
	}
	binary.LittleEndian.PutUint32(fixed[28:], uint32(smb2.HeaderSize+40))
	binary.LittleEndian.PutUint16(fixed[32:], 2)
	body = append(body, fixed...)
	body = append(body, 0x11, 0x03)
	body = append(body, 0x00, 0x00)

	preauthData := append([]byte{0x01, 0x00, 0x20, 0x00, 0x01, 0x00}, bytes.Repeat([]byte{0xC1}, 32)...)
	preauthHdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(preauthHdr[0:], uint16(smb2.CtxPreauthIntegrityCaps))
	binary.LittleEndian.PutUint16(preauthHdr[2:], uint16(len(preauthData)))
	body = append(body, preauthHdr...)
	body = append(body, preauthData...)
	for len(body)%8 != 0 {
		body = append(body, 0x00)
	}
	encData := []byte{0x01, 0x00, 0x04, 0x00}
	encHdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(encHdr[0:], uint16(smb2.CtxEncryptionCaps))
	binary.LittleEndian.PutUint16(encHdr[2:], uint16(len(encData)))
	body = append(body, encHdr...)
	body = append(body, encData...)

	full := append(hdr, body...)
	return full
}

func TestNegotiate_HappyPath(t *testing.T) {
	in := &bytes.Buffer{}
	if err := transport.WriteFrame(in, buildClientNegotiate311()); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	pipe := &rwPipe{in: in, out: out}

	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	conn, err := Negotiate(pipe, NegotiatorOptions{RequireEncryption: true, RequireSigning: true}, lg)
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if conn.Selection.Dialect != smb2.Dialect311 {
		t.Errorf("dialect: %x", conn.Selection.Dialect)
	}
	if conn.Selection.Cipher != smb2.CipherAES256GCM {
		t.Errorf("cipher: %x", conn.Selection.Cipher)
	}

	resp, err := transport.ReadFrame(out, transport.MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := smb2.DecodeHeader(resp[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Command != smb2.CommandNegotiate {
		t.Errorf("response command: %s", hdr.Command)
	}
	if hdr.Flags&smb2.FlagServerToRedir == 0 {
		t.Errorf("response missing server-to-redir flag")
	}
	if hdr.Status != 0 {
		t.Errorf("response status: %x", hdr.Status)
	}
}

func TestNegotiate_NoCommonDialect(t *testing.T) {
	hdr := make([]byte, smb2.HeaderSize)
	_ = smb2.EncodeHeader(hdr, smb2.Header{Command: smb2.CommandNegotiate})
	body := make([]byte, 36)
	body[0] = 36
	body[2] = 1
	// dialect 0x9999 is fictional and not in SupportedDialects.
	body = append(body, 0x99, 0x99)

	frame := append(hdr, body...)
	in := &bytes.Buffer{}
	_ = transport.WriteFrame(in, frame)
	pipe := &rwPipe{in: in, out: &bytes.Buffer{}}

	_, err := Negotiate(pipe, NegotiatorOptions{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected error for unsupported dialect")
	}
}
