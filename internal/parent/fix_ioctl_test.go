package parent

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// --- harness ---

// buildIoctlBody constructs an IOCTL request body (StructureSize 57) carrying
// the given control code, FileID and input buffer, laid out the way
// DecodeIoctlRequest reads it.
func buildIoctlBody(ctlCode uint32, fileID [16]byte, input []byte) []byte {
	const headerSize = 64
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:], 57)
	binary.LittleEndian.PutUint32(body[4:], ctlCode)
	copy(body[8:24], fileID[:])
	binary.LittleEndian.PutUint32(body[24:], uint32(headerSize+56)) // InputOffset
	binary.LittleEndian.PutUint32(body[28:], uint32(len(input)))    // InputCount
	binary.LittleEndian.PutUint32(body[44:], 64<<10)                // MaxOutputResponse
	binary.LittleEndian.PutUint32(body[48:], smb2.IoctlIsFsctl)
	return append(body, input...)
}

// readIoctlResponse parses the NBSS-framed response the dispatcher wrote,
// returning the status and — for a StructureSize-49 IOCTL response — the output
// buffer. A bare SMB2 error response yields a nil buffer.
func readIoctlResponse(t *testing.T, buf *bytes.Buffer) (smb2.Status, []byte) {
	t.Helper()
	frame := buf.Bytes()
	if len(frame) < 4+smb2.HeaderSize {
		t.Fatalf("ioctl response too short: %d bytes", len(frame))
	}
	frame = frame[4:] // strip the NBSS length prefix
	hdr, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode response header: %v", err)
	}
	body := frame[smb2.HeaderSize:]
	if len(body) < 2 {
		t.Fatalf("ioctl response body too short: %d bytes", len(body))
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 49 {
		// An SMB2 error response (StructureSize 9) carries no output buffer.
		return smb2.Status(hdr.Status), nil
	}
	outOff := int(binary.LittleEndian.Uint32(body[32:])) - smb2.HeaderSize
	outLen := int(binary.LittleEndian.Uint32(body[36:]))
	if outOff < 0 || outLen < 0 || outOff+outLen > len(body) {
		t.Fatalf("ioctl output buffer out of range: off=%d len=%d body=%d", outOff, outLen, len(body))
	}
	return smb2.Status(hdr.Status), body[outOff : outOff+outLen]
}

// doIoctl runs one IOCTL through the dispatcher and returns the parsed reply.
func doIoctl(t *testing.T, d *Dispatcher, sess *Session, ctlCode uint32, fileID [16]byte, input []byte) (smb2.Status, []byte) {
	t.Helper()
	var buf bytes.Buffer
	d.handleIoctl(&buf, smb2.Header{Command: smb2.CommandIoctl}, buildIoctlBody(ctlCode, fileID, input), sess)
	return readIoctlResponse(t, &buf)
}

// newCopyDispatcher wires a Dispatcher with a Connection (handleIoctl reads
// ServerGuid and the resume-key table off it) over a share rooted at shareDir.
func newCopyDispatcher(t *testing.T, shareDir string, readOnly bool) (*Dispatcher, *Session, *Tree) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir, ReadOnly: readOnly}
	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{share},
		Conn:   &Connection{Selection: smb2.Selection{Dialect: smb2.Dialect311}},
	}
	sess := &Session{ID: 1}
	tree := sess.AddTree(share)
	return d, sess, tree
}

var testFileIDSeq byte

// addFileOpen opens path and registers it as a handle on sess, the way a
// successful CREATE would.
func addFileOpen(t *testing.T, sess *Session, tree *Tree, path string, flags int, access uint32) *Open {
	t.Helper()
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	testFileIDSeq++
	o := &Open{Path: path, File: f, Tree: tree, GrantedAccess: access}
	o.FileID[0] = testFileIDSeq
	sess.AddOpen(o)
	return o
}

// resumeKeyFor asks for a resume key on open and returns it, failing the test
// if the FSCTL did not succeed.
func resumeKeyFor(t *testing.T, d *Dispatcher, sess *Session, open *Open) [smb2.ResumeKeyLen]byte {
	t.Helper()
	status, out := doIoctl(t, d, sess, smb2.FsctlSrvRequestResumeKey, open.FileID, nil)
	if status != smb2.StatusSuccess {
		t.Fatalf("FSCTL_SRV_REQUEST_RESUME_KEY status = %#08x, want SUCCESS", uint32(status))
	}
	// macOS asks for 0x20 bytes and rejects a reply shorter than 24.
	if len(out) < smb2.ResumeKeyLen {
		t.Fatalf("resume key response = %d bytes, want at least %d", len(out), smb2.ResumeKeyLen)
	}
	var key [smb2.ResumeKeyLen]byte
	copy(key[:], out)
	return key
}

// buildCopyChunkInput serializes an SRV_COPYCHUNK_COPY.
func buildCopyChunkInput(key [smb2.ResumeKeyLen]byte, chunks []smb2.SrvCopyChunk) []byte {
	in := make([]byte, 32+24*len(chunks))
	copy(in[0:24], key[:])
	binary.LittleEndian.PutUint32(in[24:], uint32(len(chunks)))
	for i, c := range chunks {
		off := 32 + i*24
		binary.LittleEndian.PutUint64(in[off:], c.SourceOffset)
		binary.LittleEndian.PutUint64(in[off+8:], c.TargetOffset)
		binary.LittleEndian.PutUint32(in[off+16:], c.Length)
	}
	return in
}

// --- Defect 1: FSCTL_VALIDATE_NEGOTIATE_INFO ---

// buildClientNegotiatePre311 builds a NEGOTIATE request for a client that
// offers only pre-3.1.1 dialects (so no negotiate contexts), advertising caps.
// SMB 3.0 / 3.0.2 is the range where the macOS client actually sends
// FSCTL_VALIDATE_NEGOTIATE_INFO: it skips the FSCTL entirely for 3.1.1 and 2.x.
func buildClientNegotiatePre311(dialects []smb2.Dialect, caps smb2.Capabilities) []byte {
	hdr := make([]byte, smb2.HeaderSize)
	_ = smb2.EncodeHeader(hdr, smb2.Header{CreditCharge: 1, Command: smb2.CommandNegotiate})
	fixed := make([]byte, 36)
	fixed[0] = 36
	binary.LittleEndian.PutUint16(fixed[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(fixed[4:], smb2.NegotiateSigningEnabled)
	binary.LittleEndian.PutUint32(fixed[8:], uint32(caps))
	for i := 0; i < 16; i++ {
		fixed[12+i] = 0xBB
	}
	body := fixed
	for _, d := range dialects {
		var dl [2]byte
		binary.LittleEndian.PutUint16(dl[:], uint16(d))
		body = append(body, dl[0], dl[1])
	}
	return append(hdr, body...)
}

// negotiatedWireValues re-reads the Capabilities, ServerGuid, SecurityMode and
// DialectRevision straight out of the NEGOTIATE response this connection
// actually put on the wire. Comparing the FSCTL against these bytes — rather
// than against a second copy of the same computation — is the whole point: it
// fails if the two ever drift.
func negotiatedWireValues(t *testing.T, conn *Connection) (smb2.Capabilities, [16]byte, uint16, smb2.Dialect) {
	t.Helper()
	msg := conn.NegotiateResponseMsg
	if len(msg) < smb2.HeaderSize+64 {
		t.Fatalf("stored NEGOTIATE response too short: %d bytes", len(msg))
	}
	body := msg[smb2.HeaderSize:]
	var guid [16]byte
	copy(guid[:], body[8:24])
	return smb2.Capabilities(binary.LittleEndian.Uint32(body[24:])),
		guid,
		binary.LittleEndian.Uint16(body[2:]),
		smb2.Dialect(binary.LittleEndian.Uint16(body[4:]))
}

// TestValidateNegotiate_EchoesWhatNegotiateSent proves FSCTL_VALIDATE_NEGOTIATE_INFO
// repeats the exact Capabilities, ServerGuid, SecurityMode and Dialect the
// NEGOTIATE response carried, across every combination of "signing required"
// and "encryption negotiated".
//
// The client saved those four values at negotiate time and compares all four
// here to detect a downgrade (smbfs_smb_2.c, smb2fs_smb_validate_neg_info).
// The previous code hardcoded Capabilities = 0 and SecurityMode = 1, so a
// client pinned to SMB 3.0 or 3.0.2 — the only dialects for which it sends this
// FSCTL — saw a mismatch on both and failed with EAUTH: a dead mount, or
// ENOTCONN if it happened during a reconnect.
func TestValidateNegotiate_EchoesWhatNegotiateSent(t *testing.T) {
	cases := []struct {
		name           string
		dialects       []smb2.Dialect
		clientCaps     smb2.Capabilities
		requireSigning bool
	}{
		{"smb300 signing-optional no-encryption", []smb2.Dialect{smb2.Dialect300}, 0, false},
		{"smb300 signing-required no-encryption", []smb2.Dialect{smb2.Dialect300}, 0, true},
		{"smb300 signing-optional encrypted", []smb2.Dialect{smb2.Dialect300}, smb2.CapEncryption, false},
		{"smb300 signing-required encrypted", []smb2.Dialect{smb2.Dialect300}, smb2.CapEncryption, true},
		{"smb302 signing-required encrypted", []smb2.Dialect{smb2.Dialect302}, smb2.CapEncryption, true},
		{"smb210 signing-optional", []smb2.Dialect{smb2.Dialect210}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &bytes.Buffer{}
			if err := transport.WriteFrame(in, buildClientNegotiatePre311(tc.dialects, tc.clientCaps)); err != nil {
				t.Fatal(err)
			}
			pipe := &rwPipe{in: in, out: &bytes.Buffer{}}
			lg := slog.New(slog.NewTextHandler(io.Discard, nil))
			conn, err := Negotiate(pipe, NegotiatorOptions{RequireSigning: tc.requireSigning}, lg)
			if err != nil {
				t.Fatalf("Negotiate: %v", err)
			}

			wantCaps, wantGuid, wantSecMode, wantDialect := negotiatedWireValues(t, conn)

			d := &Dispatcher{
				Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
				Conn:   conn,
				Shares: nil,
			}
			sess := &Session{ID: 1}
			status, out := doIoctl(t, d, sess, smb2.FsctlValidateNegotiateInfo, [16]byte{}, nil)
			if status != smb2.StatusSuccess {
				t.Fatalf("status = %#08x, want SUCCESS", uint32(status))
			}
			if len(out) != 24 {
				t.Fatalf("VALIDATE_NEGOTIATE_INFO response = %d bytes, want 24", len(out))
			}
			if got := smb2.Capabilities(binary.LittleEndian.Uint32(out[0:])); got != wantCaps {
				t.Errorf("Capabilities = %#08x, want %#08x (what NEGOTIATE sent)", uint32(got), uint32(wantCaps))
			}
			if !bytes.Equal(out[4:20], wantGuid[:]) {
				t.Errorf("ServerGuid = %x, want %x", out[4:20], wantGuid)
			}
			if got := binary.LittleEndian.Uint16(out[20:]); got != wantSecMode {
				t.Errorf("SecurityMode = %#04x, want %#04x (what NEGOTIATE sent)", got, wantSecMode)
			}
			if got := smb2.Dialect(binary.LittleEndian.Uint16(out[22:])); got != wantDialect {
				t.Errorf("Dialect = %#04x, want %#04x", uint16(got), uint16(wantDialect))
			}

			// Spell the two interesting fields out, so a regression that makes
			// both sides agree on the *wrong* value still fails here.
			wantSigningBit := uint16(smb2.NegotiateSigningEnabled)
			if tc.requireSigning {
				wantSigningBit |= smb2.NegotiateSigningRequired
			}
			if wantSecMode != wantSigningBit {
				t.Errorf("NEGOTIATE SecurityMode = %#04x, want %#04x", wantSecMode, wantSigningBit)
			}
			if wantCaps&smb2.CapLargeMTU == 0 {
				t.Error("NEGOTIATE Capabilities lost SMB2_GLOBAL_CAP_LARGE_MTU")
			}
			wantEncBit := tc.clientCaps&smb2.CapEncryption != 0
			if gotEncBit := wantCaps&smb2.CapEncryption != 0; gotEncBit != wantEncBit {
				t.Errorf("NEGOTIATE CAP_ENCRYPTION = %v, want %v", gotEncBit, wantEncBit)
			}
		})
	}
}

// TestValidateNegotiate_Echoes311 covers the dialect this server actually
// prefers. The client skips the FSCTL for 3.1.1, but nothing stops another one
// from sending it, and the answer must still be the truth.
func TestValidateNegotiate_Echoes311(t *testing.T) {
	in := &bytes.Buffer{}
	if err := transport.WriteFrame(in, buildClientNegotiate311()); err != nil {
		t.Fatal(err)
	}
	pipe := &rwPipe{in: in, out: &bytes.Buffer{}}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	conn, err := Negotiate(pipe, NegotiatorOptions{RequireEncryption: true, RequireSigning: true}, lg)
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	wantCaps, wantGuid, wantSecMode, wantDialect := negotiatedWireValues(t, conn)

	d := &Dispatcher{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Conn: conn}
	status, out := doIoctl(t, d, &Session{ID: 1}, smb2.FsctlValidateNegotiateInfo, [16]byte{}, nil)
	if status != smb2.StatusSuccess {
		t.Fatalf("status = %#08x, want SUCCESS", uint32(status))
	}
	if got := smb2.Capabilities(binary.LittleEndian.Uint32(out[0:])); got != wantCaps {
		t.Errorf("Capabilities = %#08x, want %#08x", uint32(got), uint32(wantCaps))
	}
	if !bytes.Equal(out[4:20], wantGuid[:]) {
		t.Errorf("ServerGuid = %x, want %x", out[4:20], wantGuid)
	}
	if got := binary.LittleEndian.Uint16(out[20:]); got != wantSecMode {
		t.Errorf("SecurityMode = %#04x, want %#04x", got, wantSecMode)
	}
	if got := smb2.Dialect(binary.LittleEndian.Uint16(out[22:])); got != wantDialect {
		t.Errorf("Dialect = %#04x, want %#04x", uint16(got), uint16(wantDialect))
	}
	if wantCaps&smb2.CapEncryption == 0 {
		t.Error("3.1.1 with a negotiated cipher did not advertise CAP_ENCRYPTION")
	}
}

// --- Defect 2a: resume keys ---

// TestResumeKey_RoundTripsToTheRightHandle proves an issued key resolves back
// to the open it was minted for, and never to a different one.
func TestResumeKey_RoundTripsToTheRightHandle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(a, []byte("aaaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("bbbb"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, false)
	openA := addFileOpen(t, sess, tree, a, os.O_RDONLY, smb2.AccessGenericRead)
	openB := addFileOpen(t, sess, tree, b, os.O_RDONLY, smb2.AccessGenericRead)

	keyA := resumeKeyFor(t, d, sess, openA)
	keyB := resumeKeyFor(t, d, sess, openB)
	if keyA == keyB {
		t.Fatal("two handles got the same resume key")
	}
	var zero [smb2.ResumeKeyLen]byte
	if keyA == zero {
		t.Fatal("resume key is all zeros — it must be unguessable, not derived from nothing")
	}
	if got := d.Conn.resumeKeys.resolve(keyA, sess); got != openA {
		t.Errorf("key A resolved to %p, want %p", got, openA)
	}
	if got := d.Conn.resumeKeys.resolve(keyB, sess); got != openB {
		t.Errorf("key B resolved to %p, want %p", got, openB)
	}

	// An arbitrary 24 bytes must resolve to nothing.
	var bogus [smb2.ResumeKeyLen]byte
	bogus[0] = 0xFF
	if got := d.Conn.resumeKeys.resolve(bogus, sess); got != nil {
		t.Errorf("a made-up key resolved to %p, want nil", got)
	}
}

// TestResumeKey_IssuedOnDirectoryHandle proves the mount-time probe works.
// macOS runs smb2fs_smb_cmpd_check_copyfile against the share root — a
// directory — and only sets SMBV_HAS_COPYCHUNK (and so VOL_CAP_INT_COPYFILE) if
// the resume key comes back. Refusing directories here would silently disable
// server-side copy for the entire mount.
func TestResumeKey_IssuedOnDirectoryHandle(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCopyDispatcher(t, dir, false)
	testFileIDSeq++
	o := &Open{Path: dir, IsDir: true, Tree: tree, GrantedAccess: smb2.AccessGenericRead}
	o.FileID[0] = testFileIDSeq
	sess.AddOpen(o)

	status, out := doIoctl(t, d, sess, smb2.FsctlSrvRequestResumeKey, o.FileID, nil)
	if status != smb2.StatusSuccess {
		t.Fatalf("resume key on a directory handle: status = %#08x, want SUCCESS", uint32(status))
	}
	if len(out) < smb2.ResumeKeyLen {
		t.Fatalf("resume key response = %d bytes, want at least %d", len(out), smb2.ResumeKeyLen)
	}
}

// TestResumeKey_StableForOneHandle proves asking twice returns the same key, so
// a client looping on the FSCTL cannot grow the table without bound.
func TestResumeKey_StableForOneHandle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, false)
	open := addFileOpen(t, sess, tree, p, os.O_RDONLY, smb2.AccessGenericRead)

	first := resumeKeyFor(t, d, sess, open)
	for i := 0; i < 5; i++ {
		if again := resumeKeyFor(t, d, sess, open); again != first {
			t.Fatalf("request %d returned a different key", i+2)
		}
	}
	if n := d.Conn.resumeKeys.len(); n != 1 {
		t.Errorf("resume-key table holds %d entries after 6 requests on one handle, want 1", n)
	}
}

// TestResumeKey_RefusedFromAnotherSession is the security case. A resume key is
// a bearer capability naming an open file: MS-SMB2 §3.3.5.15.6 requires the
// source handle to belong to the session issuing the copy. Without that check a
// second session on the same connection — another user, or a guest — could read
// any file the first user had open by replaying 24 bytes.
func TestResumeKey_RefusedFromAnotherSession(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("the victim's bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "stolen.txt")
	if err := os.WriteFile(dst, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	d, victim, tree := newCopyDispatcher(t, dir, false)
	srcOpen := addFileOpen(t, victim, tree, src, os.O_RDONLY, smb2.AccessGenericRead)
	key := resumeKeyFor(t, d, victim, srcOpen)

	// A second, independently authenticated session on the same connection.
	attacker := &Session{ID: 2}
	attackerTree := attacker.AddTree(config.ShareConfig{Name: "share", Path: dir})
	dstOpen := addFileOpen(t, attacker, attackerTree, dst, os.O_RDWR, smb2.AccessGenericAll)

	// Direct table check: the key must not resolve for the other session.
	if got := d.Conn.resumeKeys.resolve(key, attacker); got != nil {
		t.Fatalf("a resume key from another session resolved to %p", got)
	}

	// End to end: the copy must be refused, and nothing may reach the target.
	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{SourceOffset: 0, TargetOffset: 0, Length: 18}})
	status, _ := doIoctl(t, d, attacker, smb2.FsctlSrvCopyChunk, dstOpen.FileID, in)
	if status != smb2.StatusObjectNameNotFound {
		t.Errorf("cross-session copychunk status = %#08x, want STATUS_OBJECT_NAME_NOT_FOUND", uint32(status))
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("cross-session copychunk wrote %q to the target", got)
	}
}

// TestCopyChunk_UnknownKeyRefused proves a key the server never issued is
// refused the same way a foreign one is, so probing tells an attacker nothing.
func TestCopyChunk_UnknownKeyRefused(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(dst, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, false)
	dstOpen := addFileOpen(t, sess, tree, dst, os.O_RDWR, smb2.AccessGenericAll)

	var bogus [smb2.ResumeKeyLen]byte
	for i := range bogus {
		bogus[i] = byte(i)
	}
	in := buildCopyChunkInput(bogus, []smb2.SrvCopyChunk{{Length: 4}})
	status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dstOpen.FileID, in)
	if status != smb2.StatusObjectNameNotFound {
		t.Errorf("unknown-key copychunk status = %#08x, want STATUS_OBJECT_NAME_NOT_FOUND", uint32(status))
	}
}

// --- Defect 2b: copychunk ---

// copyChunkFixture sets up a source file with content, an empty target, and
// handles on both in one session.
func copyChunkFixture(t *testing.T, content []byte, readOnly bool) (*Dispatcher, *Session, *Open, *Open, string) {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.bin")
	dstPath := filepath.Join(dir, "dst.bin")
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, readOnly)
	src := addFileOpen(t, sess, tree, srcPath, os.O_RDONLY, smb2.AccessGenericRead)
	dst := addFileOpen(t, sess, tree, dstPath, os.O_RDWR, smb2.AccessGenericAll)
	return d, sess, src, dst, dstPath
}

// parseCopyChunkResponse decodes the 12-byte SRV_COPYCHUNK_RESPONSE.
func parseCopyChunkResponse(t *testing.T, out []byte) (chunks, chunkBytes, total uint32) {
	t.Helper()
	if len(out) != 12 {
		t.Fatalf("SRV_COPYCHUNK_RESPONSE = %d bytes, want 12 (macOS rejects anything shorter)", len(out))
	}
	return binary.LittleEndian.Uint32(out[0:]),
		binary.LittleEndian.Uint32(out[4:]),
		binary.LittleEndian.Uint32(out[8:])
}

// TestCopyChunk_SingleChunk proves the simplest whole-file copy moves the right
// bytes and reports them.
func TestCopyChunk_SingleChunk(t *testing.T) {
	content := bytes.Repeat([]byte("gosamba!"), 1024) // 8 KiB
	d, sess, src, dst, dstPath := copyChunkFixture(t, content, false)
	key := resumeKeyFor(t, d, sess, src)

	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{
		{SourceOffset: 0, TargetOffset: 0, Length: uint32(len(content))},
	})
	status, out := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusSuccess {
		t.Fatalf("status = %#08x, want SUCCESS", uint32(status))
	}
	chunks, _, total := parseCopyChunkResponse(t, out)
	// macOS fails the copy outright unless ChunksWritten equals the count it
	// sent and TotalBytesWritten equals the length it asked for.
	if chunks != 1 {
		t.Errorf("ChunksWritten = %d, want 1", chunks)
	}
	if total != uint32(len(content)) {
		t.Errorf("TotalBytesWritten = %d, want %d", total, len(content))
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("target has %d bytes, want the source's %d (equal: %v)", len(got), len(content), bytes.Equal(got, content))
	}
}

// TestCopyChunk_MultipleChunksAndSourceOffset proves several chunks apply in
// order, including a chunk that starts part-way into the source and lands at a
// different target offset — the case a naive "just copy the whole file"
// implementation gets wrong.
func TestCopyChunk_MultipleChunksAndSourceOffset(t *testing.T) {
	// Distinguishable content: byte i is i mod 251.
	content := make([]byte, 64<<10)
	for i := range content {
		content[i] = byte(i % 251)
	}
	d, sess, src, dst, dstPath := copyChunkFixture(t, content, false)
	key := resumeKeyFor(t, d, sess, src)

	// Reassemble the file out of order and out of alignment: the tail first,
	// then the head, then one slice lifted from the middle and parked past the
	// end of the original content.
	const tailOff, tailLen = 40 << 10, 24 << 10
	const headLen = 40 << 10
	const midOff, midLen, midTarget = 1234, 4321, 64 << 10
	chunks := []smb2.SrvCopyChunk{
		{SourceOffset: tailOff, TargetOffset: tailOff, Length: tailLen},
		{SourceOffset: 0, TargetOffset: 0, Length: headLen},
		{SourceOffset: midOff, TargetOffset: midTarget, Length: midLen},
	}
	in := buildCopyChunkInput(key, chunks)
	status, out := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusSuccess {
		t.Fatalf("status = %#08x, want SUCCESS", uint32(status))
	}
	gotChunks, chunkBytes, total := parseCopyChunkResponse(t, out)
	if gotChunks != uint32(len(chunks)) {
		t.Errorf("ChunksWritten = %d, want %d", gotChunks, len(chunks))
	}
	if want := uint32(tailLen + headLen + midLen); total != want {
		t.Errorf("TotalBytesWritten = %d, want %d", total, want)
	}
	// On full success ChunkBytesWritten only carries a partial count, so it is 0.
	if chunkBytes != 0 {
		t.Errorf("ChunkBytesWritten = %d on a fully successful copy, want 0", chunkBytes)
	}

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != midTarget+midLen {
		t.Fatalf("target is %d bytes, want %d", len(got), midTarget+midLen)
	}
	if !bytes.Equal(got[:len(content)], content) {
		t.Error("the first 64 KiB of the target does not match the source")
	}
	if !bytes.Equal(got[midTarget:], content[midOff:midOff+midLen]) {
		t.Errorf("the chunk copied from source offset %d did not land at target offset %d", midOff, midTarget)
	}
}

// TestCopyChunk_ReadOnlyShareRefused proves a read-only share stays read-only.
// Performing the write inside the server does not make it less of a write.
func TestCopyChunk_ReadOnlyShareRefused(t *testing.T) {
	content := []byte("some bytes to copy")
	d, sess, src, dst, dstPath := copyChunkFixture(t, content, true)
	key := resumeKeyFor(t, d, sess, src)

	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{Length: uint32(len(content))}})
	status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusAccessDenied {
		t.Fatalf("status = %#08x, want STATUS_ACCESS_DENIED", uint32(status))
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("copychunk wrote %q into a read-only share", got)
	}
}

// TestCopyChunk_TargetWithoutWriteAccessRefused proves COPYCHUNK cannot be used
// to write through a handle that was only granted read.
func TestCopyChunk_TargetWithoutWriteAccessRefused(t *testing.T) {
	content := []byte("payload")
	d, sess, src, dst, dstPath := copyChunkFixture(t, content, false)
	dst.GrantedAccess = smb2.AccessFileReadData
	key := resumeKeyFor(t, d, sess, src)

	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{Length: uint32(len(content))}})
	status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusAccessDenied {
		t.Fatalf("status = %#08x, want STATUS_ACCESS_DENIED", uint32(status))
	}
	if got, _ := os.ReadFile(dstPath); len(got) != 0 {
		t.Fatalf("copychunk wrote %q through a read-only handle", got)
	}
}

// TestCopyChunk_SourceRangePastEndOfFile proves an out-of-range source range is
// refused before anything is written, with the status MS-SMB2 §3.3.5.15.6
// mandates. It must not be STATUS_INVALID_PARAMETER: the client reads that as
// "chunk too big, retry smaller" and would loop.
func TestCopyChunk_SourceRangePastEndOfFile(t *testing.T) {
	content := []byte("only sixteen by")
	cases := []struct {
		name  string
		chunk smb2.SrvCopyChunk
	}{
		{"length past end", smb2.SrvCopyChunk{SourceOffset: 0, Length: uint32(len(content)) + 1}},
		{"offset past end", smb2.SrvCopyChunk{SourceOffset: uint64(len(content)) + 100, Length: 1}},
		{"offset overflows int64", smb2.SrvCopyChunk{SourceOffset: 1 << 63, Length: 1}},
		{"sum overflows", smb2.SrvCopyChunk{SourceOffset: ^uint64(0) - 3, Length: 16}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, sess, src, dst, dstPath := copyChunkFixture(t, content, false)
			key := resumeKeyFor(t, d, sess, src)
			in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{tc.chunk})
			status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
			if status == smb2.StatusSuccess {
				t.Fatal("an out-of-range chunk was accepted")
			}
			if got, _ := os.ReadFile(dstPath); len(got) != 0 {
				t.Fatalf("a refused copychunk still wrote %q", got)
			}
		})
	}
}

// TestCopyChunk_OutOfRangeUsesInvalidViewSize pins the exact status for the
// plain "reads past EOF" case.
func TestCopyChunk_OutOfRangeUsesInvalidViewSize(t *testing.T) {
	content := []byte("sixteen bytes...")
	d, sess, src, dst, _ := copyChunkFixture(t, content, false)
	key := resumeKeyFor(t, d, sess, src)
	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{SourceOffset: 8, Length: uint32(len(content))}})
	status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusInvalidViewSize {
		t.Fatalf("status = %#08x, want STATUS_INVALID_VIEW_SIZE (%#08x)",
			uint32(status), uint32(smb2.StatusInvalidViewSize))
	}
}

// TestCopyChunk_OversizedRequestsReturnLimits proves every "you asked for too
// much" case is refused with STATUS_INVALID_PARAMETER *and* the three ceilings,
// inside a StructureSize-49 IOCTL response. macOS retries once using
// ChunkBytesWritten as its new chunk size; a bare error instead loses the retry
// and with it server-side copy for that file.
func TestCopyChunk_OversizedRequestsReturnLimits(t *testing.T) {
	content := bytes.Repeat([]byte{0x5A}, 4096)

	tooManyChunks := make([]smb2.SrvCopyChunk, maxCopyChunkCount+1)
	for i := range tooManyChunks {
		tooManyChunks[i] = smb2.SrvCopyChunk{Length: 1}
	}
	// Each chunk is inside the per-chunk limit, but together they blow the
	// per-request total.
	overTotal := make([]smb2.SrvCopyChunk, 17)
	for i := range overTotal {
		overTotal[i] = smb2.SrvCopyChunk{Length: maxCopyChunkSize}
	}

	cases := []struct {
		name   string
		chunks []smb2.SrvCopyChunk
	}{
		{"zero chunks", nil},
		{"chunk count above the ceiling", tooManyChunks},
		{"one chunk above the per-chunk ceiling", []smb2.SrvCopyChunk{{Length: maxCopyChunkSize + 1}}},
		{"total above the per-request ceiling", overTotal},
		{"zero-length chunk", []smb2.SrvCopyChunk{{Length: 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, sess, src, dst, dstPath := copyChunkFixture(t, content, false)
			key := resumeKeyFor(t, d, sess, src)
			in := buildCopyChunkInput(key, tc.chunks)
			status, out := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
			if status != smb2.StatusInvalidParameter {
				t.Fatalf("status = %#08x, want STATUS_INVALID_PARAMETER", uint32(status))
			}
			limChunks, limChunkBytes, limTotal := parseCopyChunkResponse(t, out)
			if limChunks != maxCopyChunkCount {
				t.Errorf("limit ChunksWritten = %d, want %d", limChunks, maxCopyChunkCount)
			}
			if limChunkBytes != maxCopyChunkSize {
				t.Errorf("limit ChunkBytesWritten = %d, want %d", limChunkBytes, maxCopyChunkSize)
			}
			if limTotal != maxCopyChunkTotal {
				t.Errorf("limit TotalBytesWritten = %d, want %d", limTotal, maxCopyChunkTotal)
			}
			if got, _ := os.ReadFile(dstPath); len(got) != 0 {
				t.Fatalf("a refused copychunk still wrote %q", got)
			}
		})
	}
}

// TestCopyChunk_TruncatedRequestRefused proves a request whose buffer is too
// short for the chunk count it declares is refused rather than read past.
func TestCopyChunk_TruncatedRequestRefused(t *testing.T) {
	d, sess, src, dst, _ := copyChunkFixture(t, []byte("content"), false)
	key := resumeKeyFor(t, d, sess, src)

	// Claim four chunks, supply one.
	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{Length: 4}})
	binary.LittleEndian.PutUint32(in[24:], 4)
	status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusInvalidParameter {
		t.Fatalf("status = %#08x, want STATUS_INVALID_PARAMETER", uint32(status))
	}

	// A request with no room for even the fixed header.
	status, _ = doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, []byte{1, 2, 3})
	if status != smb2.StatusInvalidParameter {
		t.Fatalf("short-header status = %#08x, want STATUS_INVALID_PARAMETER", uint32(status))
	}
}

// TestCopyChunk_HugeChunkCountAllocatesNothing proves a request that claims a
// vast number of chunks in a tiny buffer is refused on the declared count, not
// after trying to allocate for it. The decoder checks ChunkCount against the
// ceiling before it sizes the chunk slice, so 4 billion claimed chunks cost
// nothing.
func TestCopyChunk_HugeChunkCountAllocatesNothing(t *testing.T) {
	d, sess, src, dst, _ := copyChunkFixture(t, []byte("content"), false)
	key := resumeKeyFor(t, d, sess, src)

	in := make([]byte, 32)
	copy(in[0:24], key[:])
	binary.LittleEndian.PutUint32(in[24:], ^uint32(0)) // 4,294,967,295 chunks
	status, out := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusInvalidParameter {
		t.Fatalf("status = %#08x, want STATUS_INVALID_PARAMETER", uint32(status))
	}
	if limChunks, _, _ := parseCopyChunkResponse(t, out); limChunks != maxCopyChunkCount {
		t.Errorf("limit ChunksWritten = %d, want %d", limChunks, maxCopyChunkCount)
	}
}

// TestCopyChunk_WriteVariantWorks proves FSCTL_SRV_COPYCHUNK_WRITE, which asks
// only for write access on the target, is handled too.
func TestCopyChunk_WriteVariantWorks(t *testing.T) {
	content := []byte("copychunk-write payload")
	d, sess, src, dst, dstPath := copyChunkFixture(t, content, false)
	dst.GrantedAccess = smb2.AccessFileWriteData // write only: no read bit
	key := resumeKeyFor(t, d, sess, src)

	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{Length: uint32(len(content))}})

	// Plain COPYCHUNK needs read *and* write on the target.
	if status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in); status != smb2.StatusAccessDenied {
		t.Errorf("COPYCHUNK on a write-only target: status = %#08x, want ACCESS_DENIED", uint32(status))
	}
	// COPYCHUNK_WRITE needs only write.
	status, out := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunkWrite, dst.FileID, in)
	if status != smb2.StatusSuccess {
		t.Fatalf("COPYCHUNK_WRITE status = %#08x, want SUCCESS", uint32(status))
	}
	if _, _, total := parseCopyChunkResponse(t, out); total != uint32(len(content)) {
		t.Errorf("TotalBytesWritten = %d, want %d", total, len(content))
	}
	if got, _ := os.ReadFile(dstPath); !bytes.Equal(got, content) {
		t.Fatalf("target = %q, want %q", got, content)
	}
}

// TestCopyChunk_DirectorySourceRefused proves a directory handle — which has no
// descriptor behind it — cannot be used as a copy source even though it is
// allowed to hold a resume key.
func TestCopyChunk_DirectorySourceRefused(t *testing.T) {
	dir := t.TempDir()
	dstPath := filepath.Join(dir, "dst.bin")
	if err := os.WriteFile(dstPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, false)
	testFileIDSeq++
	srcDir := &Open{Path: dir, IsDir: true, Tree: tree, GrantedAccess: smb2.AccessGenericRead}
	srcDir.FileID[0] = testFileIDSeq
	sess.AddOpen(srcDir)
	dst := addFileOpen(t, sess, tree, dstPath, os.O_RDWR, smb2.AccessGenericAll)

	key := resumeKeyFor(t, d, sess, srcDir)
	in := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{Length: 4}})
	status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dst.FileID, in)
	if status != smb2.StatusInvalidParameter {
		t.Fatalf("status = %#08x, want STATUS_INVALID_PARAMETER", uint32(status))
	}
}

// TestCopyChunk_SelfOverlapRefused proves an in-place copy whose source and
// target ranges overlap is refused rather than silently producing wrong bytes,
// while a non-overlapping copy within one file still works.
func TestCopyChunk_SelfOverlapRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "self.bin")
	content := make([]byte, 4096)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, false)
	srcH := addFileOpen(t, sess, tree, p, os.O_RDONLY, smb2.AccessGenericRead)
	dstH := addFileOpen(t, sess, tree, p, os.O_RDWR, smb2.AccessGenericAll)
	key := resumeKeyFor(t, d, sess, srcH)

	overlap := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{SourceOffset: 0, TargetOffset: 100, Length: 1000}})
	if status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dstH.FileID, overlap); status != smb2.StatusInvalidParameter {
		t.Errorf("overlapping self-copy status = %#08x, want STATUS_INVALID_PARAMETER", uint32(status))
	}

	disjoint := buildCopyChunkInput(key, []smb2.SrvCopyChunk{{SourceOffset: 0, TargetOffset: 2048, Length: 1024}})
	if status, _ := doIoctl(t, d, sess, smb2.FsctlSrvCopyChunk, dstH.FileID, disjoint); status != smb2.StatusSuccess {
		t.Fatalf("disjoint self-copy status = %#08x, want SUCCESS", uint32(status))
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[2048:3072], content[0:1024]) {
		t.Error("disjoint self-copy moved the wrong bytes")
	}
}

// --- resume-key lifetime ---

// TestResumeKey_ReleasedOnClose proves CLOSE retires the key. A key that
// outlived its handle would keep the *Open (and its fd) reachable and would
// still resolve for a later copy.
func TestResumeKey_ReleasedOnClose(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, false)
	open := addFileOpen(t, sess, tree, p, os.O_RDONLY, smb2.AccessGenericRead)
	key := resumeKeyFor(t, d, sess, open)
	if d.Conn.resumeKeys.len() != 1 {
		t.Fatalf("table holds %d entries before CLOSE, want 1", d.Conn.resumeKeys.len())
	}

	d.handleClose(discardRW{}, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)

	if n := d.Conn.resumeKeys.len(); n != 0 {
		t.Errorf("table holds %d entries after CLOSE, want 0", n)
	}
	if got := d.Conn.resumeKeys.resolve(key, sess); got != nil {
		t.Errorf("a closed handle's resume key still resolves to %p", got)
	}
}

// TestResumeKey_ReleasedOnReleaseOpens proves the batch teardown path —
// TREE_DISCONNECT, LOGOFF and previous-session close all funnel through
// releaseOpens — retires keys too.
func TestResumeKey_ReleasedOnReleaseOpens(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCopyDispatcher(t, dir, false)
	for _, name := range []string{"a", "b", "c"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		resumeKeyFor(t, d, sess, addFileOpen(t, sess, tree, p, os.O_RDONLY, smb2.AccessGenericRead))
	}
	if n := d.Conn.resumeKeys.len(); n != 3 {
		t.Fatalf("table holds %d entries, want 3", n)
	}

	// This is what handleTreeDisconnect and handleLogoff both do.
	d.releaseOpens(sess.TakeAllOpens())

	if n := d.Conn.resumeKeys.len(); n != 0 {
		t.Errorf("table holds %d entries after releaseOpens, want 0", n)
	}
}

// TestResumeKey_ReleasedOnConnectionTeardown drives the same sequence
// ServeConn's teardown defer runs when the socket dies, and proves no key (and
// so no *Open, and so no fd) survives it — including for the durable opens that
// teardown deliberately leaves alive.
func TestResumeKey_ReleasedOnConnectionTeardown(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "durable.txt")
	if err := os.WriteFile(p, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newCopyDispatcher(t, dir, false)
	open := addFileOpen(t, sess, tree, p, os.O_RDONLY, smb2.AccessGenericRead)
	open.IsDurable = true
	key := resumeKeyFor(t, d, sess, open)
	if d.Conn.resumeKeys.len() != 1 {
		t.Fatalf("table holds %d entries, want 1", d.Conn.resumeKeys.len())
	}

	// ServeConn's deferred teardown: cancel notifies, then drop resume keys.
	d.CancelAllNotifies()
	d.Conn.resumeKeys.clear()

	if n := d.Conn.resumeKeys.len(); n != 0 {
		t.Errorf("table holds %d entries after connection teardown, want 0", n)
	}
	if got := d.Conn.resumeKeys.resolve(key, sess); got != nil {
		t.Errorf("a resume key survived connection teardown and resolves to %p", got)
	}
	// Issuing again on a cleared table must still work (no nil-map panic).
	if _, err := d.Conn.resumeKeys.issue(sess, open); err != nil {
		t.Fatalf("issue after clear: %v", err)
	}
}

// --- copyRange ---

// TestCopyRange_MatchesSourceBytes exercises copyRange directly across sizes
// that straddle the fallback's staging buffer, so the linux copy_file_range
// path and the portable pread/pwrite loop are both held to the same result.
func TestCopyRange_MatchesSourceBytes(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, copyBufSize*2+7777)
	for i := range content {
		content[i] = byte(i * 7)
	}
	srcPath := filepath.Join(dir, "src")
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	for _, n := range []int64{1, copyBufSize - 1, copyBufSize, copyBufSize + 1, int64(len(content)) - 4096} {
		dstPath := filepath.Join(dir, "dst")
		dst, err := os.OpenFile(dstPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		const srcOff, dstOff = 4096, 512
		got, err := copyRange(dst, src, srcOff, dstOff, n)
		if err != nil {
			dst.Close()
			t.Fatalf("copyRange(n=%d): %v", n, err)
		}
		if got != n {
			dst.Close()
			t.Fatalf("copyRange(n=%d) copied %d bytes", n, got)
		}
		dst.Close()
		out, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(out)) != dstOff+n {
			t.Fatalf("n=%d: target is %d bytes, want %d", n, len(out), dstOff+n)
		}
		if !bytes.Equal(out[dstOff:], content[srcOff:srcOff+n]) {
			t.Fatalf("n=%d: copied bytes differ from the source range", n)
		}
	}
}
