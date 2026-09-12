package parent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
)

// --- reference encoders ---------------------------------------------------
//
// These reproduce, byte for byte, what the pre-optimisation READ path emitted:
// smb2.EncodeReadResponse into a fresh body, buildResponse into a fresh
// header+body buffer, transport.WriteFrame into a fresh NBSS frame. The whole
// point of the single-allocation rewrite is that not one wire byte moves, so
// every response the handler produces is compared against these.

func refRespHeader(reqHdr smb2.Header, status smb2.Status) smb2.Header {
	return smb2.Header{
		CreditCharge:   reqHdr.CreditCharge,
		Status:         uint32(status),
		Command:        reqHdr.Command,
		CreditResponse: grantCredits(reqHdr.CreditCharge, reqHdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      reqHdr.MessageID,
		TreeID:         reqHdr.TreeID,
		SessionID:      reqHdr.SessionID,
	}
}

// refNBSS wraps an SMB2 message the way transport.WriteFrame does.
func refNBSS(msg []byte) []byte {
	frame := make([]byte, 4+len(msg))
	frame[0] = 0x00
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	copy(frame[4:], msg)
	return frame
}

// refReadMessage is the old header+body for a successful READ.
func refReadMessage(reqHdr smb2.Header, data []byte) []byte {
	body := smb2.EncodeReadResponse(smb2.ReadResponse{Data: data})
	msg := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(msg[:smb2.HeaderSize], refRespHeader(reqHdr, smb2.StatusSuccess))
	copy(msg[smb2.HeaderSize:], body)
	return msg
}

// refErrorMessage is the old header+body for an error response.
func refErrorMessage(reqHdr smb2.Header, status smb2.Status) []byte {
	errBody := []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	msg := make([]byte, smb2.HeaderSize+len(errBody))
	_ = smb2.EncodeHeader(msg[:smb2.HeaderSize], refRespHeader(reqHdr, status))
	copy(msg[smb2.HeaderSize:], errBody)
	return msg
}

// --- fixtures -------------------------------------------------------------

// readallocRig is a dispatcher with one share, one session and one open file
// handle, ready to be driven by handleRead / handleWrite directly.
type readallocRig struct {
	d    *Dispatcher
	sess *Session
	tree *Tree
	open *Open
	path string
}

// newReadallocRig writes a file of size bytes (a repeating, position-dependent
// pattern so a misplaced copy shows up) and returns a rig over it.
func newReadallocRig(tb testing.TB, size int) *readallocRig {
	tb.Helper()
	dir := tb.TempDir()
	path := filepath.Join(dir, "payload.bin")
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i*7 + 3)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		tb.Fatal(err)
	}

	share := config.ShareConfig{Name: "share", Path: dir}
	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{share},
		Conn:   &Connection{MaxIOSize: 8 << 20},
	}
	sess := &Session{}
	tree := sess.AddTree(share)

	f, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = f.Close() })

	var fid [16]byte
	fid[0] = 0xA5
	open := &Open{
		FileID:        fid,
		Path:          path,
		File:          f,
		Tree:          tree,
		GrantedAccess: smb2.AccessGenericRead,
	}
	sess.AddOpen(open)
	return &readallocRig{d: d, sess: sess, tree: tree, open: open, path: path}
}

// encrypt switches the rig's session onto an SMB3 transform-encrypted path.
func (r *readallocRig) encrypt(tb testing.TB, cipher smb2.Cipher) {
	tb.Helper()
	keyLen := 16
	if cipher == smb2.CipherAES256CCM || cipher == smb2.CipherAES256GCM {
		keyLen = 32
	}
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	r.d.Conn.Selection.Cipher = cipher
	r.sess.ID = 0x1122334455667788
	r.sess.S2CCipherKey = key
	r.sess.C2SCipherKey = key
	r.sess.SetGotEncrypted()
}

// readHdr is a request header with every carried-through field non-zero, so a
// dropped MessageId / TreeId / credit field cannot pass unnoticed.
func readHdr() smb2.Header {
	return smb2.Header{
		Command:        smb2.CommandRead,
		CreditCharge:   3,
		CreditResponse: 17,
		MessageID:      0xDEADBEEF,
		TreeID:         0x2A,
		SessionID:      0x1122334455667788,
	}
}

// --- Defect 1: response bytes are unchanged -------------------------------

// TestReadAlloc_ResponseBytesUnchanged pins the wire output of the
// single-allocation READ path against the reference encoders for a full-size
// read, a one-byte read, a short read at EOF and a zero-length read. A
// performance change that alters one byte here breaks every client.
func TestReadAlloc_ResponseBytesUnchanged(t *testing.T) {
	const fileSize = 4096
	cases := []struct {
		name   string
		offset uint64
		length uint32
	}{
		{"zero-length", 0, 0},
		{"one-byte", 0, 1},
		{"whole-file", 0, fileSize},
		{"short-read-at-eof", fileSize - 10, 64 * 1024},
		{"tail-exact", fileSize - 1, 1},
		{"unaligned-middle", 1234, 777},
		{"over-request-from-zero", 0, 1 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newReadallocRig(t, fileSize)
			content, err := os.ReadFile(rig.path)
			if err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			hdr := readHdr()
			rig.d.handleRead(&buf, hdr, buildReadBody(rig.open.FileID, tc.offset, tc.length), rig.sess)

			// What the old implementation would have produced.
			var want []byte
			end := tc.offset + uint64(tc.length)
			if end > uint64(len(content)) {
				end = uint64(len(content))
			}
			if tc.offset >= uint64(len(content)) || end <= tc.offset {
				want = refNBSS(refErrorMessage(hdr, smb2.StatusEndOfFile))
			} else {
				want = refNBSS(refReadMessage(hdr, content[tc.offset:end]))
			}

			if got := buf.Bytes(); !bytes.Equal(got, want) {
				t.Fatalf("response frame differs from reference\n got %d bytes: %x\nwant %d bytes: %x",
					len(got), truncHex(got), len(want), truncHex(want))
			}
		})
	}
}

// truncHex keeps failure output readable for large payloads.
func truncHex(b []byte) []byte {
	if len(b) > 160 {
		return b[:160]
	}
	return b
}

// TestReadAlloc_StructureSizeAndDataOffset asserts the two fields Apple's
// parser is unforgiving about: StructureSize 17 and DataOffset 80. A
// DataOffset below 80 underflows the client's buffer arithmetic.
func TestReadAlloc_StructureSizeAndDataOffset(t *testing.T) {
	rig := newReadallocRig(t, 512)
	var buf bytes.Buffer
	rig.d.handleRead(&buf, readHdr(), buildReadBody(rig.open.FileID, 0, 512), rig.sess)

	body := buf.Bytes()[4+smb2.HeaderSize:]
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 17 {
		t.Errorf("StructureSize = %d, want 17", ss)
	}
	if body[2] != 80 {
		t.Errorf("DataOffset = %d, want 80", body[2])
	}
	if n := binary.LittleEndian.Uint32(body[4:]); n != 512 {
		t.Errorf("DataLength = %d, want 512", n)
	}
	if len(body) != 16+512 {
		t.Errorf("body = %d bytes, want %d", len(body), 16+512)
	}
}

// TestReadAlloc_SignedResponseVerifies proves the pre-framed buffer is still
// signed over exactly the SMB2 message and not over the NBSS prefix.
func TestReadAlloc_SignedResponseVerifies(t *testing.T) {
	rig := newReadallocRig(t, 2048)
	rig.sess.SigningKey = bytes.Repeat([]byte{0x5A}, 16)

	var buf bytes.Buffer
	rig.d.handleRead(&buf, readHdr(), buildReadBody(rig.open.FileID, 0, 2048), rig.sess)

	frame := buf.Bytes()
	if len(frame) != 4+smb2.HeaderSize+16+2048 {
		t.Fatalf("frame = %d bytes, want %d", len(frame), 4+smb2.HeaderSize+16+2048)
	}
	msg := frame[4:]
	if !smb3.VerifyMessage(uint16(rig.d.Conn.Selection.SigningAlgo), rig.sess.SigningKey, msg) {
		t.Fatalf("signature does not verify over the pre-framed response")
	}
	hdr, err := smb2.DecodeHeader(msg[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Flags&smb2.FlagSigned == 0 {
		t.Errorf("FlagSigned not set on signed response")
	}
}

// TestReadAlloc_EncryptedResponseBytesUnchanged runs the encrypted fallback:
// the frame must be a transform frame that decrypts to exactly the same SMB2
// message the cleartext path emits.
func TestReadAlloc_EncryptedResponseBytesUnchanged(t *testing.T) {
	for _, cipher := range []smb2.Cipher{
		smb2.CipherAES128CCM, smb2.CipherAES128GCM,
		smb2.CipherAES256CCM, smb2.CipherAES256GCM,
	} {
		t.Run(fmt.Sprintf("cipher-0x%04x", uint16(cipher)), func(t *testing.T) {
			const fileSize = 8192
			rig := newReadallocRig(t, fileSize)
			rig.encrypt(t, cipher)
			content, err := os.ReadFile(rig.path)
			if err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			hdr := readHdr()
			// Over-request so the EOF clamp is exercised under encryption too.
			rig.d.handleRead(&buf, hdr, buildReadBody(rig.open.FileID, 1000, 1<<20), rig.sess)

			frame := buf.Bytes()
			if len(frame) < 4 {
				t.Fatalf("no response written")
			}
			payload := frame[4:]
			if declared := int(frame[1])<<16 | int(frame[2])<<8 | int(frame[3]); declared != len(payload) {
				t.Fatalf("NBSS length %d != payload %d", declared, len(payload))
			}
			if !smb3.IsTransform(payload) {
				t.Fatalf("encrypted session produced a cleartext frame")
			}
			plain, sessID, err := smb3.DecryptTransform(uint16(cipher), rig.sess.C2SCipherKey, payload)
			if err != nil {
				t.Fatalf("DecryptTransform: %v", err)
			}
			if sessID != rig.sess.ID {
				t.Errorf("transform SessionId = %#x, want %#x", sessID, rig.sess.ID)
			}
			want := refReadMessage(hdr, content[1000:])
			if !bytes.Equal(plain, want) {
				t.Fatalf("decrypted message differs from reference\n got %d bytes\nwant %d bytes",
					len(plain), len(want))
			}
		})
	}
}

// --- Defect 2: clamp to what is left of the file --------------------------

// TestReadAlloc_PastEOF proves an offset at or past end-of-file is refused
// with STATUS_END_OF_FILE rather than allocating the requested quantum.
func TestReadAlloc_PastEOF(t *testing.T) {
	const fileSize = 4096
	for _, off := range []uint64{fileSize, fileSize + 1, 1 << 30} {
		rig := newReadallocRig(t, fileSize)
		var buf bytes.Buffer
		rig.d.handleRead(&buf, readHdr(), buildReadBody(rig.open.FileID, off, 1<<20), rig.sess)
		if st := respStatus(t, &buf); st != smb2.StatusEndOfFile {
			t.Errorf("READ at offset %d status=0x%08X, want END_OF_FILE", off, st)
		}
	}
}

// TestReadAlloc_EmptyFileEOF: a zero-byte file has nothing at offset 0 either.
func TestReadAlloc_EmptyFileEOF(t *testing.T) {
	rig := newReadallocRig(t, 0)
	var buf bytes.Buffer
	rig.d.handleRead(&buf, readHdr(), buildReadBody(rig.open.FileID, 0, 1<<20), rig.sess)
	if st := respStatus(t, &buf); st != smb2.StatusEndOfFile {
		t.Errorf("READ of empty file status=0x%08X, want END_OF_FILE", st)
	}
}

// TestReadAlloc_NoNewShortRead is the guard the clamp must not break: when the
// file really does hold every byte asked for, the response must carry them
// all. The clamp is only allowed to shorten a read that was already going to
// be short.
func TestReadAlloc_NoNewShortRead(t *testing.T) {
	const fileSize = 256 << 10
	rig := newReadallocRig(t, fileSize)
	content, err := os.ReadFile(rig.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []uint32{1, 4096, 64 << 10, fileSize} {
		var buf bytes.Buffer
		rig.d.handleRead(&buf, readHdr(), buildReadBody(rig.open.FileID, 0, length), rig.sess)
		body := frameBody(t, &buf)
		if got := binary.LittleEndian.Uint32(body[4:]); got != length {
			t.Fatalf("READ of %d bytes returned %d — clamp invented a short read", length, got)
		}
		if !bytes.Equal(body[16:], content[:length]) {
			t.Fatalf("READ of %d bytes returned wrong data", length)
		}
	}
}

// TestReadAlloc_TailAllocatesOnlyRemainder is the point of defect 2: reading
// the tail of a small file at the full 1 MiB quantum macOS uses must not
// allocate a megabyte. Measured in bytes, because the allocation count alone
// would not catch a right-sized count of wrong-sized buffers.
func TestReadAlloc_TailAllocatesOnlyRemainder(t *testing.T) {
	const fileSize = 4096
	const quantum = 1 << 20
	rig := newReadallocRig(t, fileSize)
	body := buildReadBody(rig.open.FileID, 0, quantum)
	// Hoisted: discardRW is a zero-size type, so handing it to an io.ReadWriter
	// parameter costs nothing and the measurement sees only the handler.
	var w io.ReadWriter = discardRW{}

	// Warm up so first-call lazy allocations (session maps, etc.) do not land
	// in the measured window.
	for i := 0; i < 10; i++ {
		rig.d.handleRead(w, readHdr(), body, rig.sess)
	}

	const iters = 200
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < iters; i++ {
		rig.d.handleRead(w, readHdr(), body, rig.sess)
	}
	runtime.ReadMemStats(&after)

	perOp := (after.TotalAlloc - before.TotalAlloc) / iters
	// The whole response is NBSS(4) + header(64) + body(16) + 4096 bytes of
	// file. Anything near the 1 MiB quantum means the clamp is gone.
	const limit = 16 << 10
	if perOp > limit {
		t.Errorf("tail READ allocated %d B/op, want <= %d (quantum was %d, file is %d)",
			perOp, limit, quantum, fileSize)
	}
	t.Logf("tail READ: %d B/op (quantum %d, file %d)", perOp, quantum, fileSize)
}

// TestReadAlloc_SingleAllocation pins defect 1: the cleartext READ response is
// one allocation, not four.
func TestReadAlloc_SingleAllocation(t *testing.T) {
	rig := newReadallocRig(t, 512<<10)
	body := buildReadBody(rig.open.FileID, 0, 512<<10)
	var w io.ReadWriter = discardRW{}

	allocs := testing.AllocsPerRun(200, func() {
		rig.d.handleRead(w, readHdr(), body, rig.sess)
	})
	if allocs > 1 {
		t.Errorf("cleartext READ = %.0f allocs/op, want 1", allocs)
	}
	t.Logf("cleartext READ: %.0f allocs/op", allocs)
}

// --- Defect 3: WRITE is clamped to MaxWriteSize ---------------------------

// TestWriteAlloc_ExceedsMaxWriteSize proves a WRITE larger than the advertised
// MaxWriteSize is refused, and that one exactly at the limit still succeeds.
func TestWriteAlloc_ExceedsMaxWriteSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sink.bin")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	share := config.ShareConfig{Name: "share", Path: dir}
	const maxIO = 64 << 10
	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{share},
		Conn:   &Connection{MaxIOSize: maxIO},
	}
	sess := &Session{}
	tree := sess.AddTree(share)
	var fid [16]byte
	fid[0] = 0xB7
	open := &Open{FileID: fid, Path: path, File: f, Tree: tree, GrantedAccess: smb2.AccessGenericWrite}
	sess.AddOpen(open)

	// One byte over the advertised maximum: refused, file untouched.
	var buf bytes.Buffer
	d.handleWrite(&buf, smb2.Header{Command: smb2.CommandWrite},
		buildWriteBody(open.FileID, 0, make([]byte, maxIO+1)), sess)
	if st := respStatus(t, &buf); st != smb2.StatusInvalidParameter {
		t.Errorf("oversized WRITE status=0x%08X, want INVALID_PARAMETER", st)
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Size() != 0 {
		t.Errorf("refused WRITE still grew the file to %d bytes", fi.Size())
	}

	// Exactly at the maximum: accepted.
	buf.Reset()
	payload := bytes.Repeat([]byte{0x42}, maxIO)
	d.handleWrite(&buf, smb2.Header{Command: smb2.CommandWrite},
		buildWriteBody(open.FileID, 0, payload), sess)
	if st := respStatus(t, &buf); st != smb2.StatusSuccess {
		t.Fatalf("WRITE at exactly MaxWriteSize status=0x%08X, want SUCCESS", st)
	}
	respBody := frameBody(t, &buf)
	if len(respBody) != 16 {
		t.Errorf("WRITE response body = %d bytes, want 16", len(respBody))
	}
	if ss := binary.LittleEndian.Uint16(respBody[0:]); ss != 17 {
		t.Errorf("WRITE response StructureSize = %d, want 17", ss)
	}
	if n := binary.LittleEndian.Uint32(respBody[4:]); n != maxIO {
		t.Errorf("WRITE Count = %d, want %d", n, maxIO)
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Size() != maxIO {
		t.Errorf("file size = %d, want %d", fi.Size(), maxIO)
	}
}

// --- benchmarks -----------------------------------------------------------

func benchRead(b *testing.B, size int, cipher smb2.Cipher) {
	rig := newReadallocRig(b, size)
	if cipher != 0 {
		rig.encrypt(b, cipher)
	}
	body := buildReadBody(rig.open.FileID, 0, uint32(size))
	hdr := readHdr()
	// discardRW is zero-size, so the interface conversion is free and B/op
	// reflects the handler alone.
	var w io.ReadWriter = discardRW{}

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rig.d.handleRead(w, hdr, body, rig.sess)
	}
}

func BenchmarkRead4KiB(b *testing.B)           { benchRead(b, 4<<10, 0) }
func BenchmarkRead64KiB(b *testing.B)          { benchRead(b, 64<<10, 0) }
func BenchmarkRead512KiB(b *testing.B)         { benchRead(b, 512<<10, 0) }
func BenchmarkReadEncrypted4KiB(b *testing.B)  { benchRead(b, 4<<10, smb2.CipherAES128GCM) }
func BenchmarkReadEncrypted64KiB(b *testing.B) { benchRead(b, 64<<10, smb2.CipherAES128GCM) }
func BenchmarkReadEncrypted512KiB(b *testing.B) {
	benchRead(b, 512<<10, smb2.CipherAES128GCM)
}

// BenchmarkReadTail4KiBFileAt1MiBQuantum is defect 2 in benchmark form: the
// macOS pattern of asking for a full quantum on a file that holds far less.
func BenchmarkReadTail4KiBFileAt1MiBQuantum(b *testing.B) {
	rig := newReadallocRig(b, 4<<10)
	body := buildReadBody(rig.open.FileID, 0, 1<<20)
	hdr := readHdr()
	var w io.ReadWriter = discardRW{}

	b.SetBytes(4 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rig.d.handleRead(w, hdr, body, rig.sess)
	}
}
