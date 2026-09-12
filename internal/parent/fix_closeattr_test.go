package parent

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- CLOSE never echoed SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB -----------------
//
// macOS sets SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB on every CLOSE. The server
// already computed and shipped the times, sizes and attributes, but left the
// response Flags field at zero, so the client discarded the whole block unread
// and issued a fresh CREATE/QUERY_INFO/CLOSE to re-read what was already on the
// wire — one extra round trip per file closed.
//
// The echo is conditional on both the request asking for it and the response
// actually carrying attributes: Apple's parser drops the entire block (and
// logs "Bad SMB 2/3 Server") if any of the four timestamps is zero.

// buildCloseBodyFlags constructs a CLOSE request body (StructureSize 24) with
// the given Flags field, which plain buildCloseBody always leaves at zero.
func buildCloseBodyFlags(fileID [16]byte, flags uint16) []byte {
	body := buildCloseBody(fileID)
	binary.LittleEndian.PutUint16(body[2:], flags)
	return body
}

// closeResponse is the decoded CLOSE response body.
type closeResponse struct {
	Flags          uint16
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndOfFile      uint64
	FileAttributes uint32
}

// decodeCloseResp parses the single CLOSE response held in buf, after checking
// it reported SUCCESS.
func decodeCloseResp(t *testing.T, buf *bytes.Buffer) closeResponse {
	t.Helper()
	if got := frameStatus(t, buf); got != smb2.StatusSuccess {
		t.Fatalf("CLOSE status = %#x, want SUCCESS", uint32(got))
	}
	body := frameBody(t, buf)
	if len(body) < 60 {
		t.Fatalf("CLOSE response body = %d bytes, want 60", len(body))
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 60 {
		t.Fatalf("CLOSE StructureSize = %d, want 60", ss)
	}
	return closeResponse{
		Flags:          binary.LittleEndian.Uint16(body[2:]),
		CreationTime:   binary.LittleEndian.Uint64(body[8:]),
		LastAccessTime: binary.LittleEndian.Uint64(body[16:]),
		LastWriteTime:  binary.LittleEndian.Uint64(body[24:]),
		ChangeTime:     binary.LittleEndian.Uint64(body[32:]),
		AllocationSize: binary.LittleEndian.Uint64(body[40:]),
		EndOfFile:      binary.LittleEndian.Uint64(body[48:]),
		FileAttributes: binary.LittleEndian.Uint32(body[56:]),
	}
}

// closeOpenWithFlags registers open, closes it with the given request Flags and
// returns the decoded response.
func closeOpenWithFlags(t *testing.T, d *Dispatcher, sess *Session, open *Open, flags uint16) closeResponse {
	t.Helper()
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)
	var buf bytes.Buffer
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBodyFlags(open.FileID, flags), sess)
	return decodeCloseResp(t, &buf)
}

// assertNoZeroTimes is the invariant Apple's parser enforces: an echoed flag
// must never travel with a zero timestamp, or the client throws the whole
// attribute block away.
func assertNoZeroTimes(t *testing.T, r closeResponse) {
	t.Helper()
	if r.Flags&smb2.CloseFlagPostQueryAttrib == 0 {
		return
	}
	if r.CreationTime == 0 || r.LastAccessTime == 0 || r.LastWriteTime == 0 || r.ChangeTime == 0 {
		t.Fatalf("POSTQUERY_ATTRIB echoed with a zero timestamp: %+v", r)
	}
}

// TestClose_PostQueryAttribEchoedWhenRequested proves a file CLOSE that asks
// for post-close attributes gets the flag back along with real attributes.
func TestClose_PostQueryAttribEchoedWhenRequested(t *testing.T) {
	shareDir := t.TempDir()
	path := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	r := closeOpenWithFlags(t, d, sess, &Open{Path: path, Tree: tree}, smb2.CloseFlagPostQueryAttrib)

	if r.Flags&smb2.CloseFlagPostQueryAttrib == 0 {
		t.Fatalf("CLOSE Flags = %#x, want SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB", r.Flags)
	}
	assertNoZeroTimes(t, r)
	if r.EndOfFile != 5 {
		t.Fatalf("EndOfFile = %d, want 5", r.EndOfFile)
	}
	if r.FileAttributes != smb2.FileAttrNormal {
		t.Fatalf("FileAttributes = %#x, want FILE_ATTRIBUTE_NORMAL", r.FileAttributes)
	}
}

// TestClose_PostQueryAttribEchoedForDirectory proves the echo covers directory
// handles too — macOS closes those with the same flag set.
func TestClose_PostQueryAttribEchoedForDirectory(t *testing.T) {
	shareDir := t.TempDir()
	sub := filepath.Join(shareDir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	r := closeOpenWithFlags(t, d, sess, &Open{Path: sub, IsDir: true, Tree: tree}, smb2.CloseFlagPostQueryAttrib)

	if r.Flags&smb2.CloseFlagPostQueryAttrib == 0 {
		t.Fatalf("directory CLOSE Flags = %#x, want POSTQUERY_ATTRIB", r.Flags)
	}
	assertNoZeroTimes(t, r)
	if r.FileAttributes != smb2.FileAttrDirectory {
		t.Fatalf("FileAttributes = %#x, want FILE_ATTRIBUTE_DIRECTORY", r.FileAttributes)
	}
}

// TestClose_PostQueryAttribNotEchoedWhenNotRequested proves the flag is only
// ever echoed back, never volunteered: a client that did not ask must not see
// it. The attributes themselves are still filled in, as before.
func TestClose_PostQueryAttribNotEchoedWhenNotRequested(t *testing.T) {
	shareDir := t.TempDir()
	path := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	r := closeOpenWithFlags(t, d, sess, &Open{Path: path, Tree: tree}, 0)

	if r.Flags != 0 {
		t.Fatalf("CLOSE Flags = %#x, want 0 (client did not ask)", r.Flags)
	}
	if r.EndOfFile != 5 {
		t.Fatalf("EndOfFile = %d, want 5 (attributes still reported)", r.EndOfFile)
	}
}

// TestClose_PostQueryAttribNotEchoedWhenStatFails is the no-lying case: the
// path is gone, so the response carries zeros. Setting the flag over zeros
// makes macOS discard the block *and* log the server as broken, which is worse
// than staying silent.
func TestClose_PostQueryAttribNotEchoedWhenStatFails(t *testing.T) {
	shareDir := t.TempDir()
	missing := filepath.Join(shareDir, "vanished.txt")
	d, sess, tree := newTestDispatcher(t, shareDir)

	r := closeOpenWithFlags(t, d, sess, &Open{Path: missing, Tree: tree}, smb2.CloseFlagPostQueryAttrib)

	if r.Flags&smb2.CloseFlagPostQueryAttrib != 0 {
		t.Fatalf("POSTQUERY_ATTRIB echoed for a path we cannot stat: %+v", r)
	}
	assertNoZeroTimes(t, r)
	if r.CreationTime != 0 || r.LastWriteTime != 0 || r.EndOfFile != 0 {
		t.Fatalf("expected a zeroed attribute block, got %+v", r)
	}
}

// TestClose_PostQueryAttribNotEchoedAfterDeleteOnClose covers the same
// no-lying rule on the path that actually hits it in production: the file is
// unlinked by DELETE_ON_CLOSE, so the stat that follows cannot succeed.
func TestClose_PostQueryAttribNotEchoedAfterDeleteOnClose(t *testing.T) {
	shareDir := t.TempDir()
	victim := filepath.Join(shareDir, "gone.txt")
	if err := os.WriteFile(victim, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	r := closeOpenWithFlags(t, d, sess, &Open{Path: victim, Tree: tree, DeleteOnClose: true}, smb2.CloseFlagPostQueryAttrib)

	if r.Flags&smb2.CloseFlagPostQueryAttrib != 0 {
		t.Fatalf("POSTQUERY_ATTRIB echoed for a deleted file: %+v", r)
	}
	assertNoZeroTimes(t, r)
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatalf("file survived delete-on-close: %v", err)
	}
}

// TestClose_PostQueryAttribEchoedForStream proves the alternate-data-stream
// path echoes too: it reports the exact buffer length and freshly synthesized
// (non-zero) times, so the block is usable.
func TestClose_PostQueryAttribEchoedForStream(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	// streamSynthetic without streamWritten: a buffer we fabricated and the
	// client only read, so CLOSE does not touch the filesystem and the test
	// does not depend on xattr support.
	open := &Open{
		Path:            base,
		Tree:            tree,
		IsStream:        true,
		StreamName:      "com.apple.metadata",
		streamBuf:       []byte("0123456789"),
		streamSynthetic: true,
	}
	r := closeOpenWithFlags(t, d, sess, open, smb2.CloseFlagPostQueryAttrib)

	if r.Flags&smb2.CloseFlagPostQueryAttrib == 0 {
		t.Fatalf("stream CLOSE Flags = %#x, want POSTQUERY_ATTRIB", r.Flags)
	}
	assertNoZeroTimes(t, r)
	if r.EndOfFile != 10 || r.AllocationSize != 10 {
		t.Fatalf("stream sizes = eof %d alloc %d, want 10/10", r.EndOfFile, r.AllocationSize)
	}
}

// TestClose_PostQueryAttribNotEchoedForPipe proves a named pipe never claims
// attributes: it has no times to report, so echoing the flag would ship a block
// of zeros the client would reject anyway.
func TestClose_PostQueryAttribNotEchoedForPipe(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)

	open := &Open{IsPipe: true, PipeName: "srvsvc", Tree: tree}
	r := closeOpenWithFlags(t, d, sess, open, smb2.CloseFlagPostQueryAttrib)

	if r.Flags != 0 {
		t.Fatalf("pipe CLOSE Flags = %#x, want 0", r.Flags)
	}
	assertNoZeroTimes(t, r)
}
