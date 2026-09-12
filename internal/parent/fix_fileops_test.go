package parent

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- shared helpers -------------------------------------------------------

// frameStatus decodes the NTSTATUS from the single NBSS-framed SMB2 response
// held in buf.
func frameStatus(t *testing.T, buf *bytes.Buffer) smb2.Status {
	t.Helper()
	frame := buf.Bytes()
	if len(frame) < 4+smb2.HeaderSize {
		t.Fatalf("response too short: %d bytes", len(frame))
	}
	hdr, err := smb2.DecodeHeader(frame[4 : 4+smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode response header: %v", err)
	}
	return smb2.Status(hdr.Status)
}

// frameBody returns the SMB2 body (past the NBSS prefix and the header) of the
// single response held in buf.
func frameBody(t *testing.T, buf *bytes.Buffer) []byte {
	t.Helper()
	frame := buf.Bytes()
	if len(frame) < 4+smb2.HeaderSize {
		t.Fatalf("response too short: %d bytes", len(frame))
	}
	return frame[4+smb2.HeaderSize:]
}

// buildQueryDirBody constructs a QUERY_DIRECTORY request body (StructureSize
// 33) with the given search pattern.
func buildQueryDirBody(fileID [16]byte, infoClass, flags uint8, outBufLen uint32, pattern string) []byte {
	const headerSize = 64
	nameU16 := utf16leName(pattern)
	body := make([]byte, 32)
	binary.LittleEndian.PutUint16(body[0:], 33)
	body[2] = infoClass
	body[3] = flags
	copy(body[8:24], fileID[:])
	if len(nameU16) > 0 {
		binary.LittleEndian.PutUint16(body[24:], uint16(headerSize+32))
		binary.LittleEndian.PutUint16(body[26:], uint16(len(nameU16)))
	}
	binary.LittleEndian.PutUint32(body[28:], outBufLen)
	return append(body, nameU16...)
}

// queryDirBuffer extracts the record buffer from a QUERY_DIRECTORY response.
func queryDirBuffer(t *testing.T, buf *bytes.Buffer) []byte {
	t.Helper()
	body := frameBody(t, buf)
	if len(body) < 8 {
		t.Fatalf("QUERY_DIRECTORY response body too short: %d", len(body))
	}
	n := binary.LittleEndian.Uint32(body[4:])
	if int(n) > len(body)-8 {
		t.Fatalf("QUERY_DIRECTORY OutputBufferLength %d exceeds body %d", n, len(body)-8)
	}
	return body[8 : 8+n]
}

// decodeDirRecordNames walks a directory-entry chain whose records have the
// given fixed-part size and carry FileNameLength at nameLenOff, returning the
// names in order.
func decodeDirRecordNames(t *testing.T, buf []byte, fixed, nameLenOff int) []string {
	t.Helper()
	var out []string
	off := 0
	for off+fixed <= len(buf) {
		next := binary.LittleEndian.Uint32(buf[off:])
		nameLen := int(binary.LittleEndian.Uint32(buf[off+nameLenOff:]))
		if off+fixed+nameLen > len(buf) {
			t.Fatalf("record at %d overruns buffer (len %d)", off, len(buf))
		}
		out = append(out, decodeUTF16LE(buf[off+fixed:off+fixed+nameLen]))
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out
}

// decodeNamesInfo walks a FILE_NAMES_INFORMATION chain (MS-FSCC §2.4.26).
func decodeNamesInfo(t *testing.T, buf []byte) []string {
	t.Helper()
	return decodeDirRecordNames(t, buf, 12, 8)
}

// erroringDirEntry stands in for a file that was unlinked between os.ReadDir
// and the encode: it is present in the scan but its Info() fails. It is a
// separate type from syntheticDirEntry so the cursor test exercises the
// skip-during-encode path without also depending on the nil-FileInfo fix.
type erroringDirEntry struct{ name string }

func (e erroringDirEntry) Name() string               { return e.name }
func (e erroringDirEntry) IsDir() bool                { return false }
func (e erroringDirEntry) Type() os.FileMode          { return 0 }
func (e erroringDirEntry) Info() (os.FileInfo, error) { return nil, os.ErrNotExist }

// newDirOpen registers a directory handle on dir and returns it.
func newDirOpen(t *testing.T, sess *Session, tree *Tree, dir string) *Open {
	t.Helper()
	open := &Open{Path: dir, IsDir: true, Tree: tree, GrantedAccess: 0x001F01FF}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)
	return open
}

// --- finding 1: nil os.FileInfo on the synthetic "." / ".." entries --------

// TestFileOps_SyntheticDirEntryNilInfo proves a syntheticDirEntry built from a
// failed os.Lstat never hands a nil os.FileInfo to the encoder. The old
// Info() returned (nil, nil), so encodeDirRecord called ModTime() on a nil
// interface and panicked the entire server process — there is no recover() in
// the serve path, so one unlucky stat killed every connection.
func TestFileOps_SyntheticDirEntryNilInfo(t *testing.T) {
	ent := syntheticDirEntry{name: ".", info: nil}
	info, err := ent.Info()
	if err == nil {
		t.Fatal("syntheticDirEntry.Info() with a nil FileInfo must report an error")
	}
	if info != nil {
		t.Fatalf("syntheticDirEntry.Info() returned a non-nil FileInfo alongside an error: %v", info)
	}
}

// TestFileOps_QueryDirSurvivesUnstattableEntry drives the full encode path
// with a nil-info entry in the middle of the listing. Before the fix this
// panicked inside encodeDirRecord.
func TestFileOps_QueryDirSurvivesUnstattableEntry(t *testing.T) {
	shareDir := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(shareDir, n), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 1 << 20}
	open := newDirOpen(t, sess, tree, shareDir)

	entries, err := os.ReadDir(shareDir)
	if err != nil {
		t.Fatal(err)
	}
	// Splice an entry whose Info() fails between the two real files.
	open.dirEntries = []os.DirEntry{
		entries[0],
		syntheticDirEntry{name: "ghost", info: nil},
		entries[1],
	}

	// Every record class must survive it. The classes that read info.ModTime()
	// / info.IsDir() are the ones that used to panic.
	//
	// FILE_NAMES_INFORMATION is the exception: it encodes nothing but the name
	// (MS-FSCC §2.4.26), so the enumerator no longer stats its entries at all —
	// one lstat per entry for fields it never reads. It therefore emits the
	// name readdir handed it, "ghost" included, which is ordinary POSIX
	// readdir behaviour: a name can be unlinked between readdir and the stat.
	// The point of this test is that nothing panics, not that the name is
	// filtered, and the stat-bearing classes below still filter it.
	want := []string{"a.txt", "b.txt"}
	classes := []struct {
		class             uint8
		fixed, nameLenOff int
		want              []string
	}{
		{smb2.InfoFileNamesInformation, 12, 8, []string{"a.txt", "ghost", "b.txt"}},
		{smb2.InfoFileDirectoryInformation, 64, 60, want},
		{smb2.InfoFileBothDirectoryInformation, 94, 60, want},
		{smb2.InfoFileIdBothDirectoryInformation, 104, 60, want},
		{smb2.InfoFileIdFullDirectoryInformation, 80, 60, want},
	}
	for _, c := range classes {
		open.dirSent = 0
		var buf bytes.Buffer
		d.handleQueryDirectory(&buf, smb2.Header{Command: smb2.CommandQueryDirectory},
			buildQueryDirBody(open.FileID, c.class, 0, 64<<10, "*"), sess)
		if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
			t.Fatalf("class %#x: QUERY_DIRECTORY status = %#x, want SUCCESS", c.class, uint32(got))
		}
		names := decodeDirRecordNames(t, queryDirBuffer(t, &buf), c.fixed, c.nameLenOff)
		if len(names) != len(c.want) {
			t.Fatalf("class %#x: names = %v, want %v", c.class, names, c.want)
		}
		for i := range c.want {
			if names[i] != c.want[i] {
				t.Fatalf("class %#x: names = %v, want %v", c.class, names, c.want)
			}
		}
	}
}

// --- finding 2: OutputBufferLength is not bounded by MaxTransactSize ------

// TestFileOps_QueryDirOutputBufferLengthClamped proves an OutputBufferLength
// larger than the negotiated MaxTransactSize is refused instead of being used
// verbatim as an allocation size (MS-SMB2 §3.3.5.18).
func TestFileOps_QueryDirOutputBufferLengthClamped(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "a.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 1 << 20}
	open := newDirOpen(t, sess, tree, shareDir)

	var buf bytes.Buffer
	d.handleQueryDirectory(&buf, smb2.Header{Command: smb2.CommandQueryDirectory},
		buildQueryDirBody(open.FileID, smb2.InfoFileNamesInformation, 0, 0xFFFFFFFF, "*"), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusInvalidParameter {
		t.Fatalf("4 GiB OutputBufferLength status = %#x, want INVALID_PARAMETER", uint32(got))
	}

	// A request within the negotiated maximum still works.
	buf.Reset()
	d.handleQueryDirectory(&buf, smb2.Header{Command: smb2.CommandQueryDirectory},
		buildQueryDirBody(open.FileID, smb2.InfoFileNamesInformation, 0, 1<<20, "*"), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("in-range OutputBufferLength status = %#x, want SUCCESS", uint32(got))
	}
}

// --- finding 3: enumeration cursor drifts past skipped entries ------------

// TestFileOps_QueryDirCursorTracksConsumedEntries proves the enumeration
// cursor advances by the entries consumed, not by the records encoded. When an
// entry is dropped during encoding the old code left open.dirSent pointing at
// an entry it had already walked past, so the next QUERY_DIRECTORY re-emitted
// files the client had already received — very visible to rclone, which
// re-lists constantly.
func TestFileOps_QueryDirCursorTracksConsumedEntries(t *testing.T) {
	shareDir := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(shareDir, n), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 1 << 20}
	open := newDirOpen(t, sess, tree, shareDir)

	entries, err := os.ReadDir(shareDir)
	if err != nil {
		t.Fatal(err)
	}
	// "ghost" cannot be encoded; the two entries after it must still be
	// delivered exactly once each.
	open.dirEntries = []os.DirEntry{
		entries[0],
		erroringDirEntry{name: "ghost"},
		entries[1],
		entries[2],
	}

	var got []string
	for i := 0; i < 8; i++ {
		var buf bytes.Buffer
		d.handleQueryDirectory(&buf, smb2.Header{Command: smb2.CommandQueryDirectory},
			buildQueryDirBody(open.FileID, smb2.InfoFileDirectoryInformation,
				smb2.QueryDirReturnSingleEntry, 64<<10, "*"), sess)
		st := frameStatus(t, &buf)
		if st == smb2.StatusNoMoreFiles {
			break
		}
		if st != smb2.StatusSuccess {
			t.Fatalf("iteration %d status = %#x, want SUCCESS or NO_MORE_FILES", i, uint32(st))
		}
		// FILE_DIRECTORY_INFORMATION rather than FILE_NAMES_INFORMATION: the
		// names class no longer stats its entries, so it never drops one and
		// could not exercise the consumed-vs-encoded divergence this test is
		// about. Both classes share the same NextEntryOffset chain.
		got = append(got, decodeDirRecordNames(t, queryDirBuffer(t, &buf), 64, 60)...)
	}

	want := []string{"a.txt", "b.txt", "c.txt"}
	if len(got) != len(want) {
		t.Fatalf("single-entry enumeration returned %v, want %v (duplicates mean the cursor drifted)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("single-entry enumeration returned %v, want %v", got, want)
		}
	}
}

// TestFileOps_QueryDirBufferTooSmallForOneEntry proves that a buffer which
// cannot hold even one record is reported as STATUS_INFO_LENGTH_MISMATCH
// (MS-SMB2 §3.3.5.18) rather than STATUS_NO_MORE_FILES, which would silently
// truncate the listing and lose every remaining file.
func TestFileOps_QueryDirBufferTooSmallForOneEntry(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "a.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 1 << 20}
	open := newDirOpen(t, sess, tree, shareDir)

	var buf bytes.Buffer
	d.handleQueryDirectory(&buf, smb2.Header{Command: smb2.CommandQueryDirectory},
		buildQueryDirBody(open.FileID, smb2.InfoFileNamesInformation, 0, 8, "*"), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusInfoLengthMismatch {
		t.Fatalf("tiny OutputBufferLength status = %#x, want INFO_LENGTH_MISMATCH", uint32(got))
	}
	if open.dirSent != 0 {
		t.Fatalf("dirSent advanced to %d on a request that returned nothing", open.dirSent)
	}
}

// --- finding 4: unsupported info classes were silently mis-encoded --------

// TestFileOps_QueryDirRejectsUnknownInfoClass proves an information class we
// have no encoder for is refused rather than answered with a differently
// shaped record the client would parse as garbage.
func TestFileOps_QueryDirRejectsUnknownInfoClass(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "a.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 1 << 20}
	open := newDirOpen(t, sess, tree, shareDir)

	for _, class := range []uint8{0x00, 0x05, 0x25 + 2, 0x99} {
		if supportedDirInfoClass(class) {
			continue
		}
		var buf bytes.Buffer
		d.handleQueryDirectory(&buf, smb2.Header{Command: smb2.CommandQueryDirectory},
			buildQueryDirBody(open.FileID, class, 0, 64<<10, "*"), sess)
		if got := frameStatus(t, &buf); got != smb2.StatusInvalidInfoClass {
			t.Errorf("class %#x status = %#x, want INVALID_INFO_CLASS", class, uint32(got))
		}
	}
}

// TestFileOps_QueryDirIdFullDirectoryInformation proves class 0x26 is encoded
// as MS-FSCC §2.4.20 FILE_ID_FULL_DIR_INFORMATION (80 fixed bytes, FileId at
// offset 72) instead of being answered with a 94-byte FILE_BOTH_DIR record.
func TestFileOps_QueryDirIdFullDirectoryInformation(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "x.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 1 << 20}
	open := newDirOpen(t, sess, tree, shareDir)

	var buf bytes.Buffer
	d.handleQueryDirectory(&buf, smb2.Header{Command: smb2.CommandQueryDirectory},
		buildQueryDirBody(open.FileID, smb2.InfoFileIdFullDirectoryInformation, 0, 64<<10, "x.txt"), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("status = %#x, want SUCCESS", uint32(got))
	}
	rec := queryDirBuffer(t, &buf)
	const fixed = 80
	if len(rec) < fixed {
		t.Fatalf("record is %d bytes, shorter than the 80-byte fixed part", len(rec))
	}
	if next := binary.LittleEndian.Uint32(rec[0:]); next != 0 {
		t.Fatalf("NextEntryOffset = %d on the only record, want 0", next)
	}
	nameLen := int(binary.LittleEndian.Uint32(rec[60:]))
	if want := len(utf16leName("x.txt")); nameLen != want {
		t.Fatalf("FileNameLength = %d, want %d", nameLen, want)
	}
	if fixed+nameLen > len(rec) {
		t.Fatalf("name overruns the record: fixed+%d > %d", nameLen, len(rec))
	}
	if name := decodeUTF16LE(rec[fixed : fixed+nameLen]); name != "x.txt" {
		t.Fatalf("FileName at offset 80 = %q, want %q", name, "x.txt")
	}
	if eof := binary.LittleEndian.Uint64(rec[40:]); eof != 5 {
		t.Fatalf("EndOfFile = %d, want 5", eof)
	}
	if attrs := binary.LittleEndian.Uint32(rec[56:]); attrs != smb2.FileAttrNormal {
		t.Fatalf("FileAttributes = %#x, want FILE_ATTRIBUTE_NORMAL", attrs)
	}
}

// --- finding 5: delete-on-close failures were swallowed -------------------

// TestFileOps_DeleteOnCloseFailureIsReported proves a failed unlink at CLOSE
// surfaces as a real status. Reporting SUCCESS made the client (rclone) record
// a delete that never happened.
func TestFileOps_DeleteOnCloseFailureIsReported(t *testing.T) {
	shareDir := t.TempDir()
	sub := filepath.Join(shareDir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "child.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	open := &Open{Path: sub, IsDir: true, Tree: tree, DeleteOnClose: true}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	var buf bytes.Buffer
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusDirectoryNotEmpty {
		t.Fatalf("CLOSE status = %#x, want DIRECTORY_NOT_EMPTY", uint32(got))
	}
	if _, err := os.Stat(sub); err != nil {
		t.Fatalf("non-empty directory was removed anyway: %v", err)
	}
}

// TestFileOps_DeleteOnCloseShareRootStatus proves the share-root refusal is
// visible to the client instead of being logged and answered with SUCCESS.
func TestFileOps_DeleteOnCloseShareRootStatus(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)

	open := &Open{Path: shareDir, IsDir: true, Tree: tree, DeleteOnClose: true}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	var buf bytes.Buffer
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusAccessDenied {
		t.Fatalf("share-root delete-on-close status = %#x, want ACCESS_DENIED", uint32(got))
	}
	if _, err := os.Stat(shareDir); err != nil {
		t.Fatalf("share root was deleted: %v", err)
	}
}

// TestFileOps_DeleteOnCloseSucceeds keeps the happy path honest: a normal
// delete-on-close still answers SUCCESS and removes the file.
func TestFileOps_DeleteOnCloseSucceeds(t *testing.T) {
	shareDir := t.TempDir()
	victim := filepath.Join(shareDir, "gone.txt")
	if err := os.WriteFile(victim, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	open := &Open{Path: victim, Tree: tree, DeleteOnClose: true}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	var buf bytes.Buffer
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("CLOSE status = %#x, want SUCCESS", uint32(got))
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatalf("file survived delete-on-close: %v", err)
	}
}

// --- finding 6: statusFromErr collapsed every errno to INTERNAL_ERROR -----

// TestFileOps_StatusFromErrno proves the errno→NTSTATUS mapping. A full disk
// reported as STATUS_INTERNAL_ERROR makes clients retry forever instead of
// telling the user what happened.
func TestFileOps_StatusFromErrno(t *testing.T) {
	cases := []struct {
		errno syscall.Errno
		want  smb2.Status
	}{
		{syscall.ENOSPC, smb2.StatusDiskFull},
		{syscall.EDQUOT, smb2.StatusDiskFull},
		{syscall.EFBIG, smb2.StatusDiskFull},
		{syscall.ENOTEMPTY, smb2.StatusDirectoryNotEmpty},
		{syscall.EISDIR, smb2.StatusFileIsADirectory},
		{syscall.ENOTDIR, smb2.StatusNotADirectory},
		{syscall.EMFILE, smb2.StatusTooManyOpenedFiles},
		{syscall.ENFILE, smb2.StatusTooManyOpenedFiles},
		{syscall.EROFS, smb2.StatusAccessDenied},
		{syscall.ENAMETOOLONG, smb2.StatusObjectNameInvalid},
		{syscall.EXDEV, smb2.StatusNotSameDevice},
		{syscall.ELOOP, smb2.StatusObjectPathNotFound},
		{syscall.EIO, smb2.StatusIODeviceError},
		{syscall.ENOMEM, smb2.StatusInsufficientResources},
		{syscall.ENOENT, smb2.StatusObjectNameNotFound},
		{syscall.EACCES, smb2.StatusAccessDenied},
		{syscall.EEXIST, smb2.StatusObjectNameCollision},
	}
	for _, c := range cases {
		// Wrapped exactly the way the os package returns it.
		err := &os.PathError{Op: "write", Path: "/share/file", Err: c.errno}
		if got := statusFromErr(err); got != c.want {
			t.Errorf("statusFromErr(%v) = %#x, want %#x", c.errno, uint32(got), uint32(c.want))
		}
	}
	// An error carrying no errno still falls back to INTERNAL_ERROR.
	if got := statusFromErr(errNoErrno{}); got != smb2.StatusInternalError {
		t.Errorf("statusFromErr(opaque) = %#x, want INTERNAL_ERROR", uint32(got))
	}
}

type errNoErrno struct{}

func (errNoErrno) Error() string { return "something went wrong" }

// --- finding 7: SET_INFO FileBasicInformation swallowed Chtimes errors ----

// TestFileOps_SetInfoBasicReportsChtimesFailure proves a failed timestamp
// write is reported. rclone compares modification times to decide whether a
// file still needs uploading, so a SUCCESS for a time we never set makes it
// treat a stale copy as up to date indefinitely.
func TestFileOps_SetInfoBasicReportsChtimesFailure(t *testing.T) {
	shareDir := t.TempDir()
	p := filepath.Join(shareDir, "f.txt")
	if err := os.WriteFile(p, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	d, sess, tree := newTestDispatcher(t, shareDir)
	open := &Open{Path: p, File: f, Tree: tree, GrantedAccess: 0x001F01FF}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	// The path disappears under the handle; setting times can no longer work.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	d.handleSetInfo(&buf, smb2.Header{Command: smb2.CommandSetInfo},
		buildSetInfoBody(smb2.InfoTypeFile, smb2.FileBasicInformationSet, open.FileID,
			basicInfoBuffer(time.Now(), time.Now())), sess)
	if got := frameStatus(t, &buf); got == smb2.StatusSuccess {
		t.Fatal("SET_INFO FileBasicInformation reported SUCCESS for a timestamp it could not set")
	} else if got != smb2.StatusObjectNameNotFound {
		t.Fatalf("status = %#x, want OBJECT_NAME_NOT_FOUND", uint32(got))
	}
}

// TestFileOps_SetInfoBasicAppliesTimes keeps the happy path honest and proves
// the nanosecond resolution of the client's FILETIME survives.
func TestFileOps_SetInfoBasicAppliesTimes(t *testing.T) {
	shareDir := t.TempDir()
	p := filepath.Join(shareDir, "f.txt")
	if err := os.WriteFile(p, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	d, sess, tree := newTestDispatcher(t, shareDir)
	open := &Open{Path: p, File: f, Tree: tree, GrantedAccess: 0x001F01FF}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	// A time whose sub-microsecond part is non-zero: futimes(2) would round it
	// away and the client would read back a different mtime than it set.
	want := time.Date(2021, 3, 4, 5, 6, 7, 123456700, time.UTC)
	var buf bytes.Buffer
	d.handleSetInfo(&buf, smb2.Header{Command: smb2.CommandSetInfo},
		buildSetInfoBody(smb2.InfoTypeFile, smb2.FileBasicInformationSet, open.FileID,
			basicInfoBuffer(want, want)), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("status = %#x, want SUCCESS", uint32(got))
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().UTC().Equal(want) {
		t.Fatalf("mtime = %v, want %v", st.ModTime().UTC(), want)
	}
}

// basicInfoBuffer builds a FILE_BASIC_INFORMATION buffer (MS-FSCC §2.4.7).
func basicInfoBuffer(atime, mtime time.Time) []byte {
	b := make([]byte, 40)
	binary.LittleEndian.PutUint64(b[8:], filetimeFromTime(atime))
	binary.LittleEndian.PutUint64(b[16:], filetimeFromTime(mtime))
	return b
}

// --- finding 8: named-stream defects -------------------------------------

// TestFileOps_StreamCreateDisposition proves CreateDisposition is honoured on
// a named stream: FILE_OPEN of a stream that was never written must fail
// rather than silently materialise an empty one, and FILE_CREATE of an
// existing stream must collide.
func TestFileOps_StreamCreateDisposition(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, base) {
		t.Skip("filesystem does not support user xattrs")
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	hdr := smb2.Header{Command: smb2.CommandCreate}

	// FILE_OPEN of a stream that does not exist → OBJECT_NAME_NOT_FOUND.
	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, hdr, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpen}, "doc.txt", "nope")
	if got := frameStatus(t, &buf); got != smb2.StatusObjectNameNotFound {
		t.Fatalf("FILE_OPEN of missing stream = %#x, want OBJECT_NAME_NOT_FOUND", uint32(got))
	}

	// FILE_OPEN_IF creates it.
	buf.Reset()
	d.handleCreateNamedStream(&buf, hdr, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}, "doc.txt", "nope")
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("FILE_OPEN_IF of missing stream = %#x, want SUCCESS", uint32(got))
	}
	created := sess.GetOpen(d.LastCreatedFileID)
	if created == nil || !created.IsStream {
		t.Fatal("FILE_OPEN_IF did not register a stream handle")
	}
	buf.Reset()
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(created.FileID), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("CLOSE after FILE_OPEN_IF = %#x, want SUCCESS", uint32(got))
	}

	// Now that it exists, FILE_CREATE must collide and FILE_OPEN must succeed.
	buf.Reset()
	d.handleCreateNamedStream(&buf, hdr, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionCreate}, "doc.txt", "nope")
	if got := frameStatus(t, &buf); got != smb2.StatusObjectNameCollision {
		t.Fatalf("FILE_CREATE of existing stream = %#x, want OBJECT_NAME_COLLISION", uint32(got))
	}
	buf.Reset()
	d.handleCreateNamedStream(&buf, hdr, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpen}, "doc.txt", "nope")
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("FILE_OPEN of existing stream = %#x, want SUCCESS", uint32(got))
	}
}

// TestFileOps_StreamAFPInfoAlwaysOpenable pins the Finder-copy behaviour the
// disposition check must not regress: AFP_AfpInfo is synthesized, so a plain
// FILE_OPEN of it succeeds even when nothing is stored yet.
func TestFileOps_StreamAFPInfoAlwaysOpenable(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, smb2.Header{Command: smb2.CommandCreate}, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpen}, "doc.txt", "AFP_AfpInfo")
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("FILE_OPEN of AFP_AfpInfo = %#x, want SUCCESS", uint32(got))
	}
}

// TestFileOps_StreamEndOfFileCapped proves SET_INFO FileEndOfFileInformation
// on a stream honours the same 64 MiB cap the stream WRITE path applies. The
// size is client-chosen and drives a make() on an in-memory buffer, so an
// unbounded value is an allocation bomb.
func TestFileOps_StreamEndOfFileCapped(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	open := &Open{Path: base, Tree: tree, IsStream: true, StreamName: "s", GrantedAccess: 0x001F01FF}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	for _, size := range []uint64{maxStreamSize + 1, 1 << 40, 1 << 62} {
		eof := make([]byte, 8)
		binary.LittleEndian.PutUint64(eof, size)
		var buf bytes.Buffer
		d.handleSetInfo(&buf, smb2.Header{Command: smb2.CommandSetInfo},
			buildSetInfoBody(smb2.InfoTypeFile, smb2.FileEndOfFileInformation, open.FileID, eof), sess)
		if got := frameStatus(t, &buf); got != smb2.StatusDiskFull {
			t.Fatalf("stream EOF %d status = %#x, want DISK_FULL", size, uint32(got))
		}
		if len(open.streamBuf) != 0 {
			t.Fatalf("stream buffer grew to %d bytes for a rejected EOF of %d", len(open.streamBuf), size)
		}
	}

	// A size inside the cap still works.
	eof := make([]byte, 8)
	binary.LittleEndian.PutUint64(eof, 1024)
	var buf bytes.Buffer
	d.handleSetInfo(&buf, smb2.Header{Command: smb2.CommandSetInfo},
		buildSetInfoBody(smb2.InfoTypeFile, smb2.FileEndOfFileInformation, open.FileID, eof), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("in-cap stream EOF status = %#x, want SUCCESS", uint32(got))
	}
	if len(open.streamBuf) != 1024 {
		t.Fatalf("stream buffer = %d bytes, want 1024", len(open.streamBuf))
	}
}

// TestFileOps_StreamFlushFailureIsReported proves a failed setxattr at CLOSE
// is surfaced. It is the only point at which stream bytes reach disk, so
// swallowing the error loses everything the client wrote while CLOSE still
// claims SUCCESS.
func TestFileOps_StreamFlushFailureIsReported(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, base) {
		t.Skip("filesystem does not support user xattrs")
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, smb2.Header{Command: smb2.CommandCreate}, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}, "doc.txt", "s")
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("stream CREATE = %#x, want SUCCESS", uint32(got))
	}
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil {
		t.Fatal("stream open not registered")
	}
	buf.Reset()
	d.handleWrite(&buf, smb2.Header{Command: smb2.CommandWrite},
		buildWriteBody(open.FileID, 0, []byte("payload")), sess)

	// The base file vanishes before CLOSE, so the flush cannot land.
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &buf); got == smb2.StatusSuccess {
		t.Fatal("CLOSE reported SUCCESS after the stream flush failed; the client's data was lost silently")
	} else if got != smb2.StatusObjectNameNotFound {
		t.Fatalf("CLOSE status = %#x, want OBJECT_NAME_NOT_FOUND", uint32(got))
	}
}

// TestFileOps_StreamCreateResolvesNormalizedBase proves a stream on a base
// file stored with an NFD-encoded name (the norm on macOS) is found when the
// client addresses it in NFC. Plain ResolveSecure missed it entirely.
//
// It only discriminates on a byte-transparent filesystem (Linux): APFS and
// HFS+ compare names normalization-insensitively, so the plain lstat already
// finds the file there and the assertion is trivially satisfied.
func TestFileOps_StreamCreateResolvesNormalizedBase(t *testing.T) {
	shareDir := t.TempDir()
	nfd := norm.NFD.String("café.txt")
	nfc := norm.NFC.String("café.txt")
	if nfd == nfc {
		t.Skip("test name has no distinct NFC/NFD forms")
	}
	if err := os.WriteFile(filepath.Join(shareDir, nfd), []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, smb2.Header{Command: smb2.CommandCreate}, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}, nfc, "AFP_AfpInfo")
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("stream CREATE on NFC name over NFD file = %#x, want SUCCESS", uint32(got))
	}
}

// --- finding 9: symlink TOCTOU on truncate / chtimes ----------------------

// TestFileOps_SetInfoEndOfFileUsesDescriptor proves SET_INFO EOF resizes the
// file the handle was opened on, not whatever the path now names. os.Truncate
// follows symlinks, so a symlink swapped in after CREATE would let a resize
// escape the share, defeating the O_NOFOLLOW protection on the open.
func TestFileOps_SetInfoEndOfFileUsesDescriptor(t *testing.T) {
	shareDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(outside, bytes.Repeat([]byte("A"), 100), 0644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(shareDir, "f.txt")
	if err := os.WriteFile(p, bytes.Repeat([]byte("B"), 50), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	d, sess, tree := newTestDispatcher(t, shareDir)
	open := &Open{Path: p, File: f, Tree: tree, GrantedAccess: 0x001F01FF}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	// Attacker swaps the leaf for a symlink pointing outside the share.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}

	eof := make([]byte, 8)
	var buf bytes.Buffer
	d.handleSetInfo(&buf, smb2.Header{Command: smb2.CommandSetInfo},
		buildSetInfoBody(smb2.InfoTypeFile, smb2.FileEndOfFileInformation, open.FileID, eof), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("SET_INFO EOF status = %#x, want SUCCESS", uint32(got))
	}
	st, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 100 {
		t.Fatalf("file outside the share was truncated through a swapped-in symlink: size %d", st.Size())
	}
}

// TestFileOps_SetInfoBasicDoesNotFollowSymlink proves the timestamp write does
// not traverse a symlink at the leaf either.
func TestFileOps_SetInfoBasicDoesNotFollowSymlink(t *testing.T) {
	shareDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(outside, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(shareDir, "f.txt")
	if err := os.WriteFile(p, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	d, sess, tree := newTestDispatcher(t, shareDir)
	open := &Open{Path: p, File: f, Tree: tree, GrantedAccess: 0x001F01FF}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}

	want := time.Date(1999, 1, 2, 3, 4, 5, 0, time.UTC)
	var buf bytes.Buffer
	d.handleSetInfo(&buf, smb2.Header{Command: smb2.CommandSetInfo},
		buildSetInfoBody(smb2.InfoTypeFile, smb2.FileBasicInformationSet, open.FileID,
			basicInfoBuffer(want, want)), sess)

	after, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("mtime of a file outside the share changed through a swapped-in symlink: %v -> %v",
			before.ModTime(), after.ModTime())
	}
}
