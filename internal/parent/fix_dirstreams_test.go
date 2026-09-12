package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/unix"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- named streams on directories -----------------------------------------
//
// macOS stores Finder metadata (tags, labels, custom icons) in named streams on
// FOLDERS, not just files: smb2fs_smb_get_create_options() in Apple's smbfs
// deliberately omits FILE_DIRECTORY_FILE when a stream name is present, and
// smbfs_vnop_setxattr() has no vnode-type guard at all. The CREATE path used to
// answer STATUS_FILE_IS_A_DIRECTORY for those, so `xattr -w
// com.apple.metadata:_kMDItemUserTags tag <dir>` over the mount failed with EIO
// while the same command on a file through the same mount succeeded.

// parseStreamInfoNames decodes a FILE_STREAM_INFORMATION list (MS-FSCC §2.4.40)
// into its stream names, so a test can assert on what a QUERY_INFO would tell
// the client.
func parseStreamInfoNames(t *testing.T, buf []byte) []string {
	t.Helper()
	var names []string
	off := 0
	for off+24 <= len(buf) {
		next := binary.LittleEndian.Uint32(buf[off:])
		nameLen := int(binary.LittleEndian.Uint32(buf[off+4:]))
		start := off + 24
		if start+nameLen > len(buf) || nameLen%2 != 0 {
			t.Fatalf("malformed FILE_STREAM_INFORMATION entry at offset %d", off)
		}
		u16 := make([]uint16, nameLen/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(buf[start+2*i:])
		}
		names = append(names, string(utf16.Decode(u16)))
		if next == 0 {
			break
		}
		off += int(next)
	}
	return names
}

// TestDirStream_WriteReadRoundTrip proves a named stream can be created,
// written, closed and read back on a DIRECTORY — the Finder folder-tag case.
func TestDirStream_WriteReadRoundTrip(t *testing.T) {
	shareDir := t.TempDir()
	sub := filepath.Join(shareDir, "folder")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, sub) {
		t.Skip("filesystem does not support user xattrs")
	}

	d, sess, tree := newTestDispatcher(t, shareDir)
	const stream = "com.apple.metadata:_kMDItemUserTags"
	createReq := smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}
	hdr := smb2.Header{Command: smb2.CommandCreate}

	// --- Handle 1: CREATE the stream on the directory, WRITE, CLOSE ---
	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, hdr, sess, tree, createReq, "folder", stream)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("stream CREATE on a directory = %#x, want SUCCESS", uint32(got))
	}
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil || !open.IsStream {
		t.Fatalf("stream open not registered: %+v", open)
	}
	if open.IsDir {
		t.Fatal("a stream handle on a directory must not be a directory handle")
	}

	payload := []byte("bplist00\x00\xd1yellow")
	buf.Reset()
	d.handleWrite(&buf, smb2.Header{Command: smb2.CommandWrite},
		buildWriteBody(open.FileID, 0, payload), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("stream WRITE on a directory = %#x, want SUCCESS", uint32(got))
	}
	buf.Reset()
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("stream CLOSE on a directory = %#x, want SUCCESS", uint32(got))
	}

	// The bytes must have landed on the directory's own xattr.
	raw := make([]byte, 256)
	n, err := unix.Getxattr(sub, "user.gosamba.ads."+stream, raw)
	if err != nil {
		t.Fatalf("on-disk Getxattr on the directory after close: %v", err)
	}
	if !bytes.Equal(raw[:n], payload) {
		t.Fatalf("on-disk directory stream = %q, want %q", raw[:n], payload)
	}

	// --- Handle 2: a fresh FILE_OPEN reads the same bytes back ---
	buf.Reset()
	d.handleCreateNamedStream(&buf, hdr, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpen}, "folder", stream)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("FILE_OPEN of an existing directory stream = %#x, want SUCCESS", uint32(got))
	}
	open2 := sess.GetOpen(d.LastCreatedFileID)
	if open2 == nil {
		t.Fatal("reopened directory stream not registered")
	}
	if !bytes.Equal(open2.streamBuf, payload) {
		t.Fatalf("reopened directory streamBuf = %q, want %q", open2.streamBuf, payload)
	}

	// The directory itself is untouched by all of this.
	if st, err := os.Lstat(sub); err != nil || !st.IsDir() {
		t.Fatalf("directory no longer a live directory after stream I/O: %v", err)
	}
}

// TestDirStream_DeleteOnCloseKeepsDirectory proves delete-on-close of a
// directory's named stream removes ONLY the backing xattr. Apple's client
// deletes an xattr with a compound Create / SetInfo(FileDispositionInformation)
// / Close, so a stream handle reaching the generic unlink would delete the
// user's folder instead of one tag.
func TestDirStream_DeleteOnCloseKeepsDirectory(t *testing.T) {
	shareDir := t.TempDir()
	sub := filepath.Join(shareDir, "folder")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(sub, "keepme.txt")
	if err := os.WriteFile(child, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, sub) {
		t.Skip("filesystem does not support user xattrs")
	}
	if err := writeStreamXattr(sub, "gone", []byte("tag")); err != nil {
		t.Fatalf("seed writeStreamXattr on a directory: %v", err)
	}

	d, sess, tree := newTestDispatcher(t, shareDir)
	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, smb2.Header{Command: smb2.CommandCreate}, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpen}, "folder", "gone")
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("FILE_OPEN of directory stream = %#x, want SUCCESS", uint32(got))
	}
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil {
		t.Fatal("directory stream open not registered")
	}

	// Mark delete-on-close the way the client does: SET_INFO Disposition.
	buf.Reset()
	d.handleSetInfo(&buf, smb2.Header{Command: smb2.CommandSetInfo},
		buildSetInfoBody(smb2.InfoTypeFile, smb2.FileDispositionInformation, open.FileID, []byte{1}), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("SET_INFO disposition on a directory stream = %#x, want SUCCESS", uint32(got))
	}
	if !open.DeleteOnClose {
		t.Fatal("SET_INFO FileDispositionInformation did not arm delete-on-close")
	}

	buf.Reset()
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("CLOSE of a delete-on-close directory stream = %#x, want SUCCESS", uint32(got))
	}

	// The xattr is gone...
	if _, err := unix.Getxattr(sub, "user.gosamba.ads.gone", make([]byte, 16)); !isXattrNotFound(err) {
		t.Fatalf("expected attribute-not-found after delete-on-close, got %v", err)
	}
	// ...and the directory, with its contents, is emphatically not.
	st, err := os.Lstat(sub)
	if err != nil || !st.IsDir() {
		t.Fatalf("delete-on-close of a stream removed the directory: %v", err)
	}
	if _, err := os.Stat(child); err != nil {
		t.Fatalf("delete-on-close of a directory stream disturbed its contents: %v", err)
	}
}

// TestDirStream_StreamInformation proves FileStreamInformation reports a
// directory's named streams (and omits the ::$DATA entry a directory does not
// have), while a regular file still reports ::$DATA plus its streams.
func TestDirStream_StreamInformation(t *testing.T) {
	shareDir := t.TempDir()
	sub := filepath.Join(shareDir, "folder")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(file, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, sub) {
		t.Skip("filesystem does not support user xattrs")
	}
	if err := writeStreamXattr(sub, "com.apple.FinderInfo", []byte("0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := writeStreamXattr(file, "mystream", []byte("abc")); err != nil {
		t.Fatal(err)
	}

	_, _, tree := newTestDispatcher(t, shareDir)

	// A directory handle: named streams, no ::$DATA.
	dirOpen := &Open{Path: sub, Tree: tree, IsDir: true}
	dirInfo, err := os.Lstat(sub)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := encodeFileInfo(smb2.FileStreamInformation, dirInfo, dirOpen)
	if !ok {
		t.Fatal("FileStreamInformation on a directory was rejected")
	}
	names := parseStreamInfoNames(t, got)
	if len(names) != 1 || names[0] != ":com.apple.FinderInfo:$DATA" {
		t.Fatalf("directory stream list = %q, want only :com.apple.FinderInfo:$DATA", names)
	}

	// Also check that listStreams itself sees it (the `xattr -l <dir>` path).
	streams, err := listStreams(sub)
	if err != nil {
		t.Fatalf("listStreams on a directory: %v", err)
	}
	if len(streams) != 1 || streams[0].Name != "com.apple.FinderInfo" || streams[0].Size != 16 {
		t.Fatalf("listStreams(dir) = %+v, want one 16-byte com.apple.FinderInfo", streams)
	}

	// A regular file is unchanged: ::$DATA first, then its named streams.
	fileOpen := &Open{Path: file, Tree: tree}
	fileInfo, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	got, ok = encodeFileInfo(smb2.FileStreamInformation, fileInfo, fileOpen)
	if !ok {
		t.Fatal("FileStreamInformation on a file was rejected")
	}
	names = parseStreamInfoNames(t, got)
	if len(names) != 2 || names[0] != "::$DATA" || names[1] != ":mystream:$DATA" {
		t.Fatalf("file stream list = %q, want [::$DATA :mystream:$DATA]", names)
	}

	// An empty directory reports no streams at all, not a bogus ::$DATA.
	empty := filepath.Join(shareDir, "empty")
	if err := os.Mkdir(empty, 0755); err != nil {
		t.Fatal(err)
	}
	emptyInfo, err := os.Lstat(empty)
	if err != nil {
		t.Fatal(err)
	}
	got, ok = encodeFileInfo(smb2.FileStreamInformation, emptyInfo, &Open{Path: empty, Tree: tree, IsDir: true})
	if !ok {
		t.Fatal("FileStreamInformation on an empty directory was rejected")
	}
	if len(got) != 0 {
		t.Fatalf("stream list for a directory with no streams = %d bytes, want 0", len(got))
	}
}

// TestDirStream_AFPInfoSynthesizedOnDir proves the synthesized AFP_AfpInfo blob
// still works for a directory: macOS reads it during a copy and aborts on a
// short read.
func TestDirStream_AFPInfoSynthesizedOnDir(t *testing.T) {
	shareDir := t.TempDir()
	sub := filepath.Join(shareDir, "folder")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, smb2.Header{Command: smb2.CommandCreate}, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpen}, "folder", "AFP_AfpInfo")
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("FILE_OPEN of AFP_AfpInfo on a directory = %#x, want SUCCESS", uint32(got))
	}
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil {
		t.Fatal("AFP_AfpInfo directory stream not registered")
	}
	if len(open.streamBuf) != afpInfoSize {
		t.Fatalf("AFP_AfpInfo blob = %d bytes, want %d", len(open.streamBuf), afpInfoSize)
	}
	if !bytes.Equal(open.streamBuf[:8], []byte{'A', 'F', 'P', 0, 0, 0, 1, 0}) {
		t.Fatalf("AFP_AfpInfo header = %x, want signature+version", open.streamBuf[:8])
	}
	if !open.streamSynthetic {
		t.Fatal("fabricated AFP_AfpInfo must be flagged synthetic so a read-only open doesn't persist it")
	}

	// A read-only open must not litter the directory with a metadata xattr.
	buf.Reset()
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
		t.Fatalf("CLOSE of a synthetic AFP_AfpInfo dir stream = %#x, want SUCCESS", uint32(got))
	}
	if _, err := unix.Getxattr(sub, "user.gosamba.ads.AFP_AfpInfo", make([]byte, 8)); err == nil {
		t.Fatal("a read-only AFP_AfpInfo open persisted an xattr on the directory")
	}
}

// TestDirStream_ContainmentStillEnforced proves the removed check was about
// vnode type only: a stream CREATE still cannot escape the share, and a stream
// on a base object that does not exist is still refused.
func TestDirStream_ContainmentStillEnforced(t *testing.T) {
	shareDir := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.Mkdir(victim, 0755); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the share pointing at a directory outside it.
	if err := os.Symlink(victim, filepath.Join(shareDir, "escape")); err != nil {
		t.Fatal(err)
	}

	d, sess, tree := newTestDispatcher(t, shareDir)
	hdr := smb2.Header{Command: smb2.CommandCreate}

	// `escape/..` is deliberately not in this list: it cleans lexically to the
	// share root, which is inside the share.
	for _, name := range []string{"../victim", "escape", "escape/tag"} {
		var buf bytes.Buffer
		d.handleCreateNamedStream(&buf, hdr, sess, tree,
			smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}, name, "tag")
		if got := frameStatus(t, &buf); got == smb2.StatusSuccess {
			t.Fatalf("stream CREATE on %q escaped the share", name)
		}
	}
	if names, err := listXattrNames(victim); err == nil {
		for _, n := range names {
			if n == "user.gosamba.ads.tag" {
				t.Fatal("a stream write landed outside the share")
			}
		}
	}
	if st, err := os.Lstat(victim); err != nil || !st.IsDir() {
		t.Fatalf("the directory outside the share was disturbed: %v", err)
	}

	// A base object that simply is not there is still OBJECT_NAME_NOT_FOUND.
	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, hdr, sess, tree,
		smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}, "nosuchdir", "tag")
	if got := frameStatus(t, &buf); got != smb2.StatusObjectNameNotFound {
		t.Fatalf("stream on a missing base = %#x, want OBJECT_NAME_NOT_FOUND", uint32(got))
	}
}
