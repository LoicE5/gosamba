package parent

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// The file identifier a client sees for a path must come from exactly one
// source of truth. macOS smbfs treats a changed id for a path as "this path now
// holds a different object" (node_vtype_changed / smbfs_nget in smbfs_node.c):
// it purges the vnode from the name cache, drops it from the node hash, zeroes
// the attribute and symlink cache timers and invalidates the page cache. When
// QUERY_DIR reports the inode and QUERY_INFO reports something else, that fires
// for every file on every stat.
//
// These tests are deliberately untagged: the identity must hold on linux and on
// darwin alike.

// --- helpers -----------------------------------------------------------------

// dirRecordFileID pulls the FileId field out of an encodeDirRecord record for
// one of the two classes that carry one.
func dirRecordFileID(t *testing.T, name string, info os.FileInfo, class uint8, useAAPL bool) uint64 {
	t.Helper()
	rec := encodeDirRecord(name, info, class, useAAPL, 0x001F01FF, 0)
	if rec == nil {
		t.Fatalf("encodeDirRecord(class=%#x) returned nil", class)
	}
	var off int
	switch class {
	case smb2.InfoFileIdBothDirectoryInformation:
		off = 96 // FILE_ID_BOTH_DIR_INFORMATION FileId
	case smb2.InfoFileIdFullDirectoryInformation:
		off = 72 // FILE_ID_FULL_DIR_INFORMATION FileId
	default:
		t.Fatalf("class %#x carries no FileId", class)
	}
	if len(rec) < off+8 {
		t.Fatalf("record too short: %d bytes, need %d", len(rec), off+8)
	}
	return binary.LittleEndian.Uint64(rec[off:])
}

// queryInfoInternalID returns the IndexNumber from FileInternalInformation.
func queryInfoInternalID(t *testing.T, info os.FileInfo, o *Open) uint64 {
	t.Helper()
	buf, ok := encodeFileInfo(smb2.FileInternalInformation, info, o)
	if !ok {
		t.Fatal("encodeFileInfo FileInternalInformation not ok")
	}
	if len(buf) != 8 {
		t.Fatalf("FileInternalInformation = %d bytes, want 8", len(buf))
	}
	return binary.LittleEndian.Uint64(buf)
}

// queryInfoAllID returns the IndexNumber embedded in FileAllInformation
// (FILE_INTERNAL_INFORMATION at offset 64, after Basic(40) + Standard(24)).
func queryInfoAllID(t *testing.T, info os.FileInfo, o *Open) uint64 {
	t.Helper()
	buf, ok := encodeFileInfo(smb2.FileAllInformation, info, o)
	if !ok {
		t.Fatal("encodeFileInfo FileAllInformation not ok")
	}
	if len(buf) < 72 {
		t.Fatalf("FileAllInformation = %d bytes, want >= 72", len(buf))
	}
	return binary.LittleEndian.Uint64(buf[64:])
}

// realInode reads the inode straight from the kernel, independently of any
// encoder in this package.
func realInode(t *testing.T, path string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return uint64(st.Ino)
}

// legacyPathHash reproduces the identifier encodeFileInfo used to report: a
// rolling hash of the open's path. Kept here only so the regression tests can
// assert we no longer emit it.
func legacyPathHash(path string) uint64 {
	var v uint64
	for _, c := range path {
		v = v*131 + uint64(c)
	}
	return v
}

// --- tests -------------------------------------------------------------------

// TestFileID_QueryInfoMatchesDirRecord is the core invariant: for the same file,
// the id QUERY_INFO reports (both FileInternalInformation and the
// FileAllInformation IndexNumber) is byte-for-byte the id QUERY_DIR put in that
// file's FileId field, and it is the real inode. Before the fix the directory
// encoder reported the inode while query-info reported a path hash, so this test
// fails on the old code for every file.
func TestFileID_QueryInfoMatchesDirRecord(t *testing.T) {
	shareDir := t.TempDir()
	path := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(path, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	open := &Open{Path: path, GrantedAccess: 0x001F01FF}

	ino := realInode(t, path)
	if ino == 0 {
		t.Fatal("kernel reported inode 0; test cannot distinguish the bug")
	}

	ids := map[string]uint64{
		"QUERY_DIR IdBoth":           dirRecordFileID(t, "doc.txt", info, smb2.InfoFileIdBothDirectoryInformation, false),
		"QUERY_DIR IdBoth (AAPL)":    dirRecordFileID(t, "doc.txt", info, smb2.InfoFileIdBothDirectoryInformation, true),
		"QUERY_DIR IdFull":           dirRecordFileID(t, "doc.txt", info, smb2.InfoFileIdFullDirectoryInformation, false),
		"QUERY_INFO Internal":        queryInfoInternalID(t, info, open),
		"QUERY_INFO All.IndexNumber": queryInfoAllID(t, info, open),
	}
	for what, got := range ids {
		if got != ino {
			t.Errorf("%s id = %d, want the real inode %d", what, got, ino)
		}
		if got == 0 {
			t.Errorf("%s reported id 0 for a real file; macOS stops trusting File IDs entirely", what)
		}
	}
}

// TestFileID_NotAPathHash is the regression guard for the specific old
// behaviour: query-info used to hash o.Path with v = v*131 + c. A file whose
// hash happened to equal its inode is not a thing, so any equality here means
// the hash is back.
func TestFileID_NotAPathHash(t *testing.T) {
	shareDir := t.TempDir()
	path := filepath.Join(shareDir, "hashed.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	open := &Open{Path: path}

	hash := legacyPathHash(path)
	if got := queryInfoInternalID(t, info, open); got == hash {
		t.Errorf("FileInternalInformation still reports the path hash %d", got)
	}
	if got := queryInfoAllID(t, info, open); got == hash {
		t.Errorf("FileAllInformation IndexNumber still reports the path hash %d", got)
	}
}

// TestFileID_StableAcrossRename proves the id tracks the object, not the name.
// The path hash changed on every rename, which is precisely what makes smbfs
// throw the vnode and its page cache away.
func TestFileID_StableAcrossRename(t *testing.T) {
	shareDir := t.TempDir()
	oldPath := filepath.Join(shareDir, "before.txt")
	newPath := filepath.Join(shareDir, "after.txt")
	if err := os.WriteFile(oldPath, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Lstat(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	before := queryInfoInternalID(t, infoBefore, &Open{Path: oldPath})

	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Lstat(newPath)
	if err != nil {
		t.Fatal(err)
	}
	after := queryInfoInternalID(t, infoAfter, &Open{Path: newPath})

	if before != after {
		t.Errorf("id changed across rename: %d -> %d (same inode, different name)", before, after)
	}
	if before == 0 {
		t.Error("id is 0 for a real file")
	}
}

// TestFileID_Directory checks a directory handle reports its own inode, matching
// what the parent directory's listing reported for it.
func TestFileID_Directory(t *testing.T) {
	shareDir := t.TempDir()
	dir := filepath.Join(shareDir, "sub")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	open := &Open{Path: dir, IsDir: true}

	want := realInode(t, dir)
	fromDir := dirRecordFileID(t, "sub", info, smb2.InfoFileIdBothDirectoryInformation, false)
	if fromDir != want {
		t.Fatalf("QUERY_DIR FileId for dir = %d, want %d", fromDir, want)
	}
	if got := queryInfoInternalID(t, info, open); got != want {
		t.Errorf("FileInternalInformation for dir = %d, want %d", got, want)
	}
	if got := queryInfoAllID(t, info, open); got != want {
		t.Errorf("FileAllInformation IndexNumber for dir = %d, want %d", got, want)
	}
}

// TestFileID_StreamHandleUsesBaseFileInode covers the one FileInfo with no inode
// behind it: the synthetic streamFileInfo an alternate-data-stream Open carries.
// We report the base file's inode (NTFS gives every stream of a file the same
// MFT record number), never 0.
func TestFileID_StreamHandleUsesBaseFileInode(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	open := &Open{Path: base, IsStream: true, StreamName: "mystream", streamBuf: []byte("meta")}

	info := openFileInfo(open)
	if _, ok := info.(streamFileInfo); !ok {
		t.Fatalf("openFileInfo on a stream returned %T, want streamFileInfo", info)
	}
	if _, ino := unixModeAndInode(info); ino != 0 {
		t.Fatalf("streamFileInfo unexpectedly carries an inode (%d); test premise is stale", ino)
	}

	want := realInode(t, base)
	if got := queryInfoInternalID(t, info, open); got != want {
		t.Errorf("stream FileInternalInformation = %d, want base file inode %d", got, want)
	}
	if got := queryInfoAllID(t, info, open); got != want {
		t.Errorf("stream FileAllInformation IndexNumber = %d, want base file inode %d", got, want)
	}
}

// TestFileID_HardLinksShareID: two names for one inode are one object, and the
// server must say so. The old path hash gave them two different ids.
func TestFileID_HardLinksShareID(t *testing.T) {
	shareDir := t.TempDir()
	a := filepath.Join(shareDir, "a.txt")
	b := filepath.Join(shareDir, "b.txt")
	if err := os.WriteFile(a, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("filesystem does not support hard links: %v", err)
	}
	infoA, err := os.Lstat(a)
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := os.Lstat(b)
	if err != nil {
		t.Fatal(err)
	}
	idA := queryInfoInternalID(t, infoA, &Open{Path: a})
	idB := queryInfoInternalID(t, infoB, &Open{Path: b})
	if idA != idB {
		t.Errorf("hard links report different ids: %d vs %d", idA, idB)
	}
	if idA == 0 {
		t.Error("id is 0 for a real file")
	}
}
