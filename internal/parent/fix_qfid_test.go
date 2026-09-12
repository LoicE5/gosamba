package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// qfidReqCtx builds a CREATE request carrying the SMB2_CREATE_QUERY_ON_DISK_ID
// context exactly the way macOS sends it: name "QFid", no data.
func qfidReqCtx() []byte {
	return smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: []byte("QFid"), Data: nil}})
}

// findContext returns the data of the first response context named tag, and
// whether it was present at all.
func findContext(raw []byte, tag string) ([]byte, bool) {
	var data []byte
	found := false
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		if string(c.Name) != tag {
			return true
		}
		found = true
		data = c.Data
		return false
	})
	return data, found
}

// statInoDev returns the inode and device number of path as the QFid context
// should report them.
func statInoDev(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		t.Skip("platform does not expose syscall.Stat_t")
	}
	return uint64(st.Ino), devToUint64(st.Dev)
}

// TestQFid_CreateReturnsRealFileID proves a CREATE that carries the QFid
// context gets a QFid response context back holding the file's real inode and
// device number.
//
// macOS attaches QFid to every CREATE that creates something and stores the
// returned DiskFileId as the vnode's inode. Dropping the context — or worse,
// answering with a zero DiskFileId — makes the client permanently clear
// FILE_IDS_SUPPORTED for the whole session and fall back to hashing file names
// into fake inode numbers.
func TestQFid_CreateReturnsRealFileID(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)

	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBody("new.txt", smb2.CreateDispositionCreate, 0, smb2.AccessGenericAll, qfidReqCtx()), sess)

	_, _, rctxs := readCreateResponse(t, &buf)
	data, ok := findContext(rctxs, "QFid")
	if !ok {
		t.Fatal("no QFid response context emitted; macOS drops File-ID support for the session")
	}
	// MS-SMB2 2.2.14.2.9: exactly 32 bytes. The macOS client fails the whole
	// CREATE with EBADRPC on any other length, and does not retry.
	if len(data) != 32 {
		t.Fatalf("QFid data len = %d, want exactly 32", len(data))
	}

	wantIno, wantDev := statInoDev(t, filepath.Join(shareDir, "new.txt"))
	if got := binary.LittleEndian.Uint64(data[0:]); got != wantIno {
		t.Errorf("QFid DiskFileId = %d, want inode %d", got, wantIno)
	}
	if got := binary.LittleEndian.Uint64(data[8:]); got != wantDev {
		t.Errorf("QFid VolumeId = %d, want dev %d", got, wantDev)
	}
	for i, b := range data[16:] {
		if b != 0 {
			t.Fatalf("QFid reserved byte %d = %#x, want 0", i, b)
		}
	}

	// The client also rejects the response unless NameLength is exactly 4.
	assertContextNameLen4(t, rctxs, "QFid")

	// Only contexts the client asked for may come back: an unknown response
	// context name is EBADRPC to macOS.
	if _, extra := findContext(rctxs, "MxAc"); extra {
		t.Error("MxAc echoed back without being requested")
	}
}

// TestQFid_OpenExistingDirectoryReportsInode proves the directory path (no
// *os.File handle to fstat) still reports the real inode.
func TestQFid_OpenExistingDirectoryReportsInode(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(shareDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBody("sub", smb2.CreateDispositionOpen, smb2.CreateOptDirectoryFile, smb2.AccessGenericRead, qfidReqCtx()), sess)

	_, _, rctxs := readCreateResponse(t, &buf)
	data, ok := findContext(rctxs, "QFid")
	if !ok {
		t.Fatal("no QFid response context for a directory open")
	}
	if len(data) != 32 {
		t.Fatalf("QFid data len = %d, want exactly 32", len(data))
	}
	wantIno, wantDev := statInoDev(t, filepath.Join(shareDir, "sub"))
	if got := binary.LittleEndian.Uint64(data[0:]); got != wantIno {
		t.Errorf("QFid DiskFileId = %d, want inode %d", got, wantIno)
	}
	if got := binary.LittleEndian.Uint64(data[8:]); got != wantDev {
		t.Errorf("QFid VolumeId = %d, want dev %d", got, wantDev)
	}
}

// TestQFid_NotEmittedWhenNotRequested proves the server never volunteers a
// QFid context. An unsolicited/unknown response context name makes the macOS
// client fail the CREATE with EBADRPC.
func TestQFid_NotEmittedWhenNotRequested(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)

	// No create contexts at all.
	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBody("plain.txt", smb2.CreateDispositionCreate, 0, smb2.AccessGenericAll, nil), sess)
	_, _, rctxs := readCreateResponse(t, &buf)
	if _, ok := findContext(rctxs, "QFid"); ok {
		t.Fatal("QFid emitted for a CREATE that did not request it")
	}

	// A different context (MxAc) requested: still no QFid.
	mxac := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: []byte("MxAc"), Data: nil}})
	var buf2 bytes.Buffer
	d.handleCreate(&buf2, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBody("plain2.txt", smb2.CreateDispositionCreate, 0, smb2.AccessGenericAll, mxac), sess)
	_, _, rctxs2 := readCreateResponse(t, &buf2)
	if _, ok := findContext(rctxs2, "QFid"); ok {
		t.Fatal("QFid emitted alongside MxAc without being requested")
	}
	if _, ok := findContext(rctxs2, "MxAc"); !ok {
		t.Fatal("MxAc response context lost")
	}
}

// TestQFid_OmittedWithoutRealInode proves that when there is no real inode to
// report — a named-stream handle, a pipe, or a failed stat — the context is
// left out entirely rather than answered with a DiskFileId of zero. Zero is
// exactly what makes macOS give up on file IDs for the session.
func TestQFid_OmittedWithoutRealInode(t *testing.T) {
	// Direct: the builder must drop QFid when handed a zero inode.
	out := buildCreateResponseContexts(qfidReqCtx(), nil, 0x001F01FF, 0, 0)
	if _, ok := findContext(out, "QFid"); ok {
		t.Fatal("QFid emitted with a zero DiskFileId")
	}
	// A zero inode must not suppress the other contexts.
	both := smb2.EncodeCreateContexts([]smb2.CreateContext{
		{Name: []byte("MxAc"), Data: nil},
		{Name: []byte("QFid"), Data: nil},
	})
	out = buildCreateResponseContexts(both, nil, 0x001F01FF, 0, 0)
	if _, ok := findContext(out, "QFid"); ok {
		t.Fatal("QFid emitted with a zero DiskFileId (mixed context set)")
	}
	if _, ok := findContext(out, "MxAc"); !ok {
		t.Fatal("MxAc dropped when QFid was suppressed")
	}

	// End-to-end: a named-stream CREATE carries no inode of its own.
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	var buf bytes.Buffer
	d.handleCreateNamedStream(&buf, smb2.Header{Command: smb2.CommandCreate}, sess, tree,
		smb2.CreateRequest{
			CreateDisposition: smb2.CreateDispositionOpenIf,
			CreateContexts:    qfidReqCtx(),
		}, "doc.txt", "mystream")

	_, _, rctxs := readCreateResponse(t, &buf)
	if _, ok := findContext(rctxs, "QFid"); ok {
		t.Fatal("QFid emitted for a named-stream handle, which has no inode of its own")
	}

	// unixInodeAndDev must report (0, 0) for a FileInfo with no Stat_t.
	if ino, dev := unixInodeAndDev(nil); ino != 0 || dev != 0 {
		t.Fatalf("unixInodeAndDev(nil) = (%d, %d), want (0, 0)", ino, dev)
	}
}

// assertContextNameLen4 walks the raw response-context list and checks the
// on-wire NameLength of the named entry is 4. The macOS client rejects the
// whole CREATE with EBADRPC when a response context's NameLength != 4
// (kernel/netsmb/smb_smb_2.c, smb2_smb_parse_create_contexts).
func assertContextNameLen4(t *testing.T, raw []byte, tag string) {
	t.Helper()
	off := 0
	for off+16 <= len(raw) {
		next := int(binary.LittleEndian.Uint32(raw[off:]))
		nameOff := int(binary.LittleEndian.Uint16(raw[off+4:]))
		nameLen := int(binary.LittleEndian.Uint16(raw[off+6:]))
		if off+nameOff+nameLen <= len(raw) && string(raw[off+nameOff:off+nameOff+nameLen]) == tag {
			if nameLen != 4 {
				t.Fatalf("%s context NameLength = %d, want 4", tag, nameLen)
			}
			return
		}
		if next == 0 {
			break
		}
		off += next
	}
	t.Fatalf("context %s not found in raw response contexts", tag)
}
