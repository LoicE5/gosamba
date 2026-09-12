package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- macOS "server message" CHANGE_NOTIFY ----------------------------------
//
// Because this server answers the AAPL server-query create context, Apple's
// client latches SMBV_OSX_SERVER (smb_smb_2.c) and smbfs_start_svrmsg_notify()
// fires a CHANGE_NOTIFY whose SMBFID is 0xffffffffffffffff (smbfs_smb_2.c);
// smb_fid_get_kernel_fid() expands that to an all-FF persistent+volatile
// FileId on the wire. It is a standalone request, not a related compound op,
// so the "previous handle" substitution never runs and no handle can match.
//
// Answering STATUS_INVALID_PARAMETER yields EINVAL, which process_svrmsg_items()
// retries until rcvd_notify_count passes SMBFS_MAX_RCVD_NOTIFY (4). Answering
// STATUS_NOT_SUPPORTED yields ENOTSUP, which that same function turns into a
// single clean "svrmsg notify not supported" teardown.

// buildChangeNotifyBody constructs a CHANGE_NOTIFY request body
// (MS-SMB2 §2.2.35: StructureSize 32, Flags, OutputBufferLength, FileId,
// CompletionFilter, Reserved).
func buildChangeNotifyBody(fileID [16]byte, flags uint16, outBufLen, filter uint32) []byte {
	body := make([]byte, 32)
	binary.LittleEndian.PutUint16(body[0:], 32)
	binary.LittleEndian.PutUint16(body[2:], flags)
	binary.LittleEndian.PutUint32(body[4:], outBufLen)
	copy(body[8:24], fileID[:])
	binary.LittleEndian.PutUint32(body[24:], filter)
	return body
}

// notifyDirHandle registers a real directory handle on the session and returns
// it, mirroring what a CREATE with FILE_DIRECTORY_FILE would have produced.
func notifyDirHandle(t *testing.T, sess *Session, tree *Tree, shareDir, name string) *Open {
	t.Helper()
	dir := filepath.Join(shareDir, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	var fid [16]byte
	fid[0], fid[1] = 0xD1, 0x5C
	open := &Open{Path: dir, IsDir: true, FileID: fid, Tree: tree}
	sess.AddOpen(open)
	return open
}

// TestFix_SvrMsgNotifySentinelDeclinedAsNotSupported proves the all-FF FileId
// with no matching handle is refused with STATUS_NOT_SUPPORTED, so Apple's
// client disables server-message notify on the first reply instead of retrying
// it five times per mount.
func TestFix_SvrMsgNotifySentinelDeclinedAsNotSupported(t *testing.T) {
	d, sess, _ := newTestDispatcher(t, t.TempDir())

	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandChangeNotify, MessageID: 7}
	body := buildChangeNotifyBody(previousHandleFileID, 0, 64*1024, smb2.NotifyFileName)
	d.handleChangeNotify(&buf, hdr, body, sess)

	if got := frameStatus(t, &buf); got != smb2.StatusNotSupported {
		t.Fatalf("svrmsg CHANGE_NOTIFY = %#x, want STATUS_NOT_SUPPORTED (%#x); "+
			"STATUS_INVALID_PARAMETER maps to EINVAL and the client retries it",
			uint32(got), uint32(smb2.StatusNotSupported))
	}
	// Nothing may be left watching: the request was declined outright.
	d.notifyMu.Lock()
	n := len(d.notifies)
	d.notifyMu.Unlock()
	if n != 0 {
		t.Fatalf("declined svrmsg notify left %d registration(s) behind", n)
	}
}

// TestFix_UnknownNotifyFileIDStillInvalidParameter proves an ordinary bad
// FileId keeps its existing error. Only the all-FF sentinel changes: a normal
// client that sends a stale handle must still be told the parameter is wrong.
func TestFix_UnknownNotifyFileIDStillInvalidParameter(t *testing.T) {
	d, sess, _ := newTestDispatcher(t, t.TempDir())

	var stale [16]byte
	stale[0] = 0xAB
	stale[15] = 0xFF // all-FF in one byte only — not the sentinel

	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandChangeNotify, MessageID: 8}
	d.handleChangeNotify(&buf, hdr, buildChangeNotifyBody(stale, 0, 64*1024, smb2.NotifyFileName), sess)

	if got := frameStatus(t, &buf); got != smb2.StatusInvalidParameter {
		t.Fatalf("CHANGE_NOTIFY on an unknown FileId = %#x, want STATUS_INVALID_PARAMETER (%#x)",
			uint32(got), uint32(smb2.StatusInvalidParameter))
	}
}

// TestFix_NotifyOnRealDirectoryHandleStillWorks proves a genuine watch is
// untouched: it is accepted with STATUS_PENDING and completed with
// STATUS_NOTIFY_CLEANUP when the directory handle is closed.
func TestFix_NotifyOnRealDirectoryHandleStillWorks(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)
	open := notifyDirHandle(t, sess, tree, shareDir, "watched")

	w := &syncWriter{}
	hdr := smb2.Header{Command: smb2.CommandChangeNotify, MessageID: 11}
	d.handleChangeNotify(w, hdr, buildChangeNotifyBody(open.FileID, 0, 64*1024, smb2.NotifyFileName), sess)

	if h := awaitFrame(t, w, 1, 2*time.Second); smb2.Status(h.Status) != smb2.StatusPending {
		t.Fatalf("CHANGE_NOTIFY on a real directory handle = %#x, want STATUS_PENDING", h.Status)
	}

	// CLOSE must complete the outstanding watch (MS-SMB2 §3.3.5.19) — on its
	// own writer, so the notify completion is unambiguously frame 2 on w.
	var closeBuf bytes.Buffer
	d.handleClose(&closeBuf, smb2.Header{Command: smb2.CommandClose, MessageID: 12},
		buildCloseBody(open.FileID), sess)
	if got := frameStatus(t, &closeBuf); got != smb2.StatusSuccess {
		t.Fatalf("CLOSE of the watched directory = %#x, want SUCCESS", uint32(got))
	}

	if h := awaitFrame(t, w, 2, 2*time.Second); smb2.Status(h.Status) != smb2.StatusNotifyCleanup {
		t.Fatalf("notify completion after CLOSE = %#x, want STATUS_NOTIFY_CLEANUP (%#x)",
			h.Status, uint32(smb2.StatusNotifyCleanup))
	}
}

// TestFix_RelatedNotifySentinelStillSubstituted proves the compound-chain path
// is unaffected: inside a related chain the all-FF FileId still becomes the
// preceding CREATE's handle, and the resulting CHANGE_NOTIFY is accepted
// rather than declined as unsupported.
func TestFix_RelatedNotifySentinelStillSubstituted(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)
	open := notifyDirHandle(t, sess, tree, shareDir, "compound")

	// Stand in for the CREATE that preceded this op in the chain.
	d.LastCreatedFileID = open.FileID
	d.HasLastCreated = true

	body := buildChangeNotifyBody(previousHandleFileID, 0, 64*1024, smb2.NotifyFileName)
	d.SubstitutePreviousHandleFileID(smb2.CommandChangeNotify, body)
	if got := [16]byte(body[8:24]); got != open.FileID {
		t.Fatalf("related CHANGE_NOTIFY sentinel not substituted: FileId = %x, want %x", got, open.FileID)
	}

	w := &syncWriter{}
	hdr := smb2.Header{Command: smb2.CommandChangeNotify, MessageID: 21, Flags: smb2.FlagRelatedOps}
	d.handleChangeNotify(w, hdr, body, sess)
	if h := awaitFrame(t, w, 1, 2*time.Second); smb2.Status(h.Status) != smb2.StatusPending {
		t.Fatalf("substituted related CHANGE_NOTIFY = %#x, want STATUS_PENDING", h.Status)
	}

	// Tear the watch down so the watcher goroutine and its descriptors go away.
	var closeBuf bytes.Buffer
	d.handleClose(&closeBuf, smb2.Header{Command: smb2.CommandClose, MessageID: 22},
		buildCloseBody(open.FileID), sess)
	awaitFrame(t, w, 2, 2*time.Second)
}

// TestFix_RelatedNotifySentinelWithoutCreateKeepsOldError proves the new
// STATUS_NOT_SUPPORTED path cannot swallow a related-op sentinel. If a chain
// carries the sentinel with no preceding CREATE to substitute, nothing was
// substituted and the request is still diagnosed as a bad parameter — not
// reported as an unsupported server-message notify.
func TestFix_RelatedNotifySentinelWithoutCreateKeepsOldError(t *testing.T) {
	d, sess, _ := newTestDispatcher(t, t.TempDir())

	body := buildChangeNotifyBody(previousHandleFileID, 0, 64*1024, smb2.NotifyFileName)
	d.SubstitutePreviousHandleFileID(smb2.CommandChangeNotify, body) // no-op: HasLastCreated is false
	if got := [16]byte(body[8:24]); got != previousHandleFileID {
		t.Fatalf("sentinel was substituted with no preceding CREATE: %x", got)
	}

	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandChangeNotify, MessageID: 31, Flags: smb2.FlagRelatedOps}
	d.handleChangeNotify(&buf, hdr, body, sess)
	if got := frameStatus(t, &buf); got != smb2.StatusInvalidParameter {
		t.Fatalf("related CHANGE_NOTIFY sentinel with no CREATE = %#x, want STATUS_INVALID_PARAMETER (%#x)",
			uint32(got), uint32(smb2.StatusInvalidParameter))
	}
}
