package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- deleting a symlink deleted its target ---
//
// Making in-share symlinks openable (see fix_createpath_test.go) resolved
// Open.Path to the link's TARGET, because QUERY_INFO, READ, WRITE and durable
// reclaim all work off that field. Every namespace operation went along for the
// ride: DELETE_ON_CLOSE unlinked the target, so deleting a symlink over SMB
// deleted the file it pointed at — and, for a link to a directory, the whole
// directory — while rename renamed the target and left the link dangling.
//
// The model these tests pin down is POSIX's, and it is a split: a handle opened
// through an in-share symlink READS AND WRITES the target, but is NAMED by the
// link. open(2) follows the final symlink; unlink(2) and rename(2) do not.
//
//	data     → Open.Path       (descriptor, READ/WRITE, QUERY_INFO, EOF, locks)
//	name     → Open.namePath() (DELETE_ON_CLOSE, FileRenameInformation)
//
// Share-mode and byte-range-lock keys are deliberately on neither: they are
// (dev,ino) taken from the open descriptor, so two clients reaching one file
// through two different links still collide. That is asserted here too, because
// it is the property most easily lost by "fixing" this the wrong way.

// symlinkFixture is a share directory with the dispatcher/session/tree that
// serve it, plus the share-mode leak check every test in this package owes the
// process-global table.
type symlinkFixture struct {
	t    *testing.T
	dir  string
	d    *Dispatcher
	sess *Session
	tree *Tree
}

func newSymlinkFixture(t *testing.T) *symlinkFixture {
	t.Helper()
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)
	baseline := sharedShareModes.len()
	t.Cleanup(func() {
		if got := sharedShareModes.len(); got != baseline {
			t.Errorf("share-mode table holds %d reservations at test end, want %d: a handle leaked",
				got, baseline)
		}
	})
	return &symlinkFixture{t: t, dir: dir, d: d, sess: sess, tree: tree}
}

func (f *symlinkFixture) path(name string) string { return filepath.Join(f.dir, name) }

// realPath is path() with every symlink evaluated. Open.Path for a handle that
// traversed a link is what vfs.ResolveLink returned, and that is EvalSymlinks
// output — on macOS the temp dir itself lives under /var -> /private/var, so the
// lexical path and the resolved one are genuinely different strings. LinkPath,
// by contrast, is the lexical path the client named, so only the target side
// needs this.
func (f *symlinkFixture) realPath(name string) string {
	f.t.Helper()
	p, err := filepath.EvalSymlinks(f.path(name))
	if err != nil {
		f.t.Fatalf("EvalSymlinks(%s): %v", name, err)
	}
	return p
}

// openShared is mustCreate with an explicit ShareAccess. The shared
// buildCreateBody helper leaves ShareAccess zero, which is deny-all, so two
// handles on one file cannot coexist without this.
func (f *symlinkFixture) openShared(name string, access, share uint32) [16]byte {
	f.t.Helper()
	var out bytes.Buffer
	f.d.handleCreate(&out, smb2.Header{Command: smb2.CommandCreate, TreeID: f.tree.ID},
		buildCreateBodyShare(name, smb2.CreateDispositionOpen, 0, access, share, nil), f.sess)
	hdr, resp, _ := readCreateResponse(f.t, &out)
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		f.t.Fatalf("CREATE %q (access=%#x share=%#x) = %#x, want success",
			name, access, share, hdr.Status)
	}
	return resp.FileID
}

// writeFile drops a regular file into the share.
func (f *symlinkFixture) writeFile(name, content string) string {
	f.t.Helper()
	p := f.path(name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// symlink creates link -> target inside the share. target is kept relative,
// which is what a user's `ln -s` produces and the case the resolver has to
// handle.
func (f *symlinkFixture) symlink(target, link string) string {
	f.t.Helper()
	p := f.path(link)
	if err := os.Symlink(target, p); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// assertFileContent fails unless name is a regular file holding want.
func (f *symlinkFixture) assertFileContent(name, want, why string) {
	f.t.Helper()
	got, err := os.ReadFile(f.path(name))
	if err != nil {
		f.t.Fatalf("%s: reading %s: %v", why, name, err)
	}
	if string(got) != want {
		f.t.Errorf("%s: %s holds %q, want %q", why, name, got, want)
	}
}

// assertGone fails unless name has no entry in the directory at all. Lstat, so
// a surviving symlink counts as present even when its target is gone.
func (f *symlinkFixture) assertGone(name, why string) {
	f.t.Helper()
	if _, err := os.Lstat(f.path(name)); err == nil {
		f.t.Errorf("%s: %s still exists", why, name)
	} else if !os.IsNotExist(err) {
		f.t.Fatalf("%s: lstat %s: %v", why, name, err)
	}
}

// assertSymlinkTo fails unless name is a symlink pointing at want.
func (f *symlinkFixture) assertSymlinkTo(name, want, why string) {
	f.t.Helper()
	st, err := os.Lstat(f.path(name))
	if err != nil {
		f.t.Fatalf("%s: lstat %s: %v", why, name, err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		f.t.Fatalf("%s: %s is not a symlink (mode %v)", why, name, st.Mode())
	}
	got, err := os.Readlink(f.path(name))
	if err != nil {
		f.t.Fatalf("%s: readlink %s: %v", why, name, err)
	}
	if got != want {
		f.t.Errorf("%s: %s points at %q, want %q", why, name, got, want)
	}
}

// setInfo drives one SET_INFO and returns its status.
func (f *symlinkFixture) setInfo(fid [16]byte, class uint8, buf []byte) smb2.Status {
	f.t.Helper()
	var out bytes.Buffer
	f.d.handleSetInfo(&out, smb2.Header{Command: smb2.CommandSetInfo, TreeID: f.tree.ID},
		buildSetInfoBody(smb2.InfoTypeFile, class, fid, buf), f.sess)
	return respStatus(f.t, &out)
}

// buildRenameBuffer encodes FILE_RENAME_INFORMATION (MS-FSCC §2.4.37):
// ReplaceIfExists(1) Reserved(7) RootDirectory(8) FileNameLength(4) FileName(N).
func buildRenameBuffer(newName string, replace bool) []byte {
	nameU16 := utf16leName(newName)
	buf := make([]byte, 20+len(nameU16))
	if replace {
		buf[0] = 1
	}
	binary.LittleEndian.PutUint32(buf[16:], uint32(len(nameU16)))
	copy(buf[20:], nameU16)
	return buf
}

// rename drives SET_INFO FileRenameInformation on fid.
func (f *symlinkFixture) rename(fid [16]byte, newName string, replace bool) smb2.Status {
	f.t.Helper()
	return f.setInfo(fid, smb2.FileRenameInformation, buildRenameBuffer(newName, replace))
}

// armDisposition drives SET_INFO FileDispositionInformation on fid.
func (f *symlinkFixture) armDisposition(fid [16]byte) smb2.Status {
	f.t.Helper()
	return f.setInfo(fid, smb2.FileDispositionInformation, []byte{1})
}

// closeOK closes fid and requires SUCCESS. Every test does this, because a CLOSE
// that failed would leave the disposal half-done and the assertions meaningless.
func (f *symlinkFixture) closeOK(fid [16]byte) {
	f.t.Helper()
	var out bytes.Buffer
	f.d.handleClose(&out, smb2.Header{Command: smb2.CommandClose, TreeID: f.tree.ID},
		buildCloseBody(fid), f.sess)
	if st := respStatus(f.t, &out); st != smb2.StatusSuccess {
		f.t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
}

// --- DELETE_ON_CLOSE: armed at CREATE ---

// TestFixSymlinkDelete_DeleteOnCloseAtCreateRemovesLinkOnly is the headline
// regression. FILE_DELETE_ON_CLOSE in CreateOptions used to unlink Open.Path,
// which by then was the target: `rm link.txt` over SMB destroyed the real file.
func TestFixSymlinkDelete_DeleteOnCloseAtCreateRemovesLinkOnly(t *testing.T) {
	f := newSymlinkFixture(t)
	const content = "the target must survive this"
	f.writeFile("target.txt", content)
	f.symlink("target.txt", "link.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "link.txt",
		smb2.CreateDispositionOpen, smb2.CreateOptDeleteOnClose, smb2.AccessFileReadData)
	f.closeOK(createFileID(body))

	f.assertGone("link.txt", "DELETE_ON_CLOSE on a symlink")
	f.assertFileContent("target.txt", content, "DELETE_ON_CLOSE on a symlink")
}

// TestFixSymlinkDelete_CreateRecordsTheLinkAndTheTarget pins the two halves of
// the handle apart: the field the data operations use is the target, the field
// the namespace operations use is the link. Everything else in this file is a
// consequence of that, so it is asserted directly rather than only through
// behaviour.
func TestFixSymlinkDelete_CreateRecordsTheLinkAndTheTarget(t *testing.T) {
	f := newSymlinkFixture(t)
	f.writeFile("target.txt", "body")
	f.symlink("target.txt", "link.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "link.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	open := f.sess.GetOpen(fid)
	if open == nil {
		t.Fatal("no Open for the FileID the CREATE returned")
	}
	if got, want := open.Path, f.realPath("target.txt"); got != want {
		t.Errorf("Open.Path = %q, want the target %q", got, want)
	}
	if got, want := open.LinkPath, f.path("link.txt"); got != want {
		t.Errorf("Open.LinkPath = %q, want the link %q", got, want)
	}
	if got, want := open.namePath(), f.path("link.txt"); got != want {
		t.Errorf("namePath() = %q, want the link %q", got, want)
	}
	f.closeOK(fid)
}

// TestFixSymlinkDelete_PlainFileLeavesLinkPathEmpty is the guard on the "empty
// unless a link was traversed" invariant. If an ordinary CREATE ever started
// populating LinkPath, namePath() would stop being a no-op for the overwhelming
// majority of handles and this whole change would have a blast radius.
func TestFixSymlinkDelete_PlainFileLeavesLinkPathEmpty(t *testing.T) {
	f := newSymlinkFixture(t)
	f.writeFile("plain.txt", "body")

	body := mustCreate(t, f.d, f.sess, f.tree, "plain.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	open := f.sess.GetOpen(fid)
	if open == nil {
		t.Fatal("no Open for the FileID the CREATE returned")
	}
	if open.LinkPath != "" {
		t.Errorf("Open.LinkPath = %q on a plain file, want empty", open.LinkPath)
	}
	if open.namePath() != open.Path {
		t.Errorf("namePath() = %q, want Path %q", open.namePath(), open.Path)
	}
	f.closeOK(fid)
}

// TestFixSymlinkDelete_PlainFileDeleteOnCloseStillWorks is the other half of
// that guard: routing the unlink through namePath() must not have made an
// ordinary delete stop deleting.
func TestFixSymlinkDelete_PlainFileDeleteOnCloseStillWorks(t *testing.T) {
	f := newSymlinkFixture(t)
	f.writeFile("doomed.txt", "body")

	body := mustCreate(t, f.d, f.sess, f.tree, "doomed.txt",
		smb2.CreateDispositionOpen, smb2.CreateOptDeleteOnClose, smb2.AccessFileReadData)
	f.closeOK(createFileID(body))

	f.assertGone("doomed.txt", "DELETE_ON_CLOSE on a plain file")
}

// --- DELETE_ON_CLOSE: armed later via SET_INFO ---

// TestFixSymlinkDelete_DispositionViaSetInfoRemovesLinkOnly covers the second
// way the flag gets set. macOS arms delete-on-close this way far more often than
// through CreateOptions — a compound CREATE / SET_INFO(disposition) / CLOSE is
// its normal unlink — so a fix that only covered the CREATE arm would miss the
// path that actually runs.
func TestFixSymlinkDelete_DispositionViaSetInfoRemovesLinkOnly(t *testing.T) {
	f := newSymlinkFixture(t)
	const content = "still here afterwards"
	f.writeFile("target.txt", content)
	f.symlink("target.txt", "link.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "link.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	if st := f.armDisposition(fid); st != smb2.StatusSuccess {
		t.Fatalf("SET_INFO FileDispositionInformation = %#x, want success", uint32(st))
	}
	f.closeOK(fid)

	f.assertGone("link.txt", "SET_INFO disposition on a symlink")
	f.assertFileContent("target.txt", content, "SET_INFO disposition on a symlink")
}

// --- DELETE_ON_CLOSE: a link to a directory ---

// TestFixSymlinkDelete_DirectoryLinkRemovesLinkOnly is the most destructive
// form of the bug. A symlink to a directory opens as a directory, so
// DELETE_ON_CLOSE ran os.Remove on the directory itself; the directory survived
// only because it was non-empty, and an empty one was simply deleted.
func TestFixSymlinkDelete_DirectoryLinkRemovesLinkOnly(t *testing.T) {
	f := newSymlinkFixture(t)
	if err := os.Mkdir(f.path("realdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	const content = "a file inside the real directory"
	f.writeFile(filepath.Join("realdir", "inside.txt"), content)
	f.symlink("realdir", "dirlink")

	body := mustCreate(t, f.d, f.sess, f.tree, "dirlink",
		smb2.CreateDispositionOpen,
		smb2.CreateOptDirectoryFile|smb2.CreateOptDeleteOnClose,
		smb2.AccessFileReadData)
	f.closeOK(createFileID(body))

	f.assertGone("dirlink", "DELETE_ON_CLOSE on a directory symlink")
	if st, err := os.Lstat(f.path("realdir")); err != nil {
		t.Fatalf("DELETE_ON_CLOSE on a directory symlink removed the directory: %v", err)
	} else if !st.IsDir() {
		t.Fatalf("realdir is no longer a directory (mode %v)", st.Mode())
	}
	f.assertFileContent(filepath.Join("realdir", "inside.txt"), content,
		"DELETE_ON_CLOSE on a directory symlink")
}

// TestFixSymlinkDelete_EmptyDirectoryLinkRemovesLinkOnly is the same case with
// the accident removed: an EMPTY target directory has nothing to make os.Remove
// fail, so before the fix it really was deleted.
func TestFixSymlinkDelete_EmptyDirectoryLinkRemovesLinkOnly(t *testing.T) {
	f := newSymlinkFixture(t)
	if err := os.Mkdir(f.path("emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.symlink("emptydir", "dirlink")

	body := mustCreate(t, f.d, f.sess, f.tree, "dirlink",
		smb2.CreateDispositionOpen,
		smb2.CreateOptDirectoryFile|smb2.CreateOptDeleteOnClose,
		smb2.AccessFileReadData)
	f.closeOK(createFileID(body))

	f.assertGone("dirlink", "DELETE_ON_CLOSE on a link to an empty directory")
	if st, err := os.Lstat(f.path("emptydir")); err != nil {
		t.Fatalf("the empty target directory was deleted: %v", err)
	} else if !st.IsDir() {
		t.Fatalf("emptydir is no longer a directory (mode %v)", st.Mode())
	}
}

// TestFixSymlinkDelete_LinkToShareRootIsDeletable exercises the share-root
// guard's new form. The guard exists so a client cannot take the whole share
// offline by deleting the tree root, and it compares the handle's NAME. A link
// that happens to point AT the share root is a name of its own: removing it
// leaves the shared directory untouched, so there is nothing to refuse.
func TestFixSymlinkDelete_LinkToShareRootIsDeletable(t *testing.T) {
	f := newSymlinkFixture(t)
	f.writeFile("keepme.txt", "share content")
	f.symlink(".", "selfdir")

	body := mustCreate(t, f.d, f.sess, f.tree, "selfdir",
		smb2.CreateDispositionOpen,
		smb2.CreateOptDirectoryFile|smb2.CreateOptDeleteOnClose,
		smb2.AccessFileReadData)
	f.closeOK(createFileID(body))

	f.assertGone("selfdir", "DELETE_ON_CLOSE on a link to the share root")
	f.assertFileContent("keepme.txt", "share content", "DELETE_ON_CLOSE on a link to the share root")
	if st, err := os.Lstat(f.dir); err != nil || !st.IsDir() {
		t.Fatalf("the share root itself was disturbed: %v", err)
	}
}

// TestFixSymlinkDelete_ShareRootItselfStillRefused proves the guard still fires
// for the case it was written for — a handle on the tree root with no link in
// front of it.
func TestFixSymlinkDelete_ShareRootItselfStillRefused(t *testing.T) {
	f := newSymlinkFixture(t)

	body := mustCreate(t, f.d, f.sess, f.tree, "",
		smb2.CreateDispositionOpen,
		smb2.CreateOptDirectoryFile|smb2.CreateOptDeleteOnClose,
		smb2.AccessFileReadData)
	fid := createFileID(body)

	var out bytes.Buffer
	f.d.handleClose(&out, smb2.Header{Command: smb2.CommandClose, TreeID: f.tree.ID},
		buildCloseBody(fid), f.sess)
	if st := respStatus(t, &out); st != smb2.StatusAccessDenied {
		t.Fatalf("CLOSE of a delete-on-close share-root handle = %#x, want ACCESS_DENIED (%#x)",
			uint32(st), uint32(smb2.StatusAccessDenied))
	}
	if st, err := os.Lstat(f.dir); err != nil || !st.IsDir() {
		t.Fatalf("the share root was removed: %v", err)
	}
}

// --- FileRenameInformation ---

// TestFixSymlinkDelete_RenameMovesLinkNotTarget: `mv link.txt other.txt` moves
// the LINK. Renaming Open.Path renamed the real file instead and left the link
// pointing at a name that no longer existed — the user asked to rename a
// shortcut and got a broken shortcut plus a renamed document.
func TestFixSymlinkDelete_RenameMovesLinkNotTarget(t *testing.T) {
	f := newSymlinkFixture(t)
	const content = "the target keeps its own name"
	f.writeFile("target.txt", content)
	f.symlink("target.txt", "link.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "link.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	if st := f.rename(fid, "other.txt", false); st != smb2.StatusSuccess {
		t.Fatalf("SET_INFO FileRenameInformation = %#x, want success", uint32(st))
	}

	// The handle still reads the target: only the name moved.
	open := f.sess.GetOpen(fid)
	if open == nil {
		t.Fatal("the handle vanished across the rename")
	}
	if got, want := open.Path, f.realPath("target.txt"); got != want {
		t.Errorf("after rename Open.Path = %q, want the unmoved target %q", got, want)
	}
	if got, want := open.LinkPath, f.path("other.txt"); got != want {
		t.Errorf("after rename Open.LinkPath = %q, want the moved link %q", got, want)
	}
	if got := string(readAll(t, f.d, f.sess, fid, uint32(len(content)))); got != content {
		t.Errorf("READ after rename = %q, want the target's %q", got, content)
	}
	f.closeOK(fid)

	f.assertGone("link.txt", "rename of a symlink")
	f.assertSymlinkTo("other.txt", "target.txt", "rename of a symlink")
	f.assertFileContent("target.txt", content, "rename of a symlink")
}

// TestFixSymlinkDelete_RenamedLinkCanThenBeDeleted chains the two namespace
// operations. The rename has to leave LinkPath naming the link's NEW location,
// or the delete that follows would unlink a name that no longer exists (and
// report success for a file still on disk).
func TestFixSymlinkDelete_RenamedLinkCanThenBeDeleted(t *testing.T) {
	f := newSymlinkFixture(t)
	const content = "survives both operations"
	f.writeFile("target.txt", content)
	f.symlink("target.txt", "link.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "link.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	if st := f.rename(fid, "moved.txt", false); st != smb2.StatusSuccess {
		t.Fatalf("rename = %#x, want success", uint32(st))
	}
	if st := f.armDisposition(fid); st != smb2.StatusSuccess {
		t.Fatalf("SET_INFO disposition = %#x, want success", uint32(st))
	}
	f.closeOK(fid)

	f.assertGone("moved.txt", "rename then delete of a symlink")
	f.assertGone("link.txt", "rename then delete of a symlink")
	f.assertFileContent("target.txt", content, "rename then delete of a symlink")
}

// TestFixSymlinkDelete_PlainRenameStillMovesTheFile is the regression guard for
// the ordinary case: routing the rename source through namePath() must not have
// changed what happens to a handle that never saw a symlink.
func TestFixSymlinkDelete_PlainRenameStillMovesTheFile(t *testing.T) {
	f := newSymlinkFixture(t)
	const content = "ordinary file, ordinary rename"
	f.writeFile("before.txt", content)

	body := mustCreate(t, f.d, f.sess, f.tree, "before.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	if st := f.rename(fid, "after.txt", false); st != smb2.StatusSuccess {
		t.Fatalf("rename = %#x, want success", uint32(st))
	}
	if got, want := f.sess.GetOpen(fid).Path, f.path("after.txt"); got != want {
		t.Errorf("after rename Open.Path = %q, want %q", got, want)
	}
	f.closeOK(fid)

	f.assertGone("before.txt", "rename of a plain file")
	f.assertFileContent("after.txt", content, "rename of a plain file")
}

// TestFixSymlinkDelete_RenameOntoExistingLinkReplacesTheLink settles the
// destination side. POSIX rename(2) does not follow a symlink at the
// destination: the link is unlinked and the file it pointed at is untouched.
// Following it instead would overwrite a file the client never named, which is
// the same class of surprise as the source-side bug.
func TestFixSymlinkDelete_RenameOntoExistingLinkReplacesTheLink(t *testing.T) {
	f := newSymlinkFixture(t)
	const srcContent = "the file being moved"
	const victimContent = "pointed at by the destination link"
	f.writeFile("source.txt", srcContent)
	f.writeFile("victim.txt", victimContent)
	f.symlink("victim.txt", "alias.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "source.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	if st := f.rename(fid, "alias.txt", true); st != smb2.StatusSuccess {
		t.Fatalf("rename onto an existing symlink = %#x, want success", uint32(st))
	}
	f.closeOK(fid)

	// alias.txt is now the moved regular file, not a link.
	st, err := os.Lstat(f.path("alias.txt"))
	if err != nil {
		t.Fatalf("lstat alias.txt: %v", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		t.Error("alias.txt is still a symlink: the rename followed the destination link")
	}
	f.assertFileContent("alias.txt", srcContent, "rename onto an existing symlink")
	// And the file that link pointed at is untouched.
	f.assertFileContent("victim.txt", victimContent, "rename onto an existing symlink")
	f.assertGone("source.txt", "rename onto an existing symlink")
}

// TestFixSymlinkDelete_RenameOntoExistingLinkWithoutReplaceCollides is the
// other half of that decision. Without FILE_RENAME_INFORMATION.ReplaceIfExists
// the destination must be reported as taken, and the check is an Lstat so the
// link counts as an occupant in its own right rather than being judged by
// whatever it points at.
func TestFixSymlinkDelete_RenameOntoExistingLinkWithoutReplaceCollides(t *testing.T) {
	f := newSymlinkFixture(t)
	f.writeFile("source.txt", "src")
	f.writeFile("victim.txt", "victim")
	f.symlink("victim.txt", "alias.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "source.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)
	fid := createFileID(body)
	if st := f.rename(fid, "alias.txt", false); st != smb2.StatusObjectNameCollision {
		t.Fatalf("rename onto an existing symlink without ReplaceIfExists = %#x, want OBJECT_NAME_COLLISION (%#x)",
			uint32(st), uint32(smb2.StatusObjectNameCollision))
	}
	f.closeOK(fid)

	f.assertSymlinkTo("alias.txt", "victim.txt", "refused rename onto a symlink")
	f.assertFileContent("source.txt", "src", "refused rename onto a symlink")
	f.assertFileContent("victim.txt", "victim", "refused rename onto a symlink")
}

// --- the data side must NOT move ---

// TestFixSymlinkDelete_DataOperationsStillReachTheTarget is the constraint the
// fix had to respect. READ, WRITE and QUERY_INFO go on following the link; only
// the two namespace operations were changed. A handle whose size came from the
// link while its bytes came from the target would be a worse bug than the one
// being fixed, because the client would size its reads from a lie.
func TestFixSymlinkDelete_DataOperationsStillReachTheTarget(t *testing.T) {
	f := newSymlinkFixture(t)
	const content = "twenty-nine bytes of payload."
	f.writeFile("target.txt", content)
	f.symlink("target.txt", "link.txt")

	body := mustCreate(t, f.d, f.sess, f.tree, "link.txt",
		smb2.CreateDispositionOpen, 0,
		smb2.AccessFileReadData|smb2.AccessFileWriteData)
	fid := createFileID(body)

	// The CREATE response already reports the target's size, not the link's
	// (which would be len("target.txt") == 10).
	if got, want := createEndOfFile(body), uint64(len(content)); got != want {
		t.Errorf("CREATE EndOfFile = %d, want the target's %d", got, want)
	}

	// QUERY_INFO FileStandardInformation reports the target's size too.
	if got, want := queryStandardEndOfFile(t, f.d, f.sess, fid), uint64(len(content)); got != want {
		t.Errorf("QUERY_INFO EndOfFile = %d, want the target's %d", got, want)
	}

	// READ returns the target's bytes.
	if got := string(readAll(t, f.d, f.sess, fid, uint32(len(content)))); got != content {
		t.Errorf("READ through the link = %q, want %q", got, content)
	}

	// WRITE lands in the target, and the link is still a link afterwards.
	const appended = "APPENDED"
	var out bytes.Buffer
	f.d.handleWrite(&out, smb2.Header{Command: smb2.CommandWrite, TreeID: f.tree.ID},
		buildWriteBody(fid, uint64(len(content)), []byte(appended)), f.sess)
	if st := respStatus(t, &out); st != smb2.StatusSuccess {
		t.Fatalf("WRITE through the link = %#x, want success", uint32(st))
	}
	f.closeOK(fid)

	f.assertFileContent("target.txt", content+appended, "WRITE through a symlink")
	f.assertSymlinkTo("link.txt", "target.txt", "WRITE through a symlink")
}

// queryStandardEndOfFile drives QUERY_INFO FileStandardInformation and returns
// the EndOfFile field (MS-FSCC §2.4.41: AllocationSize(8) EndOfFile(8) ...).
func queryStandardEndOfFile(t *testing.T, d *Dispatcher, sess *Session, fid [16]byte) uint64 {
	t.Helper()
	var out bytes.Buffer
	d.handleQueryInfo(&out, smb2.Header{Command: smb2.CommandQueryInfo},
		buildQueryInfoBody(fid, smb2.InfoTypeFile, smb2.FileStandardInformation, 4096), sess)
	frame := out.Bytes()
	if len(frame) < 4+smb2.HeaderSize+8+16 {
		t.Fatalf("QUERY_INFO: response too short (%d bytes)", len(frame))
	}
	hdr, err := smb2.DecodeHeader(frame[4 : 4+smb2.HeaderSize])
	if err != nil {
		t.Fatalf("QUERY_INFO: decode header: %v", err)
	}
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("QUERY_INFO = %#x, want success", hdr.Status)
	}
	// The response's fixed part is 8 bytes and the payload follows it.
	payload := frame[4+smb2.HeaderSize+8:]
	return binary.LittleEndian.Uint64(payload[8:])
}

// --- share modes and locks stay keyed on the target ---

// TestFixSymlinkDelete_TwoLinksToOneFileStillConflict is the property most
// easily destroyed by fixing this the wrong way. Share modes are whole-file
// mutual exclusion, and they are keyed by (device, inode) from the open
// descriptor precisely so that a file reached under two different names — hard
// links, NFC/NFD spellings, and now two symlinks — lands on one entry. Keying
// them by the handle's name instead would let two clients both take an
// exclusive open on the same file and never see each other.
func TestFixSymlinkDelete_TwoLinksToOneFileStillConflict(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("target.txt", "shared body")
	for _, link := range []string{"first.lnk", "second.lnk"} {
		if err := os.Symlink("target.txt", filepath.Join(f.dir, link)); err != nil {
			t.Fatal(err)
		}
	}

	// A deny-write open through the first link.
	fid := f.mustOpen("first.lnk", wantWrite, denyWrite)
	// A writer arriving through the OTHER link must still be refused.
	f.assertViolation("second.lnk", wantWrite, shareAll)
	// And so must one arriving through the target's own name.
	f.assertViolation("target.txt", wantWrite, shareAll)

	if st := f.close(fid); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
	f.assertNoReservations("closing the link handle")

	// Once released, the same open through the other link is admitted.
	second := f.mustOpen("second.lnk", wantWrite, shareAll)
	if st := f.close(second); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
}

// TestFixSymlinkDelete_LinkAndTargetShareOneLockKey asserts the same identity
// for byte-range locks: the lock manager fstat's the descriptor, so a handle
// opened through a link and one opened on the target are the same file to it.
func TestFixSymlinkDelete_LinkAndTargetShareOneLockKey(t *testing.T) {
	f := newSymlinkFixture(t)
	f.writeFile("target.txt", "shared body")
	f.symlink("target.txt", "link.txt")

	// Both handles have to be open at once, so both tolerate everything: a
	// deny-all pair would be refused by the very check this test is about.
	const rw = smb2.AccessFileReadData | smb2.AccessFileWriteData
	viaLink := f.openShared("link.txt", rw, shareAll)
	viaName := f.openShared("target.txt", rw, shareAll)

	linkOpen := f.sess.GetOpen(viaLink)
	nameOpen := f.sess.GetOpen(viaName)
	if linkOpen == nil || nameOpen == nil {
		t.Fatal("one of the handles is missing")
	}
	linkKey, err := sharedLockManager.keyFor(linkOpen)
	if err != nil {
		t.Fatalf("keyFor(link handle): %v", err)
	}
	nameKey, err := sharedLockManager.keyFor(nameOpen)
	if err != nil {
		t.Fatalf("keyFor(target handle): %v", err)
	}
	if linkKey != nameKey {
		t.Errorf("lock key through the link = %+v, through the target = %+v: locks would not conflict",
			linkKey, nameKey)
	}

	// The share-mode key is built the same way and must agree too.
	linkShare, ok1 := shareKeyForFd(int(linkOpen.File.Fd()))
	nameShare, ok2 := shareKeyForFd(int(nameOpen.File.Fd()))
	if !ok1 || !ok2 {
		t.Fatal("share key could not be built from a descriptor")
	}
	if linkShare != nameShare {
		t.Errorf("share-mode key through the link = %+v, through the target = %+v",
			linkShare, nameShare)
	}

	f.closeOK(viaLink)
	f.closeOK(viaName)
}

// --- a link chain ---

// TestFixSymlinkDelete_ChainedLinkDeletesOnlyTheNamedLink: a -> b -> file. The
// handle's name is `a`, so deleting it removes `a` and leaves both `b` and the
// file. ResolveLink collapses the whole chain to reach the data, which is what
// makes this worth asserting: only the FIRST link is the handle's name.
func TestFixSymlinkDelete_ChainedLinkDeletesOnlyTheNamedLink(t *testing.T) {
	f := newSymlinkFixture(t)
	const content = "at the end of the chain"
	f.writeFile("target.txt", content)
	f.symlink("target.txt", "middle.lnk")
	f.symlink("middle.lnk", "outer.lnk")

	body := mustCreate(t, f.d, f.sess, f.tree, "outer.lnk",
		smb2.CreateDispositionOpen, smb2.CreateOptDeleteOnClose, smb2.AccessFileReadData)
	f.closeOK(createFileID(body))

	f.assertGone("outer.lnk", "DELETE_ON_CLOSE on a chained symlink")
	f.assertSymlinkTo("middle.lnk", "target.txt", "DELETE_ON_CLOSE on a chained symlink")
	f.assertFileContent("target.txt", content, "DELETE_ON_CLOSE on a chained symlink")
}
