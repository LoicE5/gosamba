package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- ShareAccess was decoded and then discarded ---
//
// SMB2 CREATE carries a ShareAccess mask naming the concurrent opens the client
// will tolerate. The server parsed it into CreateRequest.ShareAccess and never
// looked at it again, and kept no per-file open table at all, so two machines
// could both take an exclusive (deny-all) open on the same file and neither was
// told. macOS keeps no cross-client deny-mode bookkeeping of its own —
// smbfs_get_rights_shareMode() turns O_SHLOCK into deny-write and O_EXLOCK into
// deny-all, ships that as ShareAccess, and depends entirely on the server
// answering STATUS_SHARING_VIOLATION (which it maps to EBUSY). Anything using
// deny modes for mutual exclusion over the share — SQLite side files, Office
// lock files, Xcode, photo libraries — raced silently.
//
// These tests drive handleCreate/handleClose directly so the sharing-access
// check (MS-SMB2 §3.3.5.9) and, just as importantly, the release of every
// reservation on every teardown path are both exercised.

// SMB2 DesiredAccess combinations the tests use, spelled out so each case reads
// as the intent rather than a hex literal.
const (
	wantRead      = smb2.AccessFileReadData
	wantWrite     = smb2.AccessFileWriteData
	wantReadWrite = smb2.AccessFileReadData | smb2.AccessFileWriteData
	wantAttrsOnly = smb2.AccessFileReadAttributes
	shareAll      = shareAccessRead | shareAccessWrite | shareAccessDelete
	shareNone     = uint32(0)
	denyWrite     = shareAccessRead | shareAccessDelete
)

// buildCreateBodyShare is buildCreateBody plus the ShareAccess field, which the
// shared helper leaves zero. It is defined here rather than by changing that
// helper so every existing test keeps the exact request it was written against.
func buildCreateBodyShare(name string, disposition, options, access, shareAccess uint32, ctxs []byte) []byte {
	body := buildCreateBody(name, disposition, options, access, ctxs)
	binary.LittleEndian.PutUint32(body[32:], shareAccess)
	return body
}

// shareModeFixture is one share directory plus the dispatcher/session/tree that
// serve it, and a baseline of the process-global table so every test can prove
// it left nothing behind.
type shareModeFixture struct {
	t        *testing.T
	dir      string
	d        *Dispatcher
	sess     *Session
	tree     *Tree
	baseline int
}

func newShareModeFixture(t *testing.T) *shareModeFixture {
	t.Helper()
	dir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, dir)
	return newShareModeFixtureFrom(t, dir, d, sess, tree)
}

// newShareModeFixtureFrom wraps an already-built dispatcher (the durable tests
// need one carrying a Connection) in the same baseline/leak bookkeeping.
func newShareModeFixtureFrom(t *testing.T, dir string, d *Dispatcher, sess *Session, tree *Tree) *shareModeFixture {
	t.Helper()
	f := &shareModeFixture{t: t, dir: dir, d: d, sess: sess, tree: tree,
		baseline: sharedShareModes.len()}
	// The share-mode table is process-global (it has to be, or two clients
	// never see each other), so a test that leaves an entry behind would
	// poison every later test. Fail loudly instead.
	t.Cleanup(func() {
		if got := sharedShareModes.len(); got != f.baseline {
			t.Errorf("share-mode table holds %d reservations at test end, want %d: a handle leaked",
				got, f.baseline)
		}
	})
	return f
}

// assertNoReservations checks the process-global table is back to its baseline
// RIGHT NOW, with no reopen in between.
//
// This is the assertion that actually catches a leaked entry. "The file is
// openable again" is not enough on its own: acquire sweeps entries whose owner
// has lost its descriptor, so a disposal path that forgot to release would
// still let the next CREATE through and hide the bug. That sweep is a safety
// net for production, not a substitute for releasing, and the tests must be
// able to tell the difference.
func (f *shareModeFixture) assertNoReservations(after string) {
	f.t.Helper()
	if got := sharedShareModes.len(); got != f.baseline {
		f.t.Fatalf("share-mode table holds %d reservations after %s, want %d: the handle leaked its entry",
			got, after, f.baseline)
	}
}

// writeFile drops a regular file into the share and returns its OS path.
func (f *shareModeFixture) writeFile(name, content string) string {
	f.t.Helper()
	p := filepath.Join(f.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// open issues a CREATE with an explicit DesiredAccess/ShareAccess pair and
// returns the status plus the FileID on success.
func (f *shareModeFixture) open(name string, access, share uint32) (smb2.Status, [16]byte) {
	f.t.Helper()
	return f.openDisposition(name, smb2.CreateDispositionOpen, access, share)
}

func (f *shareModeFixture) openDisposition(name string, disposition, access, share uint32) (smb2.Status, [16]byte) {
	f.t.Helper()
	var buf bytes.Buffer
	f.d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: f.tree.ID},
		buildCreateBodyShare(name, disposition, 0, access, share, nil), f.sess)
	hdr, resp, _ := readCreateResponse(f.t, &buf)
	return smb2.Status(hdr.Status), resp.FileID
}

// mustOpen fails the test unless the CREATE succeeded.
func (f *shareModeFixture) mustOpen(name string, access, share uint32) [16]byte {
	f.t.Helper()
	st, fid := f.open(name, access, share)
	if st != smb2.StatusSuccess {
		f.t.Fatalf("CREATE %s (access=%#x share=%#x) = %#x, want success", name, access, share, uint32(st))
	}
	return fid
}

// close issues a CLOSE for fid and returns the status.
func (f *shareModeFixture) close(fid [16]byte) smb2.Status {
	f.t.Helper()
	var buf bytes.Buffer
	f.d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose, TreeID: f.tree.ID},
		buildCloseBody(fid), f.sess)
	return respStatus(f.t, &buf)
}

// assertShared asserts a CREATE is admitted; assertViolation asserts it is
// refused with STATUS_SHARING_VIOLATION specifically — a generic ACCESS_DENIED
// would not reach macOS as EBUSY.
func (f *shareModeFixture) assertViolation(name string, access, share uint32) {
	f.t.Helper()
	st, _ := f.open(name, access, share)
	if st != smb2.StatusSharingViolation {
		f.t.Fatalf("CREATE %s (access=%#x share=%#x) = %#x, want STATUS_SHARING_VIOLATION (%#x)",
			name, access, share, uint32(st), uint32(smb2.StatusSharingViolation))
	}
}

// TestFixShareMode_ShareAllOpensCoexist is the baseline: the overwhelmingly
// common case is a client that tolerates everything, and it must stay free.
// A false STATUS_SHARING_VIOLATION breaks ordinary use far more visibly than
// the missing check ever did.
func TestFixShareMode_ShareAllOpensCoexist(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("doc.txt", "body")

	first := f.mustOpen("doc.txt", wantReadWrite, shareAll)
	second := f.mustOpen("doc.txt", wantReadWrite, shareAll)
	if first == second {
		t.Fatal("the two opens got the same FileID")
	}
	if f.close(first) != smb2.StatusSuccess || f.close(second) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_ExclusiveOpenBlocksReader is the core regression: an
// O_EXLOCK open (ShareAccess 0, deny-all) must refuse the next opener. Before
// the fix both CREATEs succeeded and neither client was told.
func TestFixShareMode_ExclusiveOpenBlocksReader(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("locked.txt", "body")

	exclusive := f.mustOpen("locked.txt", wantReadWrite, shareNone)
	f.assertViolation("locked.txt", wantRead, shareAll)
	// A refused CREATE must not record anything, or one rejected open would
	// leave the file unopenable even after the real holder lets go.
	if got := sharedShareModes.len(); got != f.baseline+1 {
		t.Fatalf("table holds %d reservations after one grant and one refusal, want %d",
			got, f.baseline+1)
	}
	if f.close(exclusive) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_DenyWriteAllowsReaderRefusesWriter covers O_SHLOCK: the
// holder shares read and delete but not write, so a reader gets in and a writer
// does not. Collapsing the mask to a single "is it exclusive" flag would fail
// the first half of this.
func TestFixShareMode_DenyWriteAllowsReaderRefusesWriter(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("shlock.txt", "body")

	holder := f.mustOpen("shlock.txt", wantWrite, denyWrite)

	reader := f.mustOpen("shlock.txt", wantRead, shareAll)
	f.assertViolation("shlock.txt", wantWrite, shareAll)

	if f.close(reader) != smb2.StatusSuccess || f.close(holder) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_NewShareAccessMustTolerateExistingOpen exercises the second
// half of §3.3.5.9, the direction that is easy to forget: the check runs BOTH
// ways. Here the existing open shares everything, but the newcomer refuses to
// tolerate a writer — and a writer is exactly what is already there.
func TestFixShareMode_NewShareAccessMustTolerateExistingOpen(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("rw.txt", "body")

	// The incumbent is permissive; it is what it DOES that conflicts.
	incumbent := f.mustOpen("rw.txt", wantReadWrite, shareAll)

	// deny-write newcomer: it only wants to read, so the forward check passes.
	// It must still be refused, because it will not tolerate the writer that is
	// already there.
	f.assertViolation("rw.txt", wantRead, denyWrite)

	// Prove it is specifically the write side: a newcomer that denies nothing
	// gets in against the same incumbent.
	tolerant := f.mustOpen("rw.txt", wantRead, shareAll)

	if f.close(tolerant) != smb2.StatusSuccess || f.close(incumbent) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_DeleteAccessHonoursShareDelete checks the third bit. DELETE
// is what a rename or delete-on-close needs, and FILE_SHARE_DELETE is the bit
// Office and SQLite manipulate most deliberately.
func TestFixShareMode_DeleteAccessHonoursShareDelete(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("del.txt", "body")

	// Shares read and write but not delete.
	holder := f.mustOpen("del.txt", wantRead, shareAccessRead|shareAccessWrite)

	f.assertViolation("del.txt", accDelete, shareAll)
	// A plain reader is unaffected.
	reader := f.mustOpen("del.txt", wantRead, shareAll)

	if f.close(reader) != smb2.StatusSuccess || f.close(holder) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_AttributeOnlyOpenIsNotBlocked pins the permissive edge of
// the classification. A stat-style open asks for FILE_READ_ATTRIBUTES only; it
// touches no data, so it must not be refused by a deny-all holder. macOS issues
// these constantly (Finder, Spotlight) and refusing them would make an
// exclusively-opened file undisplayable rather than merely unopenable.
func TestFixShareMode_AttributeOnlyOpenIsNotBlocked(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("attrs.txt", "body")

	exclusive := f.mustOpen("attrs.txt", wantReadWrite, shareNone)
	stat := f.mustOpen("attrs.txt", wantAttrsOnly, shareAll)

	if f.close(stat) != smb2.StatusSuccess || f.close(exclusive) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_CloseReleasesTheRestriction proves the deny mode is a
// property of the live handle and not of the file: once the exclusive holder
// closes, the next opener gets in.
func TestFixShareMode_CloseReleasesTheRestriction(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("temp.txt", "body")

	exclusive := f.mustOpen("temp.txt", wantReadWrite, shareNone)
	f.assertViolation("temp.txt", wantRead, shareAll)

	if st := f.close(exclusive); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
	f.assertNoReservations("CLOSE")

	after := f.mustOpen("temp.txt", wantReadWrite, shareNone)
	if st := f.close(after); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
}

// TestFixShareMode_DeleteOnCloseStillReleases guards the CLOSE path that has
// its own early exits. A delete-on-close handle unlinks the file and returns
// from a different branch than the ordinary one; the reservation must be gone
// either way, or a path whose inode gets recycled becomes unopenable.
func TestFixShareMode_DeleteOnCloseStillReleases(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("doomed.txt", "body")

	var buf bytes.Buffer
	f.d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: f.tree.ID},
		buildCreateBodyShare("doomed.txt", smb2.CreateDispositionOpen,
			smb2.CreateOptDeleteOnClose, wantReadWrite, shareNone, nil), f.sess)
	hdr, resp, _ := readCreateResponse(t, &buf)
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("CREATE = %#x, want success", hdr.Status)
	}
	if st := f.close(resp.FileID); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
	if _, err := os.Lstat(filepath.Join(f.dir, "doomed.txt")); !os.IsNotExist(err) {
		t.Fatalf("delete-on-close did not remove the file: %v", err)
	}
	f.assertNoReservations("a delete-on-close CLOSE")
	// The fixture's cleanup asserts the table is back to its baseline.
}

// TestFixShareMode_RefusedOverwriteDoesNotTruncate is why the check runs before
// the disposition is applied. FILE_OVERWRITE truncates the file before any
// descriptor is opened, so a CREATE that checked its share mode only at the end
// would empty a file another client holds exclusively and *then* refuse it —
// destroying data on the way out.
func TestFixShareMode_RefusedOverwriteDoesNotTruncate(t *testing.T) {
	f := newShareModeFixture(t)
	path := f.writeFile("precious.txt", "important bytes")

	exclusive := f.mustOpen("precious.txt", wantReadWrite, shareNone)

	st, _ := f.openDisposition("precious.txt", smb2.CreateDispositionOverwrite, wantWrite, shareAll)
	if st != smb2.StatusSharingViolation {
		t.Fatalf("overwriting CREATE = %#x, want STATUS_SHARING_VIOLATION", uint32(st))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "important bytes" {
		t.Fatalf("file contents = %q; the refused CREATE truncated it anyway", b)
	}

	// The pre-check must not swallow more specific answers. FILE_CREATE on an
	// existing name is a collision whether or not anyone else holds the file.
	if st, _ := f.openDisposition("precious.txt", smb2.CreateDispositionCreate, wantWrite, shareAll); st != smb2.StatusObjectNameCollision {
		t.Fatalf("FILE_CREATE over an existing name = %#x, want STATUS_OBJECT_NAME_COLLISION", uint32(st))
	}
	if f.close(exclusive) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_HardLinksConflict is why the table is keyed by (device,
// inode) and not by path. One file with two names is still one file: an
// exclusive open under either name must block the other. A path-keyed table
// would let the same file be opened exclusively twice, which is the original
// bug wearing a different hat. The normalization-insensitive resolver makes the
// same point for a single name that arrives as NFC or NFD.
func TestFixShareMode_HardLinksConflict(t *testing.T) {
	f := newShareModeFixture(t)
	primary := f.writeFile("primary.txt", "body")
	alias := filepath.Join(f.dir, "alias.txt")
	if err := os.Link(primary, alias); err != nil {
		t.Skipf("filesystem does not support hard links: %v", err)
	}

	exclusive := f.mustOpen("primary.txt", wantReadWrite, shareNone)
	f.assertViolation("alias.txt", wantRead, shareAll)

	if f.close(exclusive) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
	// And the other way round, to prove neither name is privileged.
	viaAlias := f.mustOpen("alias.txt", wantReadWrite, shareNone)
	f.assertViolation("primary.txt", wantRead, shareAll)
	if f.close(viaAlias) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_DirectoriesAreNotSerialised pins the deliberate exemption.
// macOS opens directories constantly — enumeration, CHANGE_NOTIFY, the tree
// root — and honouring a directory deny mode would risk serialising ordinary
// browsing across every client on the share. Nothing in the deny-mode use cases
// this check exists for is a directory.
func TestFixShareMode_DirectoriesAreNotSerialised(t *testing.T) {
	f := newShareModeFixture(t)
	if err := os.Mkdir(filepath.Join(f.dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	first := f.mustOpen("sub", wantReadWrite, shareNone)
	second := f.mustOpen("sub", wantReadWrite, shareNone)
	if f.close(first) != smb2.StatusSuccess || f.close(second) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_TreeDisconnectReleases proves the TREE_DISCONNECT arm of
// disposal releases reservations. A client that disconnects the tree without
// closing its handles (which is legal) must not leave the file unopenable.
func TestFixShareMode_TreeDisconnectReleases(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("held.txt", "body")

	f.mustOpen("held.txt", wantReadWrite, shareNone)
	f.assertViolation("held.txt", wantRead, shareAll)

	var buf bytes.Buffer
	f.d.handleTreeDisconnect(&buf, smb2.Header{Command: smb2.CommandTreeDisconnect, TreeID: f.tree.ID},
		[]byte{0x04, 0x00, 0x00, 0x00}, f.sess)
	if st := respStatus(t, &buf); st != smb2.StatusSuccess {
		t.Fatalf("TREE_DISCONNECT = %#x, want success", uint32(st))
	}
	f.assertNoReservations("TREE_DISCONNECT")

	// A fresh tree on the same share, as a reconnecting client would use.
	f.tree = f.sess.AddTree(config.ShareConfig{Name: "share", Path: f.dir})
	again := f.mustOpen("held.txt", wantReadWrite, shareNone)
	if f.close(again) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_LogoffReleases proves the LOGOFF arm of disposal releases
// reservations.
func TestFixShareMode_LogoffReleases(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("held.txt", "body")

	f.mustOpen("held.txt", wantReadWrite, shareNone)
	f.assertViolation("held.txt", wantRead, shareAll)

	var buf bytes.Buffer
	f.d.handleLogoff(&buf, smb2.Header{Command: smb2.CommandLogoff}, f.sess)
	if st := respStatus(t, &buf); st != smb2.StatusSuccess {
		t.Fatalf("LOGOFF = %#x, want success", uint32(st))
	}
	f.assertNoReservations("LOGOFF")

	// LOGOFF drops every tree too, so a new session/tree stands in for the
	// client's reconnect.
	f.sess = &Session{}
	f.tree = f.sess.AddTree(config.ShareConfig{Name: "share", Path: f.dir})
	again := f.mustOpen("held.txt", wantReadWrite, shareNone)
	if f.close(again) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_ConnectionDropReleases drives the real connection-teardown
// disposal (releaseConnOpens, which is what ServeConn defers) rather than a
// reimplementation of it. A client whose TCP connection dies without closing
// anything is the commonest way handles are disposed of, and a reservation left
// behind here would make the file unopenable for the life of the process.
func TestFixShareMode_ConnectionDropReleases(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("held.txt", "body")

	// A session reachable through a SessionTable, the way ServeConn holds it.
	sessions := NewSessionTable()
	dropped := sessions.New()
	dropped.Authenticated = true
	f.sess = dropped
	f.tree = dropped.AddTree(config.ShareConfig{Name: "share", Path: f.dir})

	f.mustOpen("held.txt", wantReadWrite, shareNone)

	// A second, surviving session must still be refused while the first lives.
	survivor := &Session{}
	surviving := &shareModeFixture{t: t, dir: f.dir, d: f.d, sess: survivor,
		tree: survivor.AddTree(config.ShareConfig{Name: "share", Path: f.dir})}
	surviving.assertViolation("held.txt", wantRead, shareAll)

	releaseConnOpens(sessions, nil)
	f.assertNoReservations("the connection dropping")

	fid := surviving.mustOpen("held.txt", wantReadWrite, shareNone)
	if surviving.close(fid) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_DurableExpiryReleases proves the last disposal path. A
// durable handle keeps its deny mode while it is reclaimable — it is still an
// open per MS-SMB2 §3.3.5.9 — but once the entry expires the reservation must
// go with the descriptor. Nothing else can reach that Open, so an entry left
// here could never be released by anyone.
func TestFixShareMode_DurableExpiryReleases(t *testing.T) {
	f := newShareModeFixture(t)
	f.writeFile("durable.txt", "body")

	fid := f.mustOpen("durable.txt", wantReadWrite, shareNone)
	open := f.sess.GetOpen(fid)
	if open == nil {
		t.Fatal("CREATE did not register the open")
	}

	// Stand the handle up as a durable entry the way applyDurableAndLease
	// would, then drop the connection: the entry detaches and keeps the mode.
	tbl := NewDurableTable()
	var clientGuid, createGuid [16]byte
	createGuid[0] = 0x5A
	open.IsDurable = true
	open.DurableClientGuid = clientGuid
	open.DurableCreateGuid = createGuid
	if !tbl.Register(clientGuid, createGuid, open, time.Minute, "share", "alice") {
		t.Fatal("Register refused a fresh durable entry")
	}

	sessions := NewSessionTable()
	held := sessions.New()
	held.AddOpen(open)
	releaseConnOpens(sessions, tbl)

	// Still reclaimable, so still holding its deny mode.
	other := &Session{}
	waiting := &shareModeFixture{t: t, dir: f.dir, d: f.d, sess: other,
		tree: other.AddTree(config.ShareConfig{Name: "share", Path: f.dir})}
	waiting.assertViolation("durable.txt", wantRead, shareAll)

	if n := tbl.Expire(time.Now().Add(2 * time.Minute)); n != 1 {
		t.Fatalf("Expire evicted %d entries, want 1", n)
	}
	f.assertNoReservations("durable-handle expiry")
	reopened := waiting.mustOpen("durable.txt", wantReadWrite, shareNone)
	if waiting.close(reopened) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
	// Drop the session's stale handle so the fixture's baseline check is about
	// the share-mode table and nothing else.
	f.sess.RemoveOpen(fid)
}

// TestFixShareMode_DurableReclaimKeepsOneEntry drives the real DH2C reconnect
// path end to end. A reclaimed durable handle is the SAME open continuing, so
// it must keep its deny mode across the reconnect — and it must hold exactly
// one reservation afterwards, not two. Releasing and re-acquiring would fail
// both halves: it opens a window for another client to take a conflicting mode,
// and a reclaim that then bailed out (the file turned read-only, the name
// vanished) would strand the entry on a handle that no longer exists.
func TestFixShareMode_DurableReclaimKeepsOneEntry(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree, tbl := newDurableDispatcher(t, shareDir)
	f := newShareModeFixtureFrom(t, shareDir, d, sess, tree)
	f.writeFile("reclaim.txt", "body")

	// A rival client on its own session, used throughout to observe the mode.
	rivalSess := &Session{}
	rival := &shareModeFixture{t: t, dir: shareDir, d: d, sess: rivalSess,
		tree: rivalSess.AddTree(d.Shares[0]), baseline: f.baseline}

	// --- durable, deny-all CREATE ---
	var dh2q [32]byte
	binary.LittleEndian.PutUint32(dh2q[0:], 30000)
	var createGuid [16]byte
	createGuid[0] = 0x9E
	copy(dh2q[16:32], createGuid[:])
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2Q, Data: dh2q[:]}})

	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBodyShare("reclaim.txt", smb2.CreateDispositionOpen, 0,
			wantReadWrite, shareNone, ctxs), sess)
	hdr, resp, _ := readCreateResponse(t, &buf)
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("durable CREATE = %#x, want success", hdr.Status)
	}
	if got := sharedShareModes.len(); got != f.baseline+1 {
		t.Fatalf("table holds %d reservations after one CREATE, want %d", got, f.baseline+1)
	}
	rival.assertViolation("reclaim.txt", wantRead, shareAll)

	// --- the connection drops: the durable entry detaches and KEEPS the mode ---
	sess.RemoveOpen(resp.FileID)
	tbl.Detach(d.Conn.ClientGuid, createGuid)
	rival.assertViolation("reclaim.txt", wantRead, shareAll)

	// --- reconnect with DH2C ---
	var dh2c [36]byte
	copy(dh2c[0:16], resp.FileID[:])
	copy(dh2c[16:32], createGuid[:])
	reconnectCtxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2C, Data: dh2c[:]}})
	sess2 := &Session{}
	tree2 := sess2.AddTree(d.Shares[0])

	var buf2 bytes.Buffer
	d.handleCreate(&buf2, smb2.Header{Command: smb2.CommandCreate, TreeID: tree2.ID},
		buildCreateBodyShare("reclaim.txt", smb2.CreateDispositionOpen, 0,
			wantReadWrite, shareNone, reconnectCtxs), sess2)
	hdr2, resp2, _ := readCreateResponse(t, &buf2)
	if smb2.Status(hdr2.Status) != smb2.StatusSuccess {
		t.Fatalf("DH2C reconnect = %#x, want success", hdr2.Status)
	}
	if resp2.FileID != resp.FileID {
		t.Fatalf("reclaimed FileID = %x, want %x", resp2.FileID, resp.FileID)
	}

	// Exactly one reservation: the reclaim moved it, it did not add a second.
	if got := sharedShareModes.len(); got != f.baseline+1 {
		t.Fatalf("table holds %d reservations after the reclaim, want %d: the reclaim duplicated the entry",
			got, f.baseline+1)
	}
	// And it followed the new handle, so the rival is still refused.
	rival.assertViolation("reclaim.txt", wantRead, shareAll)

	// --- closing the reclaimed handle frees the file for everyone ---
	f.sess, f.tree = sess2, tree2
	if st := f.close(resp2.FileID); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE of the reclaimed handle = %#x, want success", uint32(st))
	}
	f.assertNoReservations("closing a reclaimed durable handle")
	after := rival.mustOpen("reclaim.txt", wantReadWrite, shareNone)
	if rival.close(after) != smb2.StatusSuccess {
		t.Fatal("CLOSE failed")
	}
}

// TestFixShareMode_ConcurrentOpensAndCloses is the -race guard. The table is
// process-global and every CREATE and every teardown path touches it, so the
// test-and-insert has to be atomic: two clients racing on the same file must
// not both be admitted, and nothing may be left behind when the dust settles.
func TestFixShareMode_ConcurrentOpensAndCloses(t *testing.T) {
	f := newShareModeFixture(t)
	const files = 4
	for i := 0; i < files; i++ {
		f.writeFile(string(rune('a'+i))+".txt", "body")
	}

	const workers = 24
	const rounds = 40
	// Each goroutine gets its own Session: Session.mu would otherwise serialise
	// the very concurrency this test is trying to create.
	var wg sync.WaitGroup
	var exclusiveWins, refusals int64
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			sess := &Session{}
			tree := sess.AddTree(config.ShareConfig{Name: "share", Path: f.dir})
			local := &shareModeFixture{t: t, dir: f.dir, d: &Dispatcher{Log: f.d.Log, Shares: f.d.Shares},
				sess: sess, tree: tree}
			for r := 0; r < rounds; r++ {
				name := string(rune('a'+(w+r)%files)) + ".txt"
				// Alternate deny-all and share-all so both the conflict and
				// the no-conflict paths run concurrently on the same inodes.
				share := shareAll
				if (w+r)%3 == 0 {
					share = shareNone
				}
				st, fid := local.open(name, wantReadWrite, share)
				switch st {
				case smb2.StatusSuccess:
					if share == shareNone {
						mu.Lock()
						exclusiveWins++
						mu.Unlock()
					}
					if cs := local.close(fid); cs != smb2.StatusSuccess {
						t.Errorf("CLOSE = %#x, want success", uint32(cs))
						return
					}
				case smb2.StatusSharingViolation:
					mu.Lock()
					refusals++
					mu.Unlock()
				default:
					t.Errorf("CREATE %s = %#x, want success or sharing violation", name, uint32(st))
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if exclusiveWins == 0 {
		t.Error("no exclusive open ever succeeded; the test never exercised the grant path")
	}
	if refusals == 0 {
		t.Error("no open was ever refused; the test never exercised the conflict path")
	}
	// The fixture's cleanup asserts every reservation was released.
}
