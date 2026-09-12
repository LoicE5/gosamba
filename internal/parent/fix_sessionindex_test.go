package parent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/ntlm"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// Cross-connection PreviousSessionId (MS-SMB2 §3.3.5.5.3).
//
// The case these tests exist for is the one macOS actually hits: the client's
// own side breaks (a Wi-Fi flap), it reconnects on a NEW TCP connection while
// the server still believes the old one is alive, and names the old session in
// PreviousSessionId. Everything that session was holding — descriptors,
// byte-range locks, share-mode reservations, server-side-copy resume keys,
// durable-handle entries and CHANGE_NOTIFY registrations — has to be released
// there and then, or those reservations block the very client that reconnected.
//
// Every assertion below counts the owning table directly. "The file is openable
// again" is deliberately NOT used as a proxy: a previous agent established that
// it still passes with the release removed.

// --- fixture ----------------------------------------------------------------

// idxFixture is one server: a share, the server-scoped session index and the
// server-scoped durable table, with connections hung off it.
type idxFixture struct {
	dir   string
	share config.ShareConfig
	index *SessionIndex
	dur   *DurableTable
	users []config.UserConfig
}

func newIdxFixture(t *testing.T) *idxFixture {
	t.Helper()
	dir := t.TempDir()
	return &idxFixture{
		dir:   dir,
		share: config.ShareConfig{Name: "share", Path: dir},
		index: NewSessionIndex(),
		dur:   NewDurableTable(),
		users: fixSessionUsers(),
	}
}

// idxConn is one TCP connection on that server: its own session table,
// dispatcher and Connection, all registered in the shared index — exactly the
// shape ServeConn builds.
type idxConn struct {
	hs *fixCryptoHarness
	f  *idxFixture
}

func (f *idxFixture) connect(t *testing.T) *idxConn {
	t.Helper()
	hs := newFixCryptoHarnessIndexed(t, smb2.CipherAES256GCM, f.users, f.index)
	hs.conn.MaxIOSize = 1 << 20
	hs.conn.Durable = f.dur
	hs.conn.DurableTimeout = time.Minute
	hs.disp.Shares = []config.ShareConfig{f.share}
	hs.h.Shares = []config.ShareConfig{f.share}
	return &idxConn{hs: hs, f: f}
}

// auth runs a complete NTLM handshake on this connection, naming prev in
// PreviousSessionId, and returns the session plus a tree on the share.
func (c *idxConn) auth(t *testing.T, msgID uint64, user, pw string, prev uint64) (*Session, *Tree) {
	t.Helper()
	sess := fixSessionAuthenticate(t, c.hs, msgID, user, pw, prev)
	return sess, sess.AddTree(c.f.share)
}

// create issues a real CREATE through the connection's dispatcher and returns
// the granted handle. Going through handleCreate rather than fabricating an
// *Open is the point: it is what registers the share-mode reservation, and a
// fabricated handle would make the reservation assertions vacuous.
func (c *idxConn) create(t *testing.T, sess *Session, tree *Tree, name string,
	access, shareAccess uint32, ctxs []byte) *Open {
	t.Helper()
	body := buildCreateBodyShare(name, smb2.CreateDispositionOpenIf, 0, access, shareAccess, ctxs)
	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandCreate, SessionID: sess.ID, TreeID: tree.ID}
	if !c.hs.disp.handleCreate(&buf, hdr, body, sess) {
		t.Fatalf("create %q returned false", name)
	}
	rhdr, resp, _ := readCreateResponse(t, &buf)
	if smb2.Status(rhdr.Status) != smb2.StatusSuccess {
		t.Fatalf("create %q: status 0x%08X", name, rhdr.Status)
	}
	open := sess.GetOpen(resp.FileID)
	if open == nil {
		t.Fatalf("create %q: handle missing from the session", name)
	}
	return open
}

// --- direct table probes ----------------------------------------------------
//
// Each of these reads the table that actually owns the resource, so a missing
// release is visible as a count rather than inferred from behaviour.

func shareModeHeld(o *Open) bool {
	sharedShareModes.mu.Lock()
	defer sharedShareModes.mu.Unlock()
	_, ok := sharedShareModes.owners[o]
	return ok
}

// lockKeyOf snapshots a handle's (dev, ino) while it still has a descriptor, so
// its byte-range ranges can be counted after the descriptor is gone.
func lockKeyOf(t *testing.T, o *Open) fileKey {
	t.Helper()
	key, err := sharedLockManager.keyFor(o)
	if err != nil {
		t.Fatalf("fstat for the lock key: %v", err)
	}
	return key
}

func lockRangesOwnedBy(key fileKey, o *Open) int {
	l := sharedLockManager.tbl
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.t.locks[key] {
		if r.owner == o {
			n++
		}
	}
	return n
}

func notifyRegCount(d *Dispatcher) int {
	at := d.asyncTable()
	at.mu.Lock()
	defer at.mu.Unlock()
	return len(at.regs)
}

// waitFor polls cond until it holds or the deadline passes. Used for the
// registrations an async goroutine retires on its own way out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// --- a session loaded with one of everything --------------------------------

// idxLoaded is a session on connection A holding every kind of resource the
// teardown checklist covers, plus the baselines needed to prove each one came
// back.
type idxLoaded struct {
	conn    *idxConn
	sess    *Session
	tree    *Tree
	file    *Open // ordinary handle: fd + share-mode reservation + byte-range lock + resume key
	dir     *Open // directory handle with a CHANGE_NOTIFY outstanding
	durable *Open // durable handle: durable-table entry
	lockKey fileKey

	baseShareModes int
	baseLockRanges int64
}

// loadSession gives a fresh session on c every resource in the checklist.
func loadSession(t *testing.T, c *idxConn, msgID uint64, user, pw string) *idxLoaded {
	t.Helper()
	l := &idxLoaded{conn: c}
	l.baseShareModes = sharedShareModes.len()
	l.baseLockRanges = sharedLockManager.tbl.n.Load()

	l.sess, l.tree = c.auth(t, msgID, user, pw, 0)

	// 1. An ordinary file handle. Deny-all sharing, so its reservation is the
	//    kind that makes the file unopenable by anyone else until released.
	name := fmt.Sprintf("held-%d.bin", l.sess.ID)
	if err := os.WriteFile(filepath.Join(c.f.dir, name), bytes.Repeat([]byte("x"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	l.file = c.create(t, l.sess, l.tree, name,
		smb2.AccessGenericRead|smb2.AccessGenericWrite, 0, nil)
	if l.file.File == nil {
		t.Fatal("the file handle has no descriptor")
	}
	if !shareModeHeld(l.file) {
		t.Fatal("CREATE did not register a share-mode reservation; the teardown assertions would be vacuous")
	}
	l.lockKey = lockKeyOf(t, l.file)

	// 2. A byte-range lock on it.
	var lbuf bytes.Buffer
	lockBody := encodeLockBody(l.file.FileID, []lockElemSpec{
		{offset: 0, length: 128, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
	})
	if !c.hs.disp.handleLock(&lbuf, smb2.Header{Command: smb2.CommandLock,
		SessionID: l.sess.ID, MessageID: msgID + 100}, lockBody, l.sess) {
		t.Fatal("handleLock returned false")
	}
	if got := frameStatus(t, &lbuf); got != smb2.StatusSuccess {
		t.Fatalf("LOCK status = 0x%08X, want SUCCESS", uint32(got))
	}
	if lockRangesOwnedBy(l.lockKey, l.file) != 1 {
		t.Fatal("the byte-range lock was not recorded; the teardown assertions would be vacuous")
	}

	// 3. A server-side-copy resume key naming it.
	var ibuf bytes.Buffer
	ioctlBody := buildIoctlBody(smb2.FsctlSrvRequestResumeKey, l.file.FileID, nil)
	if !c.hs.disp.handleIoctl(&ibuf, smb2.Header{Command: smb2.CommandIoctl,
		SessionID: l.sess.ID, TreeID: l.tree.ID}, ioctlBody, l.sess) {
		t.Fatal("resume-key IOCTL returned false")
	}
	if got := frameStatus(t, &ibuf); got != smb2.StatusSuccess {
		t.Fatalf("resume-key IOCTL status = 0x%08X, want SUCCESS", uint32(got))
	}
	if c.hs.conn.resumeKeys.len() != 1 {
		t.Fatal("no resume key was issued; the teardown assertions would be vacuous")
	}

	// 4. A durable handle, so there is a durable-table entry to retire.
	durName := fmt.Sprintf("durable-%d.bin", l.sess.ID)
	if err := os.WriteFile(filepath.Join(c.f.dir, durName), []byte("durable"), 0o644); err != nil {
		t.Fatal(err)
	}
	var dh2q [32]byte
	binary.LittleEndian.PutUint32(dh2q[0:], 30000)
	var createGuid [16]byte
	createGuid[0], createGuid[1] = 0xD0, byte(l.sess.ID)
	copy(dh2q[16:32], createGuid[:])
	l.durable = c.create(t, l.sess, l.tree, durName,
		smb2.AccessGenericRead, shareAccessRead|shareAccessWrite|shareAccessDelete,
		smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2Q, Data: dh2q[:]}}))
	if !l.durable.IsDurable {
		t.Fatal("the durable CREATE was not granted; the teardown assertions would be vacuous")
	}
	if c.f.dur.len() == 0 {
		t.Fatal("no durable-table entry was registered")
	}

	// 5. A directory handle with an outstanding CHANGE_NOTIFY.
	dirName := fmt.Sprintf("watched-%d", l.sess.ID)
	if err := os.Mkdir(filepath.Join(c.f.dir, dirName), 0o755); err != nil {
		t.Fatal(err)
	}
	l.dir = c.create(t, l.sess, l.tree, dirName,
		smb2.AccessGenericRead, shareAccessRead|shareAccessWrite|shareAccessDelete,
		nil)
	if !l.dir.IsDir {
		t.Fatal("the directory CREATE did not produce a directory handle")
	}
	notifyBody := buildChangeNotifyBody(l.dir.FileID, 0, 64*1024, smb2.NotifyFileName)
	if !c.hs.disp.handleChangeNotify(&syncWriter{}, smb2.Header{Command: smb2.CommandChangeNotify,
		SessionID: l.sess.ID, MessageID: msgID + 200}, notifyBody, l.sess) {
		t.Fatal("handleChangeNotify returned false")
	}
	waitFor(t, "the CHANGE_NOTIFY to register", func() bool { return notifyRegCount(c.hs.disp) == 1 })

	if l.sess.OpenCount() != 3 {
		t.Fatalf("session holds %d opens, want 3", l.sess.OpenCount())
	}
	return l
}

// assertFullyReleased checks every table in the teardown checklist.
func (l *idxLoaded) assertFullyReleased(t *testing.T) {
	t.Helper()

	if l.sess.OpenCount() != 0 {
		t.Errorf("the superseded session still holds %d opens", l.sess.OpenCount())
	}
	// Descriptors. releaseOpens nils File after closing it, so a non-nil File
	// here is a descriptor that was never closed.
	for _, o := range []*Open{l.file, l.durable} {
		if o.File != nil {
			t.Errorf("%s: descriptor was not closed", filepath.Base(o.Path))
		}
	}
	// Byte-range locks, counted against the file identity captured earlier.
	if n := lockRangesOwnedBy(l.lockKey, l.file); n != 0 {
		t.Errorf("%d byte-range lock(s) still held by the superseded handle", n)
	}
	if got := sharedLockManager.tbl.n.Load(); got != l.baseLockRanges {
		t.Errorf("process lock table holds %d ranges, want the baseline %d", got, l.baseLockRanges)
	}
	// Share-mode reservations. A leaked one makes the file unopenable by every
	// client on every connection for the life of the process.
	for _, o := range []*Open{l.file, l.durable} {
		if shareModeHeld(o) {
			t.Errorf("%s: share-mode reservation was not released", filepath.Base(o.Path))
		}
	}
	if got := sharedShareModes.len(); got != l.baseShareModes {
		t.Errorf("share-mode table holds %d reservations, want the baseline %d", got, l.baseShareModes)
	}
	// Server-side-copy resume keys, on the OWNING connection's table.
	if got := l.conn.hs.conn.resumeKeys.len(); got != 0 {
		t.Errorf("%d resume key(s) outlived the session that was issued them", got)
	}
	// Durable-handle entries.
	if got := l.conn.f.dur.len(); got != 0 {
		t.Errorf("durable table holds %d entries, want 0", got)
	}
	// CHANGE_NOTIFY registrations, on the OWNING connection's async table. The
	// registration is retired by the watching goroutine as it exits, so this is
	// also the proof that goroutine was woken rather than left blocked forever.
	waitFor(t, "the CHANGE_NOTIFY registration to be retired",
		func() bool { return notifyRegCount(l.conn.hs.disp) == 0 })
	// The session itself.
	if l.conn.f.index.get(l.sess.ID) != nil {
		t.Error("the superseded session is still in the server index")
	}
	if l.conn.hs.h.Sessions.Get(l.sess.ID) != nil {
		t.Error("the superseded SessionId is still usable on its own connection")
	}
}

// assertNothingReleased is the negative of the above, for the refusal paths.
func (l *idxLoaded) assertNothingReleased(t *testing.T, what string) {
	t.Helper()
	if l.sess.OpenCount() != 3 {
		t.Errorf("%s: session holds %d opens, want its original 3", what, l.sess.OpenCount())
	}
	if l.file.File == nil || l.durable.File == nil {
		t.Errorf("%s: a descriptor was closed", what)
	}
	if n := lockRangesOwnedBy(l.lockKey, l.file); n != 1 {
		t.Errorf("%s: byte-range lock count is %d, want 1", what, n)
	}
	if !shareModeHeld(l.file) {
		t.Errorf("%s: the share-mode reservation was released", what)
	}
	if got := l.conn.hs.conn.resumeKeys.len(); got != 1 {
		t.Errorf("%s: resume-key count is %d, want 1", what, got)
	}
	if got := l.conn.f.dur.len(); got != 1 {
		t.Errorf("%s: durable table holds %d entries, want 1", what, got)
	}
	if got := notifyRegCount(l.conn.hs.disp); got != 1 {
		t.Errorf("%s: CHANGE_NOTIFY registration count is %d, want 1", what, got)
	}
	if l.conn.f.index.get(l.sess.ID) == nil {
		t.Errorf("%s: the session was dropped from the server index", what)
	}
	if l.conn.hs.h.Sessions.Get(l.sess.ID) == nil {
		t.Errorf("%s: the SessionId was invalidated on its own connection", what)
	}
}

// --- the defect -------------------------------------------------------------

// TestFixSessionIndex_SupersededAcrossConnectionsReleasesEverything is the
// regression test for the defect. PreviousSessionId used to be honoured only
// for a previous session on the SAME TCP connection, because SessionTable is
// created per ServeConn and there was no server-scoped index to look anything
// up in. The common macOS case — reconnect arrives on a NEW connection — left
// the old session's descriptors, byte-range locks, share-mode reservations,
// resume keys and change-notify watches in place until the idle reaper ran.
func TestFixSessionIndex_SupersededAcrossConnectionsReleasesEverything(t *testing.T) {
	f := newIdxFixture(t)

	connA := f.connect(t)
	loaded := loadSession(t, connA, 1, "alice", "test123")

	// A second, independent TCP connection. Its own session table, its own
	// dispatcher, its own Connection — everything but the server-scoped index.
	connB := f.connect(t)
	if connB.hs.h.Sessions == connA.hs.h.Sessions {
		t.Fatal("the two connections share a session table; the test proves nothing")
	}
	sessB, _ := connB.auth(t, 1, "alice", "test123", loaded.sess.ID)
	if sessB.ID == loaded.sess.ID {
		t.Fatal("the reconnect reused the previous SessionId")
	}

	loaded.assertFullyReleased(t)

	// And the new session is properly installed.
	if f.index.get(sessB.ID) == nil {
		t.Error("the reconnecting session is not in the server index")
	}
	if connB.hs.h.Sessions.Get(sessB.ID) == nil {
		t.Error("the reconnecting session is not in its own connection's table")
	}
}

// TestFixSessionIndex_PreviousSessionClosedBeforeTheResponse pins WHEN the
// teardown happens relative to the SESSION_SETUP response.
//
// The response is what tells a reconnecting client its session is up, and the
// very next thing such a client does is re-open the files it had open. If the
// old session is still holding those files' share-mode reservations and
// byte-range locks when the response lands, the client gets sharing violations
// on its own handles — which is the failure this whole change exists to remove,
// merely made narrower. So the close must complete first.
//
// The test parks the teardown by holding the handle lock it has to take, and
// then asserts that nothing has been written to the reconnecting connection.
func TestFixSessionIndex_PreviousSessionClosedBeforeTheResponse(t *testing.T) {
	f := newIdxFixture(t)
	connA := f.connect(t)
	loaded := loadSession(t, connA, 1, "alice", "test123")

	// Run the reconnect's handshake up to its final leg.
	connB := f.connect(t)
	leg := connB.hs.leg1(t, 1)
	auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
	hdr, body, frame := sessionSetupFrameWithPrev(auth.secBuf, 2, leg.sessionID, loaded.sess.ID)

	// Park the teardown: releasing this handle means taking its lock, which is
	// the lock a request in flight on it would hold.
	loaded.file.mu.Lock()

	out := &syncWriter{}
	done := make(chan error, 1)
	go func() {
		_, err := connB.hs.h.HandleSessionSetup(out, hdr, body, frame)
		done <- err
	}()

	select {
	case <-done:
		loaded.file.mu.Unlock()
		t.Fatal("the reconnect finished while the previous session's handle was still held")
	case <-time.After(250 * time.Millisecond):
	}
	if n := len(out.snapshot()); n != 0 {
		loaded.file.mu.Unlock()
		<-done
		t.Fatalf("%d bytes of SESSION_SETUP response were written while the previous session "+
			"still held its handles; the client would re-open its files into its own stale "+
			"share-mode reservations", n)
	}

	loaded.file.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("session setup: %v", err)
	}
	if len(out.snapshot()) == 0 {
		t.Fatal("no SESSION_SETUP response was written once the teardown completed")
	}
	loaded.assertFullyReleased(t)
}

// TestFixSessionIndex_SupersedeRefusesAnotherUser is the security half. A
// PreviousSessionId is a bare 64-bit number the client chooses, so without an
// identity check any client could name any other client's SessionId and have
// the server close its files and drop its locks.
func TestFixSessionIndex_SupersedeRefusesAnotherUser(t *testing.T) {
	f := newIdxFixture(t)

	connA := f.connect(t)
	victim := loadSession(t, connA, 1, "alice", "test123")

	connB := f.connect(t)
	if _, _ = connB.auth(t, 1, "bob", "hunter2", victim.sess.ID); false {
		t.Fatal("unreachable")
	}

	victim.assertNothingReleased(t, "bob named alice's SessionId from another connection")
}

// TestFixSessionIndex_SupersedeNoOps covers the ids that must change nothing
// and must not fail the SESSION_SETUP: zero, an id nobody holds, and the
// setting-up session's own id. After a server restart every client's saved
// SessionId is unknown, so erroring on these would make reconnects unmountable.
func TestFixSessionIndex_SupersedeNoOps(t *testing.T) {
	cases := []struct {
		name string
		prev func(victim, self uint64) uint64
	}{
		{"zero", func(victim, self uint64) uint64 { return 0 }},
		{"unknown id", func(victim, self uint64) uint64 { return victim ^ 0x5EED_0000_0000_0001 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newIdxFixture(t)
			connA := f.connect(t)
			victim := loadSession(t, connA, 1, "alice", "test123")

			connB := f.connect(t)
			sessB, _ := connB.auth(t, 1, "alice", "test123", tc.prev(victim.sess.ID, 0))
			if sessB == nil || !sessB.Authenticated {
				t.Fatal("SESSION_SETUP failed; a no-op PreviousSessionId must not break the setup")
			}
			victim.assertNothingReleased(t, tc.name)
		})
	}

	t.Run("names the session being set up", func(t *testing.T) {
		f := newIdxFixture(t)
		connA := f.connect(t)
		victim := loadSession(t, connA, 1, "alice", "test123")

		// Run the handshake by hand so PreviousSessionId can name the very id
		// the type-3 is completing.
		connB := f.connect(t)
		leg := connB.hs.leg1(t, 1)
		auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
		hdr, body, frame := sessionSetupFrameWithPrev(auth.secBuf, 2, leg.sessionID, leg.sessionID)
		sessB, err := connB.hs.h.HandleSessionSetup(connB.hs.pipe, hdr, body, frame)
		if err != nil {
			t.Fatalf("session setup: %v", err)
		}
		if sessB == nil || connB.hs.h.Sessions.Get(sessB.ID) == nil {
			t.Fatal("the session removed itself")
		}
		if f.index.get(sessB.ID) == nil {
			t.Error("the session removed itself from the server index")
		}
		victim.assertNothingReleased(t, "a session naming itself")
	})
}

// TestFixSessionIndex_GuestNeedsMatchingClientGuid covers the one identity that
// is not an identity. Every anonymous client authenticates as the same "guest"
// user, so the name comparison alone would let any machine on the network close
// any other machine's guest session. The ClientGuid is the only thing that
// distinguishes two guests.
func TestFixSessionIndex_GuestNeedsMatchingClientGuid(t *testing.T) {
	sameGuid := [16]byte{0x11, 0x22, 0x33}
	otherGuid := [16]byte{0x99, 0x88, 0x77}

	mk := func(guid [16]byte) (*SessionIndex, *sessionHost, *Session) {
		idx := NewSessionIndex()
		conn := &Connection{ClientGuid: guid}
		tbl := NewSessionTable()
		host := &sessionHost{sessions: tbl, conn: conn}
		sess := tbl.New()
		sess.Authenticated = true
		sess.IsGuest = true
		sess.User = config.UserConfig{Name: "guest"}
		idx.register(sess, host)
		return idx, host, sess
	}

	t.Run("same client guid supersedes", func(t *testing.T) {
		idx, _, prev := mk(sameGuid)
		by := &Session{ID: prev.ID + 1_000_000, Authenticated: true, IsGuest: true,
			User: config.UserConfig{Name: "guest"}}
		if !idx.supersede(prev.ID, by, sameGuid, nil) {
			t.Fatal("a guest reconnect from the same client was refused")
		}
	})

	t.Run("different client guid refused", func(t *testing.T) {
		idx, _, prev := mk(sameGuid)
		by := &Session{ID: prev.ID + 1_000_000, Authenticated: true, IsGuest: true,
			User: config.UserConfig{Name: "guest"}}
		if idx.supersede(prev.ID, by, otherGuid, nil) {
			t.Fatal("one machine's guest session closed another machine's")
		}
		if idx.get(prev.ID) == nil {
			t.Error("a refused supersede still dropped the index entry")
		}
	})

	t.Run("a guest may not supersede a named user", func(t *testing.T) {
		idx := NewSessionIndex()
		tbl := NewSessionTable()
		host := &sessionHost{sessions: tbl, conn: &Connection{ClientGuid: sameGuid}}
		prev := tbl.New()
		prev.Authenticated = true
		prev.User = config.UserConfig{Name: "alice"}
		idx.register(prev, host)

		by := &Session{ID: prev.ID + 1_000_000, Authenticated: true, IsGuest: true,
			User: config.UserConfig{Name: "alice"}}
		if idx.supersede(prev.ID, by, sameGuid, nil) {
			t.Fatal("a guest session closed a named user's session")
		}
	})
}

// TestFixSessionIndex_SessionIdsAreUniqueAcrossConnections guards the
// precondition the whole index rests on. SessionIds used to come from a
// per-SessionTable counter that started at the same value on every connection,
// so connection A and connection B both had a session 2 — and a
// PreviousSessionId of 2 would have named whichever the index happened to hold.
func TestFixSessionIndex_SessionIdsAreUniqueAcrossConnections(t *testing.T) {
	seen := map[uint64]bool{}
	for i := 0; i < 8; i++ {
		tbl := NewSessionTable()
		for j := 0; j < 4; j++ {
			s := tbl.New()
			if s.ID == 0 {
				t.Fatal("allocated SessionId 0, which the protocol reserves for \"no session\"")
			}
			if seen[s.ID] {
				t.Fatalf("SessionId %d was allocated twice; PreviousSessionId would be ambiguous", s.ID)
			}
			seen[s.ID] = true
		}
	}
}

// TestFixSessionIndex_LogoffLeavesTheIndex proves a session removed by LOGOFF
// does not stay reachable server-wide. An entry left behind would keep a dead
// SessionId nameable by a later reconnect, and would leak for the life of the
// process.
func TestFixSessionIndex_LogoffLeavesTheIndex(t *testing.T) {
	f := newIdxFixture(t)
	c := f.connect(t)
	sess, _ := c.auth(t, 1, "alice", "test123", 0)
	if f.index.get(sess.ID) == nil {
		t.Fatal("an authenticated session was not registered")
	}
	var buf bytes.Buffer
	c.hs.disp.handleLogoff(&buf, smb2.Header{Command: smb2.CommandLogoff, SessionID: sess.ID}, sess)
	if f.index.get(sess.ID) != nil {
		t.Error("LOGOFF left the session in the server index")
	}
	if f.index.len() != 0 {
		t.Errorf("index holds %d entries after the only session logged off", f.index.len())
	}
}

// --- races ------------------------------------------------------------------

// TestFixSessionIndex_SupersedeRacesInFlightRequests runs the teardown while
// the owning connection's workers are executing requests against the very
// handles being released. Run with -race -count=5.
//
// The teardown holds each handle's Open.mu — the same lock the dispatcher takes
// for the length of every message naming that handle — so a READ or a WRITE
// either finishes before its descriptor is closed or never starts. Removing the
// session from the owner's table first is what guarantees "never starts": a
// message that cannot resolve its session never reaches the handle at all.
func TestFixSessionIndex_SupersedeRacesInFlightRequests(t *testing.T) {
	f := newIdxFixture(t)
	connA := f.connect(t)
	loaded := loadSession(t, connA, 1, "alice", "test123")

	const workers = 24
	var stop atomic.Bool
	var wg sync.WaitGroup
	started := make(chan struct{}, workers)

	payload := bytes.Repeat([]byte("z"), 512)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started <- struct{}{}
			scratch := fmt.Sprintf("scratch-%02d.bin", i)
			for !stop.Load() {
				fd := connA.hs.disp.forFrame(false)
				hdr := smb2.Header{SessionID: loaded.sess.ID, TreeID: loaded.tree.ID,
					MessageID: uint64(1000 + i)}
				switch i % 5 {
				case 0:
					hdr.Command = smb2.CommandRead
					fd.Dispatch(discardRW{}, hdr, buildReadBody(loaded.file.FileID, 0, 1024), nil)
				case 1:
					hdr.Command = smb2.CommandWrite
					fd.Dispatch(discardRW{}, hdr, buildWriteBody(loaded.file.FileID, 0, payload), nil)
				case 2:
					hdr.Command = smb2.CommandQueryInfo
					fd.Dispatch(discardRW{}, hdr,
						buildQueryInfoBody(loaded.file.FileID, 1, smb2.FileAllInformation, 4096), nil)
				case 3:
					hdr.Command = smb2.CommandQueryDirectory
					fd.Dispatch(discardRW{}, hdr,
						buildQueryDirBody(loaded.dir.FileID, smb2.InfoFileIdBothDirectoryInformation, 0, 8192, "*"), nil)
				default:
					// A CREATE in flight is the sharp case: it resolves its
					// session at the top of the message and then does real
					// filesystem work before AddOpen, so it can reach AddOpen
					// AFTER the teardown has emptied the session's open map.
					// The handle it installed there would be reachable by
					// nobody — its descriptor and its share-mode reservation
					// held for the life of the process.
					hdr.Command = smb2.CommandCreate
					fd.Dispatch(discardRW{}, hdr,
						buildCreateBodyShare(scratch, smb2.CreateDispositionOpenIf, 0,
							smb2.AccessGenericRead|smb2.AccessGenericWrite,
							shareAccessRead|shareAccessWrite|shareAccessDelete, nil), nil)
					hdr.Command = smb2.CommandClose
					hdr.Flags = smb2.FlagRelatedOps
					hdr.MessageID++
					fd.Dispatch(discardRW{}, hdr, buildCloseBody(previousHandleFileID), nil)
				}
				fd.flush(discardRW{})
			}
		}(i)
	}
	for i := 0; i < workers; i++ {
		<-started
	}

	// Tear the session down out from under all of them, from another
	// connection, exactly as a reconnecting client would.
	connB := f.connect(t)
	connB.auth(t, 1, "alice", "test123", loaded.sess.ID)

	stop.Store(true)
	wg.Wait()

	loaded.assertFullyReleased(t)
}

// TestFixSessionIndex_SupersedeRacesHandleClose proves exactly one release when
// a CLOSE of the same handle runs concurrently with the teardown.
//
// The invariant is ownership, not timing: the Session.opens map is the token,
// and exactly one of handleClose's RemoveOpen and the teardown's TakeAllOpens
// can come away with the *Open. The two sub-tests below pin that invariant from
// each side deterministically — a teardown racing a CLOSE is far too short a
// window to hit reliably by hammering — and the third then hammers it anyway,
// which is what -race actually needs.
func TestFixSessionIndex_SupersedeRacesHandleClose(t *testing.T) {
	// setup returns a session on connection A holding one ordinary handle.
	setup := func(t *testing.T, name string) (*idxFixture, *idxConn, *Session, *Tree, *Open) {
		t.Helper()
		f := newIdxFixture(t)
		connA := f.connect(t)
		sess, tree := connA.auth(t, 1, "alice", "test123", 0)
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte("contested"), 0o644); err != nil {
			t.Fatal(err)
		}
		open := connA.create(t, sess, tree, name,
			smb2.AccessGenericRead|smb2.AccessGenericWrite, 0, nil)
		return f, connA, sess, tree, open
	}

	supersedeAs := func(f *idxFixture, sess *Session) bool {
		return f.index.supersede(sess.ID, &Session{
			ID:            sess.ID + 1_000_000,
			Authenticated: true,
			User:          sess.User,
		}, [16]byte{}, nil)
	}

	t.Run("a CLOSE arriving after the teardown claimed the handle finds nothing", func(t *testing.T) {
		f, connA, sess, _, open := setup(t, "claimed.bin")
		fileID := open.FileID

		// Stand in for a request already running on this handle: the dispatcher
		// holds exactly this lock for the length of every message that names a
		// handle, so holding it parks the teardown after it has claimed the
		// handle and before it releases anything.
		open.mu.Lock()

		done := make(chan bool, 1)
		go func() { done <- supersedeAs(f, sess) }()

		// The teardown invalidates the SessionId first, then claims the
		// handles, then asks for this lock. Waiting for the first step and
		// yielding puts us reliably after the second.
		waitFor(t, "the teardown to invalidate the SessionId", func() bool {
			return connA.hs.h.Sessions.Get(sess.ID) == nil
		})
		time.Sleep(25 * time.Millisecond)

		if got := sess.RemoveOpen(fileID); got != nil {
			open.mu.Unlock()
			<-done
			t.Fatal("the handle was still claimable after the teardown took ownership of it; " +
				"a CLOSE landing here and the teardown would both release it")
		}
		open.mu.Unlock()

		if !<-done {
			t.Fatal("the supersede did not happen")
		}
		if open.File != nil {
			t.Error("the teardown did not close the descriptor")
		}
		if shareModeHeld(open) {
			t.Error("the share-mode reservation was not released")
		}
	})

	t.Run("the teardown does not touch a handle a CLOSE already took", func(t *testing.T) {
		f, connA, sess, tree, open := setup(t, "closed-first.bin")

		fd := connA.hs.disp.forFrame(false)
		var buf bytes.Buffer
		fd.Dispatch(&buf, smb2.Header{Command: smb2.CommandClose, SessionID: sess.ID,
			TreeID: tree.ID, MessageID: 42}, buildCloseBody(open.FileID), nil)
		fd.flush(&buf)
		if got := frameStatus(t, &buf); got != smb2.StatusSuccess {
			t.Fatalf("CLOSE status = 0x%08X, want SUCCESS", uint32(got))
		}

		if !supersedeAs(f, sess) {
			t.Fatal("the supersede did not happen")
		}
		// handleClose closes the descriptor but leaves Open.File set; only
		// releaseOpens nils it. A nil here means the teardown released a handle
		// that was already somebody else's.
		if open.File == nil {
			t.Fatal("the teardown released a handle handleClose had already released")
		}
		if _, err := open.File.Stat(); err == nil {
			t.Error("the CLOSE left the descriptor open")
		}
	})

	t.Run("hammered", func(t *testing.T) {
		const rounds = 20
		for round := 0; round < rounds; round++ {
			f, connA, sess, tree, open := setup(t, fmt.Sprintf("raced-%d.bin", round))
			baseShareModes := sharedShareModes.len()
			fileID := open.FileID

			// Run the reconnect's handshake up to its final leg before the
			// gate, so the gated goroutine does only the type-3 that triggers
			// the teardown and the two really do overlap.
			connB := f.connect(t)
			leg := connB.hs.leg1(t, 1)
			auth := buildAuthenticate(t, leg, "alice", "WORKGROUP", "test123", true, nil)
			ssHdr, ssBody, ssFrame := sessionSetupFrameWithPrev(auth.secBuf, 2, leg.sessionID, sess.ID)

			const closers = 8
			var closeSuccesses atomic.Int32
			var wg sync.WaitGroup
			gate := make(chan struct{})

			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				if _, err := connB.hs.h.HandleSessionSetup(connB.hs.pipe, ssHdr, ssBody, ssFrame); err != nil {
					t.Errorf("round %d: reconnect session setup: %v", round, err)
				}
			}()
			for i := 0; i < closers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-gate
					fd := connA.hs.disp.forFrame(false)
					var buf bytes.Buffer
					fd.Dispatch(&buf, smb2.Header{Command: smb2.CommandClose, SessionID: sess.ID,
						TreeID: tree.ID, MessageID: uint64(2000 + i)}, buildCloseBody(fileID), nil)
					fd.flush(&buf)
					if buf.Len() >= 4+smb2.HeaderSize && frameStatus(t, &buf) == smb2.StatusSuccess {
						closeSuccesses.Add(1)
					}
				}(i)
			}

			close(gate)
			wg.Wait()

			// Whoever took the handle out of the map released it, and only them.
			if open.File == nil {
				if n := closeSuccesses.Load(); n != 0 {
					t.Fatalf("round %d: the teardown released the handle but %d CLOSE(s) also reported success",
						round, n)
				}
			} else {
				if n := closeSuccesses.Load(); n != 1 {
					t.Fatalf("round %d: %d CLOSE(s) reported success, want exactly 1", round, n)
				}
				if _, err := open.File.Stat(); err == nil {
					t.Fatalf("round %d: the winning CLOSE left the descriptor open", round)
				}
			}
			if sess.OpenCount() != 0 {
				t.Fatalf("round %d: the handle is still in the session", round)
			}
			if shareModeHeld(open) {
				t.Fatalf("round %d: the share-mode reservation survived both paths", round)
			}
			if got := sharedShareModes.len(); got != baseShareModes-1 {
				t.Fatalf("round %d: share-mode table holds %d reservations, want %d",
					round, got, baseShareModes-1)
			}
			if got := connA.hs.conn.resumeKeys.len(); got != 0 {
				t.Fatalf("round %d: %d resume key(s) left behind", round, got)
			}
		}
	})
}

// TestFixSessionIndex_CreateRacingTeardownIsNotOrphaned covers the window the
// per-handle lock cannot: a CREATE has no handle to lock until it has already
// opened the file and reserved its share mode, and it resolved its session at
// the top of the message, long before either. A teardown landing in between
// empties the open map and then the CREATE puts a handle back into it — a
// handle nothing will ever close, because no CLOSE, TREE_DISCONNECT or teardown
// can reach a session that is already gone. The descriptor and, far worse, the
// share-mode reservation would then be held for the life of the process, and a
// leaked reservation makes that file unopenable by every client on every
// connection.
//
// The fix is the dead latch on Session: TakeAllOpens is what claims the
// handles, so it is also what closes the map, and AddOpen refuses afterwards.
func TestFixSessionIndex_CreateRacingTeardownIsNotOrphaned(t *testing.T) {
	t.Run("AddOpen refuses once the handles have been claimed", func(t *testing.T) {
		sess := &Session{ID: 1}
		o := &Open{FileID: [16]byte{0x01}}
		if !sess.AddOpen(o) {
			t.Fatal("AddOpen refused on a live session")
		}
		if got := sess.TakeAllOpens(); len(got) != 1 {
			t.Fatalf("TakeAllOpens returned %d handles, want 1", len(got))
		}
		if sess.AddOpen(&Open{FileID: [16]byte{0x02}}) {
			t.Fatal("AddOpen accepted a handle into a session whose handles had already been claimed; " +
				"nothing would ever release it")
		}
		if sess.OpenCount() != 0 {
			t.Fatal("the refused handle was installed anyway")
		}
	})

	t.Run("a CREATE completing after the teardown releases what it opened", func(t *testing.T) {
		f := newIdxFixture(t)
		c := f.connect(t)
		baseShareModes := sharedShareModes.len()
		sess, _ := c.auth(t, 1, "alice", "test123", 0)
		if err := os.WriteFile(filepath.Join(f.dir, "orphan.bin"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		// Stand in for the teardown having already run: the session's handles
		// are claimed and its SessionId is gone. This is exactly the state a
		// CREATE that resolved its session a moment earlier now finds — and it
		// still holds the *Tree it resolved back then, which is what the
		// re-added tree stands in for (TakeAllOpens clears the tree map too,
		// but the in-flight CREATE is holding its pointer, not looking it up
		// again).
		sess.TakeAllOpens()
		c.hs.h.Sessions.Remove(sess.ID)
		f.index.unregister(sess.ID)
		tree := sess.AddTree(f.share)

		var buf bytes.Buffer
		body := buildCreateBodyShare("orphan.bin", smb2.CreateDispositionOpenIf, 0,
			smb2.AccessGenericRead|smb2.AccessGenericWrite, 0, nil)
		if !c.hs.disp.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate,
			SessionID: sess.ID, TreeID: tree.ID}, body, sess) {
			t.Fatal("handleCreate returned false")
		}
		if got := frameStatus(t, &buf); got != smb2.StatusUserSessionDeleted {
			t.Errorf("CREATE on a torn-down session = 0x%08X, want STATUS_USER_SESSION_DELETED", uint32(got))
		}
		if sess.OpenCount() != 0 {
			t.Error("the CREATE installed a handle in a session nothing can reach")
		}
		if got := sharedShareModes.len(); got != baseShareModes {
			t.Errorf("share-mode table holds %d reservations, want the baseline %d — "+
				"an orphaned CREATE leaked a reservation and the file is now unopenable by everyone",
				got, baseShareModes)
		}
	})

	t.Run("a durable reclaim completing after the teardown releases what it reclaimed", func(t *testing.T) {
		shareDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(shareDir, "rw.txt"), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		baseShareModes := sharedShareModes.len()
		d, sess, _, tbl := newDurableDispatcher(t, shareDir)

		fileID, createGuid := fixSessionDurableCreate(t, d, sess, "rw.txt")
		sess.RemoveOpen(fileID)
		tbl.Detach(d.Conn.ClientGuid, createGuid)

		// The reconnecting session is torn down before the reclaim lands.
		sess2 := &Session{}
		sess2.TakeAllOpens() // the reconnecting session is torn down...
		sess2.AddTree(d.Shares[0])

		status, _ := fixSessionDurableReconnect(t, d, sess2, "rw.txt", fileID, createGuid)
		if status != smb2.StatusUserSessionDeleted {
			t.Errorf("reclaim into a torn-down session = 0x%08X, want STATUS_USER_SESSION_DELETED",
				uint32(status))
		}
		if sess2.OpenCount() != 0 {
			t.Error("the reclaim installed a handle in a session nothing can reach")
		}
		if got := sharedShareModes.len(); got != baseShareModes {
			t.Errorf("share-mode table holds %d reservations, want the baseline %d — "+
				"the orphaned reclaim leaked the reservation it was handed", got, baseShareModes)
		}
	})
}

// TestFixSessionIndex_HandleLockChoiceIgnoresTheDescriptor pins the one line
// that decides whether a message holds its handle shared or exclusively.
//
// It used to read open.File — "is there a descriptor behind this handle?" —
// before taking the lock. open.File is not immutable: a release nils it, and it
// does so under this very lock, which is the whole reason that field is safe to
// touch at all. So the test was an unsynchronized read of a field being written
// at that instant, and a teardown releasing a handle a worker had just looked
// up was a genuine data race (caught once in roughly three hundred -race
// iterations before the fix, by SupersedeRacesInFlightRequests). It was also
// redundant: File is non-nil for exactly the handles IsDir, IsPipe and IsStream
// are all false for.
//
// The observable consequence of getting it wrong is the lock MODE, so that is
// what this asserts: a handle whose descriptor has already been released still
// takes the shared path for READ. With the old test it took the exclusive path
// instead and would block behind the reader below.
func TestFixSessionIndex_HandleLockChoiceIgnoresTheDescriptor(t *testing.T) {
	sess := &Session{}
	// An ordinary file handle whose descriptor has already gone — the state a
	// worker sees when it looked the handle up just before a teardown.
	o := &Open{FileID: [16]byte{0x5A}}
	if !sess.AddOpen(o) {
		t.Fatal("AddOpen refused on a fresh session")
	}

	// Another READ is already holding the handle shared.
	o.mu.RLock()

	got := make(chan func(), 1)
	go func() {
		got <- lockOpenForMessage(sess, smb2.CommandRead, buildReadBody(o.FileID, 0, 16))
	}()
	select {
	case unlock := <-got:
		if unlock == nil {
			t.Fatal("lockOpenForMessage returned no unlock for a handle in the session")
		}
		unlock()
	case <-time.After(5 * time.Second):
		// Leave the reader held: unlocking now would let the blocked goroutine
		// proceed and unlock a mutex this test still owns.
		t.Fatal("READ on a handle whose descriptor was already released took the handle " +
			"EXCLUSIVELY — the shared/exclusive choice is reading open.File, which a " +
			"release writes under this very lock")
	}
	o.mu.RUnlock()

	// The exclusive commands must still be exclusive.
	for _, cmd := range []smb2.Command{smb2.CommandClose, smb2.CommandQueryDirectory} {
		unlock := lockOpenForMessage(sess, cmd, buildCloseBody(o.FileID))
		if unlock == nil {
			t.Fatalf("%v got no handle lock", cmd)
		}
		if o.mu.TryRLock() {
			o.mu.RUnlock()
			unlock()
			t.Fatalf("%v did not hold the handle exclusively", cmd)
		}
		unlock()
	}

	// And a directory handle READ stays exclusive: it has no descriptor to
	// pread through, so it is served off the mutable enumeration cursor.
	dir := &Open{FileID: [16]byte{0x5B}, IsDir: true}
	sess.AddOpen(dir)
	unlock := lockOpenForMessage(sess, smb2.CommandRead, buildReadBody(dir.FileID, 0, 16))
	if unlock == nil {
		t.Fatal("directory READ got no handle lock")
	}
	if dir.mu.TryRLock() {
		dir.mu.RUnlock()
		unlock()
		t.Fatal("READ on a directory handle took the handle shared")
	}
	unlock()
}

// TestFixSessionIndex_ConnTeardownTakesOwnership guards the other half of the
// ownership rule. Connection teardown used to iterate each session's open map
// and release in place, without removing anything; a cross-connection teardown
// superseding one of those sessions at the same moment would claim the same
// handles and release them a second time. Taking them out of the map is what
// makes "whoever emptied the map owns the release" true on this path too.
func TestFixSessionIndex_ConnTeardownTakesOwnership(t *testing.T) {
	f := newIdxFixture(t)
	c := f.connect(t)
	sess, tree := c.auth(t, 1, "alice", "test123", 0)
	if err := os.WriteFile(filepath.Join(f.dir, "conn-teardown.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	open := c.create(t, sess, tree, "conn-teardown.bin",
		smb2.AccessGenericRead|smb2.AccessGenericWrite, 0, nil)

	releaseConnOpens(c.hs.h.Sessions, f.dur)

	if sess.OpenCount() != 0 {
		t.Fatal("connection teardown released handles without taking them out of the session; " +
			"a cross-connection teardown racing it would release the same handles again")
	}
	if _, err := open.File.Stat(); err == nil {
		t.Error("connection teardown left the descriptor open")
	}
	if shareModeHeld(open) {
		t.Error("connection teardown left the share-mode reservation behind")
	}
}

// TestFixSessionIndex_ConcurrentSupersedesCloseOnce points two reconnects at
// the same previous session at once. supersede deletes the index entry under
// the index lock before it starts the teardown, so exactly one of them may
// reach it.
func TestFixSessionIndex_ConcurrentSupersedesCloseOnce(t *testing.T) {
	f := newIdxFixture(t)
	connA := f.connect(t)
	loaded := loadSession(t, connA, 1, "alice", "test123")

	const racers = 8
	var won atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			if f.index.supersede(loaded.sess.ID, &Session{
				ID:            loaded.sess.ID + 1_000_000,
				Authenticated: true,
				User:          loaded.sess.User,
			}, [16]byte{}, nil) {
				won.Add(1)
			}
		}()
	}
	close(gate)
	wg.Wait()

	if got := won.Load(); got != 1 {
		t.Fatalf("%d concurrent supersedes reached the teardown, want exactly 1", got)
	}
	loaded.assertFullyReleased(t)
}

// --- the owning connection, end to end --------------------------------------

// TestFixSessionIndex_SupersededConnectionShutsDownCleanly drives two real
// ServeConn connections over TCP. It is the only test here that exercises the
// worker pool, the writer goroutine and the connection teardown, which is what
// the checklist item about goroutines is really about: after a session is
// superseded from another connection, the owning connection must notice, answer
// STATUS_USER_SESSION_DELETED, and shut down without panicking, without
// double-releasing and without leaving its writer or its pool behind.
func TestFixSessionIndex_SupersededConnectionShutsDownCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "e2e.bin"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := ConnOptions{
		MaxIOSize: 1 << 20,
		Users:     fixSessionUsers(),
		Shares:    []config.ShareConfig{{Name: "share", Path: dir}},
		Sessions:  NewSessionIndex(),
		Durable:   NewDurableTable(),
	}

	baseShareModes := sharedShareModes.len()
	// One warm-up connection so lazily-created runtime goroutines are not
	// counted as a leak below.
	warm, warmDone := serveConnPair(t, ctx, opts)
	warm.Close()
	<-warmDone
	baseGoroutines := settledGoroutines(t)

	// Connection A: authenticate, connect the share, open a file.
	clientA, doneA := serveConnPair(t, ctx, opts)
	rcA := newRawClient(t, clientA)
	rcA.negotiate()
	sessA := rcA.sessionSetup("alice", "test123", 0)
	treeA := rcA.treeConnect(sessA, `\\srv\share`)
	rcA.create(sessA, treeA, "e2e.bin")
	if got := sharedShareModes.len(); got != baseShareModes+1 {
		t.Fatalf("the CREATE on connection A did not reserve a share mode (table %d, baseline %d)",
			got, baseShareModes)
	}

	// Connection B: the reconnect, naming A's session.
	clientB, doneB := serveConnPair(t, ctx, opts)
	rcB := newRawClient(t, clientB)
	rcB.negotiate()
	rcB.sessionSetup("alice", "test123", sessA)

	if got := sharedShareModes.len(); got != baseShareModes {
		t.Errorf("share-mode table holds %d reservations once the reconnect was answered, want "+
			"the baseline %d — connection A's handle was still reserved when connection B was "+
			"told its session was up", got, baseShareModes)
	}

	// A's next request must be told its session is gone, and A must then shut
	// itself down — the client is owed that answer before the socket dies.
	rcA.send(smb2.Header{Command: smb2.CommandEcho, MessageID: 99, SessionID: sessA},
		[]byte{0x04, 0x00, 0x00, 0x00})
	if got := rcA.recvStatus(); got != smb2.StatusUserSessionDeleted {
		t.Errorf("ECHO on a superseded session = 0x%08X, want STATUS_USER_SESSION_DELETED", uint32(got))
	}
	select {
	case <-doneA:
	case <-time.After(10 * time.Second):
		t.Fatal("the superseded connection did not shut down")
	}
	clientA.Close()

	clientB.Close()
	select {
	case <-doneB:
	case <-time.After(10 * time.Second):
		t.Fatal("the reconnecting connection did not shut down")
	}

	if got := sharedShareModes.len(); got != baseShareModes {
		t.Errorf("share-mode table holds %d reservations after both connections went away, want %d",
			got, baseShareModes)
	}
	if opts.Sessions.len() != 0 {
		t.Errorf("the session index holds %d entries after both connections went away",
			opts.Sessions.len())
	}
	// The writer goroutine, the ctx watcher and every pool worker of both
	// connections must be gone.
	if after := settledGoroutines(t); after > baseGoroutines+2 {
		t.Errorf("goroutine count %d after the connections ended, baseline %d — "+
			"a superseded connection left goroutines behind", after, baseGoroutines)
	}
}

// serveConnPair returns a connected client socket and a channel closed when the
// ServeConn serving the other end has returned. A real TCP pair rather than
// net.Pipe, so the server's writer goroutine is never blocked waiting for the
// test to read.
func serveConnPair(t *testing.T, ctx context.Context, opts ConnOptions) (net.Conn, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	if a.err != nil {
		t.Fatal(a.err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeConn(ctx, a.c, slog.New(slog.NewTextHandler(io.Discard, nil)),
			transport.MaxFrameSize, opts)
	}()
	t.Cleanup(func() { client.Close() })
	return client, done
}

// rawClient is the minimum SMB2 client these tests need: NEGOTIATE,
// SESSION_SETUP (both NTLM legs), TREE_CONNECT, CREATE and ECHO, unsigned and
// unencrypted, against a server configured to require neither.
type rawClient struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
}

func newRawClient(t *testing.T, c net.Conn) *rawClient {
	return &rawClient{t: t, c: c, br: bufio.NewReader(c)}
}

func (rc *rawClient) sendFrame(frame []byte) {
	rc.t.Helper()
	if err := transport.WriteFrame(rc.c, frame); err != nil {
		rc.t.Fatalf("write frame: %v", err)
	}
}

func (rc *rawClient) send(hdr smb2.Header, body []byte) {
	rc.t.Helper()
	hdr.CreditCharge = 1
	frame := make([]byte, smb2.HeaderSize+len(body))
	if err := smb2.EncodeHeader(frame[:smb2.HeaderSize], hdr); err != nil {
		rc.t.Fatal(err)
	}
	copy(frame[smb2.HeaderSize:], body)
	rc.sendFrame(frame)
}

func (rc *rawClient) recv() (smb2.Header, []byte) {
	rc.t.Helper()
	_ = rc.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	frame, err := transport.ReadFrame(rc.br, transport.MaxFrameSize)
	if err != nil {
		rc.t.Fatalf("read frame: %v", err)
	}
	hdr, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
	if err != nil {
		rc.t.Fatalf("decode header: %v", err)
	}
	return hdr, frame[smb2.HeaderSize:]
}

func (rc *rawClient) recvStatus() smb2.Status {
	rc.t.Helper()
	hdr, _ := rc.recv()
	return smb2.Status(hdr.Status)
}

func (rc *rawClient) negotiate() {
	rc.t.Helper()
	rc.sendFrame(buildClientNegotiate311())
	if hdr, _ := rc.recv(); smb2.Status(hdr.Status) != smb2.StatusSuccess {
		rc.t.Fatalf("negotiate status 0x%08X", hdr.Status)
	}
}

// sessionSetup runs both NTLM legs and returns the established SessionId.
func (rc *rawClient) sessionSetup(user, pw string, prev uint64) uint64 {
	rc.t.Helper()

	neg := make([]byte, 40)
	copy(neg[0:8], ntlm.Signature[:])
	binary.LittleEndian.PutUint32(neg[8:], ntlm.MessageTypeNegotiate)
	binary.LittleEndian.PutUint32(neg[12:], ntlm.NegotiateUnicode|ntlm.NegotiateNTLM|
		ntlm.NegotiateExtendedSessionSecurity|ntlm.NegotiateAlwaysSign|ntlm.NegotiateVersion)

	_, _, frame := sessionSetupFrame(neg, 1, 0)
	rc.sendFrame(frame)
	hdr, body := rc.recv()
	if smb2.Status(hdr.Status) != smb2.StatusMoreProcessingReq {
		rc.t.Fatalf("type-1 leg status 0x%08X", hdr.Status)
	}
	chal, err := smb2.UnwrapNTLM(body)
	if err != nil {
		rc.t.Fatalf("unwrap challenge: %v", err)
	}
	leg := fixCryptoLeg1{negotiate: neg, challenge: chal, sessionID: hdr.SessionID}
	copy(leg.challenge8[:], chal[24:32])

	auth := buildAuthenticate(rc.t, leg, user, "WORKGROUP", pw, true, nil)
	_, _, frame = sessionSetupFrameWithPrev(auth.secBuf, 2, leg.sessionID, prev)
	rc.sendFrame(frame)
	if hdr, _ = rc.recv(); smb2.Status(hdr.Status) != smb2.StatusSuccess {
		rc.t.Fatalf("type-3 leg status 0x%08X", hdr.Status)
	}
	return hdr.SessionID
}

func (rc *rawClient) treeConnect(sessID uint64, path string) uint32 {
	rc.t.Helper()
	rc.send(smb2.Header{Command: smb2.CommandTreeConnect, MessageID: 3, SessionID: sessID},
		buildTreeConnectBody(path))
	hdr, _ := rc.recv()
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		rc.t.Fatalf("tree-connect status 0x%08X", hdr.Status)
	}
	return hdr.TreeID
}

func (rc *rawClient) create(sessID uint64, treeID uint32, name string) [16]byte {
	rc.t.Helper()
	rc.send(smb2.Header{Command: smb2.CommandCreate, MessageID: 4, SessionID: sessID, TreeID: treeID},
		buildCreateBodyShare(name, smb2.CreateDispositionOpenIf, 0,
			smb2.AccessGenericRead|smb2.AccessGenericWrite, 0, nil))
	hdr, body := rc.recv()
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		rc.t.Fatalf("create status 0x%08X", hdr.Status)
	}
	var fid [16]byte
	copy(fid[:], body[64:80])
	return fid
}
