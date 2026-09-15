package parent

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- a transient sharing conflict was answered instantly ---
//
// macOS deletes a file by opening it deny-all (SMBClient
// kernel/smbfs/smbfs_smb_2.c, radar <17346821>: "Set share_access to
// NTCREATEX_SHARE_ACCESS_NONE so that we can attempt to delete the item right
// now"), and it never retries the refusal — kernel/netsmb/smb_subr.c maps
// STATUS_SHARING_VIOLATION straight to EBUSY. So a few milliseconds of overlap
// with another client's read is enough to fail rm, which leaves .git/index.lock
// on disk and breaks the repository for good. The server has to absorb the
// window, because nobody else will.

// newWaitDispatcher builds a Dispatcher carrying a Connection, which is what
// bounds how many CREATEs one connection may park at once.
func newWaitDispatcher(t *testing.T, shareDir string) (*Dispatcher, *Session, *Tree) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir}
	conn := &Connection{MaxIOSize: 1 << 20}
	conn.ClientGuid[0] = 0xD3
	d := &Dispatcher{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares:   []config.ShareConfig{share},
		Conn:     conn,
		Sessions: NewSessionTable(),
		locks:    sharedLockManager,
		async:    &asyncTable{},
	}
	sess := d.Sessions.New()
	sess.Authenticated = true
	tree := sess.AddTree(share)
	return d, sess, tree
}

// waitCreate dispatches through d.forFrame, exactly as conn.go's frame loop
// does, rather than calling d.handleCreate on the shared Dispatcher directly.
// The compound-chain state (lastChainStatus and friends) lives on the
// Dispatcher itself and is only made per-request-safe by that clone — tests
// that fire concurrent requests at one Dispatcher without it corrupt that
// state exactly the way forFrame's own doc comment describes.
func waitCreate(t *testing.T, d *Dispatcher, sess *Session, tree *Tree,
	name string, access, share uint32) (smb2.Status, [16]byte) {
	t.Helper()
	var buf bytes.Buffer
	fd := d.forFrame(false)
	fd.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBodyShare(name, smb2.CreateDispositionOpen, 0, access, share, nil), sess)
	fd.flush(&buf)
	hdr, resp, _ := readCreateResponse(t, &buf)
	return smb2.Status(hdr.Status), resp.FileID
}

func waitClose(t *testing.T, d *Dispatcher, sess *Session, tree *Tree, fid [16]byte) {
	t.Helper()
	var buf bytes.Buffer
	fd := d.forFrame(false)
	fd.handleClose(&buf, smb2.Header{Command: smb2.CommandClose, TreeID: tree.ID},
		buildCloseBody(fid), sess)
	fd.flush(&buf)
	if st := respStatus(t, &buf); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
}

// TestFixShareWait_TransientConflictIsAbsorbed is the regression: a deny-all
// delete-style open that arrives while another client is mid-read must succeed
// once that read's handle goes away, not fail instantly.
func TestFixShareWait_TransientConflictIsAbsorbed(t *testing.T) {
	dir := t.TempDir()
	baseline := sharedShareModes.len()
	t.Cleanup(func() {
		if got := sharedShareModes.len(); got != baseline {
			t.Errorf("share-mode table holds %d reservations at test end, want %d", got, baseline)
		}
	})

	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Reader is one connection; deleter is another.
	dr, sr, tr := newWaitDispatcher(t, dir)
	dd, sd, td := newWaitDispatcher(t, dir)

	st, readerFID := waitCreate(t, dr, sr, tr, "f.txt", wantRead, shareAll)
	if st != smb2.StatusSuccess {
		t.Fatalf("reader CREATE = %#x, want success", uint32(st))
	}

	// The reader lets go 30ms from now — well inside sharingViolationWait.
	go func() {
		time.Sleep(30 * time.Millisecond)
		var buf bytes.Buffer
		dr.handleClose(&buf, smb2.Header{Command: smb2.CommandClose, TreeID: tr.ID},
			buildCloseBody(readerFID), sr)
	}()

	start := time.Now()
	st, delFID := waitCreate(t, dd, sd, td, "f.txt",
		accDelete|smb2.AccessFileReadAttributes|accSynchronize, shareNone)
	elapsed := time.Since(start)

	if st != smb2.StatusSuccess {
		t.Fatalf("deny-all delete open = %#x, want success after the reader closed", uint32(st))
	}
	if elapsed >= sharingViolationWait {
		t.Errorf("waited %v, want a wake as soon as the reader released (well under %v)",
			elapsed, sharingViolationWait)
	}
	waitClose(t, dd, sd, td, delFID)
}

// TestFixShareWait_HeldConflictStillRefuses proves the wait is bounded: a
// holder that never lets go still gets the client a STATUS_SHARING_VIOLATION.
func TestFixShareWait_HeldConflictStillRefuses(t *testing.T) {
	dir := t.TempDir()
	baseline := sharedShareModes.len()

	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	dr, sr, tr := newWaitDispatcher(t, dir)
	dd, sd, td := newWaitDispatcher(t, dir)

	st, readerFID := waitCreate(t, dr, sr, tr, "f.txt", wantRead, shareAll)
	if st != smb2.StatusSuccess {
		t.Fatalf("reader CREATE = %#x, want success", uint32(st))
	}

	start := time.Now()
	st, _ = waitCreate(t, dd, sd, td, "f.txt",
		accDelete|smb2.AccessFileReadAttributes|accSynchronize, shareNone)
	elapsed := time.Since(start)

	if st != smb2.StatusSharingViolation {
		t.Fatalf("deny-all delete open = %#x, want STATUS_SHARING_VIOLATION", uint32(st))
	}
	if elapsed < sharingViolationWait {
		t.Errorf("gave up after %v, want it to wait at least %v", elapsed, sharingViolationWait)
	}

	waitClose(t, dr, sr, tr, readerFID)
	if got := sharedShareModes.len(); got != baseline {
		t.Errorf("share-mode table holds %d reservations, want %d: the refused CREATE left something behind",
			got, baseline)
	}
}

// TestFixShareWait_ParkedCreatesAreCapped proves one connection cannot park
// its whole worker pool on a contended file: past maxSharingWaits, the
// refusal is immediate again.
func TestFixShareWait_ParkedCreatesAreCapped(t *testing.T) {
	dir := t.TempDir()
	baseline := sharedShareModes.len()

	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	dr, sr, tr := newWaitDispatcher(t, dir)
	dd, sd, td := newWaitDispatcher(t, dir)

	st, readerFID := waitCreate(t, dr, sr, tr, "f.txt", wantRead, shareAll)
	if st != smb2.StatusSuccess {
		t.Fatalf("reader CREATE = %#x, want success", uint32(st))
	}

	// Fill the connection's parking slots with goroutines that will each sit
	// out the full wait.
	done := make(chan struct{}, maxSharingWaits)
	for i := 0; i < maxSharingWaits; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			waitCreate(t, dd, sd, td, "f.txt",
				accDelete|smb2.AccessFileReadAttributes|accSynchronize, shareNone)
		}()
	}
	// Give them time to park.
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	st, _ = waitCreate(t, dd, sd, td, "f.txt",
		accDelete|smb2.AccessFileReadAttributes|accSynchronize, shareNone)
	elapsed := time.Since(start)

	if st != smb2.StatusSharingViolation {
		t.Fatalf("over-cap CREATE = %#x, want STATUS_SHARING_VIOLATION", uint32(st))
	}
	if elapsed > sharingViolationWait/2 {
		t.Errorf("over-cap CREATE took %v, want an immediate refusal", elapsed)
	}

	for i := 0; i < maxSharingWaits; i++ {
		<-done
	}
	waitClose(t, dr, sr, tr, readerFID)
	if got := sharedShareModes.len(); got != baseline {
		t.Errorf("share-mode table holds %d reservations, want %d", got, baseline)
	}
}
