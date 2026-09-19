package parent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/ahmetozer/gosamba/internal/config"
)

// workerEnvKey is the marker env var set on the re-exec'd worker child. When
// present the process serves exactly one connection (inherited as fd 3) instead
// of binding the listener.
const workerEnvKey = "GOSAMBA_WORKER"

// workerConnFD is the fixed file-descriptor number the accepted connection
// lands on inside the worker child. exec.Cmd.ExtraFiles[0] maps to fd 3.
const workerConnFD = 3

// maxConcurrentWorkers bounds how many worker processes may be alive at once.
//
// In the re-exec model every accepted TCP connection costs a whole process, and
// the spawn happens BEFORE the peer has authenticated — so without a bound an
// anonymous client that merely opens sockets in a loop forks the host until it
// hits RLIMIT_NPROC or exhausts memory. 128 is chosen to be far above any
// plausible real SMB client population for the single-host, small-deployment
// use case this server targets (a handful of Macs and PCs, each holding one or
// two connections), while staying comfortably inside a default 1024-process
// user limit even counting the parent and its helper goroutines. Connections
// beyond the bound are refused immediately rather than queued: queuing would
// let an attacker park unbounded sockets and memory in the parent, which is the
// resource exhaustion we are trying to prevent.
const maxConcurrentWorkers = 128

// errWorkerLimit is returned by reExecWorker when maxConcurrentWorkers workers
// are already running. The caller drops the connection.
var errWorkerLimit = errors.New("worker limit reached")

// workerSemaphore is a non-blocking counting semaphore guarding worker spawns.
type workerSemaphore struct {
	slots chan struct{}
}

func newWorkerSemaphore(n int) *workerSemaphore {
	return &workerSemaphore{slots: make(chan struct{}, n)}
}

// acquire takes a slot, reporting false immediately if none is free.
func (s *workerSemaphore) acquire() bool {
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// release returns a slot. It is safe to call on an empty semaphore so the
// spawn error paths can release unconditionally.
func (s *workerSemaphore) release() {
	select {
	case <-s.slots:
	default:
	}
}

// workerSlots bounds live worker processes across the whole parent process.
var workerSlots = newWorkerSemaphore(maxConcurrentWorkers)

// IsWorker reports whether the current process is a re-exec'd worker that
// should serve a single inherited connection rather than bind the listener.
func IsWorker() bool {
	return os.Getenv(workerEnvKey) == "1"
}

// privDropPlan describes a privilege-drop decision computed from the
// authenticated user's identity and the current process state. It is a pure
// data value so the gating logic can be unit-tested without performing the
// destructive Setresuid/Setresgid syscalls.
type privDropPlan struct {
	// Drop is true when dropPrivileges should perform the syscalls.
	Drop bool
	// Skip is true when dropping is intentionally a no-op (e.g. the target is
	// already the current identity, or the process is not privileged enough).
	Skip bool
	// Reason is a human-readable explanation for logging.
	Reason string
	// UID/GID/Groups are the target identity used when Drop is true.
	UID    int
	GID    int
	Groups []int
}

// decidePrivDrop computes the privilege-drop plan for a target uid/gid given
// the process's current euid. It is pure (no syscalls) so it can be tested.
//
// Rules:
//   - Not root (euid != 0): cannot change uid; Skip with a warning reason.
//   - Target uid == current euid: nothing to do; Skip (no-op, still "works").
//   - Otherwise: Drop to the target identity.
func decidePrivDrop(euid, targetUID, targetGID int, groups []int) privDropPlan {
	if euid != 0 {
		return privDropPlan{
			Skip:   true,
			Reason: fmt.Sprintf("not running as root (euid=%d); cannot drop to uid=%d", euid, targetUID),
			UID:    targetUID, GID: targetGID, Groups: groups,
		}
	}
	if targetUID == euid {
		// Dropping to the current (root) identity is a no-op but must still
		// succeed — the serving path continues unchanged.
		return privDropPlan{
			Skip:   true,
			Reason: fmt.Sprintf("target uid=%d equals current euid; no drop needed", targetUID),
			UID:    targetUID, GID: targetGID, Groups: groups,
		}
	}
	return privDropPlan{
		Drop:   true,
		Reason: fmt.Sprintf("dropping to uid=%d gid=%d", targetUID, targetGID),
		UID:    targetUID, GID: targetGID, Groups: groups,
	}
}

// dropPrivileges permanently drops the WHOLE PROCESS (all OS threads) to the
// given uid/gid and supplementary groups.
//
// It uses the Go standard library syscall package on purpose: since Go 1.16 the
// stdlib Setresuid/Setresgid/Setgroups (and the Setuid/Setgid family) are
// implemented as process-wide operations — the runtime coordinates every thread
// so the credential change applies to all of them, not just the caller. This is
// exactly what we need: a goroutine that later runs on a different thread (e.g.
// the async CHANGE_NOTIFY handler) must also be unprivileged. The raw
// golang.org/x/sys/unix calls only affect the calling thread and would leave a
// security hole, so they must NOT be used here.
//
// The order is mandatory: set supplementary groups, then gid, then uid LAST —
// once uid is dropped you can no longer change the group set. Saved-ids are set
// equal to the real/effective ids so privileges cannot be regained.
func dropPrivileges(uid, gid int, groups []int) error {
	plan := decidePrivDrop(syscall.Geteuid(), uid, gid, groups)
	return applyPrivDrop(plan)
}

// ShouldUsePrivdropWorker reports whether the listener should serve connections
// via re-exec workers. It is pure (decision uses the supplied euid) so the
// gating can be unit-tested.
//
// The worker model is used when:
//   - explicit is true (the operator set PerUserPrivdrop), OR
//   - the process is root (euid==0) AND at least one configured user maps to a
//     non-root SystemUID (auto-enable: there is something meaningful to drop to).
//
// In all other cases connections are served in-process unchanged. When explicit
// is true but euid!=0, the caller should warn — drops will be skipped per
// connection, but we still avoid changing behavior silently.
func ShouldUsePrivdropWorker(explicit bool, euid int, users []config.UserConfig) bool {
	if explicit {
		return true
	}
	if euid != 0 {
		return false
	}
	for _, u := range users {
		if u.SystemUID != 0 {
			return true
		}
	}
	return false
}

// reExecWorker launches a worker child for the accepted connection. It passes
// the connection's underlying fd as the child's fd 3 via ExtraFiles, marks the
// child with GOSAMBA_WORKER=1, and re-uses the parent's argv so the child
// re-parses the identical configuration from scratch (no secrets cross the
// process boundary — only the socket fd). The parent does NOT serve the
// connection itself.
//
// The caller is responsible for closing its own copy of conn after this
// returns; reExecWorker only duplicates the fd into the child.
//
// It returns errWorkerLimit without spawning anything when maxConcurrentWorkers
// workers are already alive; the slot is held for the child's whole lifetime and
// returned by the reaper goroutine below.
func reExecWorker(conn net.Conn, log *slog.Logger) error {
	if !workerSlots.acquire() {
		return errWorkerLimit
	}
	// Every path from here that does not hand the slot to a running child must
	// give it back, or the limit ratchets down to zero on repeated failures.
	spawned := false
	defer func() {
		if !spawned {
			workerSlots.release()
		}
	}()

	fc, ok := conn.(filer)
	if !ok {
		return fmt.Errorf("connection %T does not expose a file descriptor", conn)
	}
	f, err := fc.File()
	if err != nil {
		return fmt.Errorf("conn.File: %w", err)
	}
	// f is a dup of the conn's fd; the worker inherits it. Close our copy once
	// the child has started.
	defer f.Close()

	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	guid, err := serverGuid()
	if err != nil {
		return fmt.Errorf("server guid: %w", err)
	}
	cmd.Env = append(os.Environ(), workerEnvKey+"=1", serverGuidEnvKey+"="+hex.EncodeToString(guid[:]))
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{f} // lands as fd 3 in the child

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}
	spawned = true
	// Reap the child asynchronously so we don't leave zombies. The parent does
	// not block on the worker — each worker owns its connection independently.
	// Reaping is also what frees the concurrency slot, so the bound tracks live
	// worker processes rather than accepted connections.
	go func() {
		defer workerSlots.release()
		if werr := cmd.Wait(); werr != nil {
			log.Warn("worker exited", "pid", cmd.Process.Pid, "err", werr)
		}
	}()
	log.Info("worker spawned", "pid", cmd.Process.Pid)
	return nil
}

// filer is satisfied by *net.TCPConn (and other *net.*Conn types) which expose
// File() to obtain a dup of the underlying socket fd.
type filer interface {
	File() (*os.File, error)
}

// resolveSupplementaryGroups returns the group ids to install before dropping
// to a system account: its primary gid first, followed by every supplementary
// group the account belongs to.
//
// This must be resolved explicitly. The process starts as root, and root's
// group set is inherited by anything that does not replace it — so a worker
// that dropped uid/gid without calling setgroups would keep root's groups (e.g.
// wheel/admin) alongside an unprivileged uid. Conversely, dropping with only
// the primary gid silently denies the user every group-granted path on the
// share. Neither is acceptable, so the account's real group set is looked up.
//
// Lookup is by uid rather than by the configured system_user string, because
// system_user may be a bare uid or a "uid/gid" pair (see config.Validate) and
// SystemUID is the id the drop actually targets.
//
// Portability note: with CGO_ENABLED=0 (how the release binaries are built)
// os/user is the pure-Go implementation on Linux, which reads /etc/passwd and
// /etc/group directly. Accounts that exist only in a non-file NSS source
// (LDAP/SSSD/winbind) therefore resolve with fewer groups than getgrouplist
// would return. That direction is fail-safe — the drop grants less, never more
// — but it is a real functional limitation of cgo-less Linux builds. darwin is
// unaffected: os/user calls libSystem's getgrouplist there even without cgo.
func resolveSupplementaryGroups(uid, gid int) ([]int, error) {
	acct, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	ids, err := acct.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("group ids for uid %d: %w", uid, err)
	}
	// The primary gid leads the list, matching what initgroups(3) installs.
	groups := make([]int, 0, len(ids)+1)
	seen := map[int]bool{gid: true}
	groups = append(groups, gid)
	for _, s := range ids {
		n, cerr := strconv.Atoi(s)
		if cerr != nil {
			return nil, fmt.Errorf("group id %q for uid %d: %w", s, uid, cerr)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		groups = append(groups, n)
	}
	return groups, nil
}

// privDropGroups resolves the group set for a drop to uid/gid, degrading safely
// (primary gid only) if the account cannot be resolved and truncating to the
// platform's group limit. Every failure mode here reduces the credentials the
// worker ends up with; none can widen them.
func privDropGroups(uid, gid int, log *slog.Logger) []int {
	groups, err := resolveSupplementaryGroups(uid, gid)
	if err != nil {
		// Fail closed. Dropping with the primary gid alone may cost the user
		// access to group-readable paths, but it never leaves root's groups in
		// place, which is the outcome that actually matters here.
		log.Warn("could not resolve supplementary groups; dropping with primary gid only",
			"err", err, "uid", uid, "gid", gid)
		return []int{gid}
	}
	if len(groups) > maxSupplementaryGroups {
		log.Warn("supplementary group list exceeds the platform limit; truncating",
			"uid", uid, "have", len(groups), "limit", maxSupplementaryGroups)
		groups = groups[:maxSupplementaryGroups]
	}
	return groups
}

// RunWorker is the entrypoint for a re-exec'd worker process. It reconstructs
// the connection from the inherited fd 3, runs the full SMB serving loop, and
// returns when the connection ends. The worker serves exactly one connection.
//
// opts must already be populated with Users/Shares/etc parsed from the same
// argv as the parent. RunWorker installs an OnAuthenticated hook that performs
// the one-time privilege drop after the user is resolved.
//
// Limitation — byte-range locking: sharedLockManager is process-global by
// design (see lockmanager.go), because on darwin it IS the lock table: locks
// live in an in-process (dev,ino)-keyed map rather than in the kernel. The
// re-exec worker model puts every connection in its own process, so on darwin
// that invariant cannot hold — two connections served by different workers
// consult different tables and can both be granted conflicting exclusive locks
// on the same byte range of the same file. Linux is unaffected: its locks are
// kernel OFD locks, which are enforced across processes. There is no in-process
// fix; honouring SMB locking under --per-user-privdrop on darwin would need a
// lock broker in the parent. Until then, treat --per-user-privdrop on darwin as
// "privilege isolation, no cross-connection lock enforcement".
func RunWorker(ctx context.Context, log *slog.Logger, maxFrame uint32, opts ConnOptions) error {
	f := os.NewFile(uintptr(workerConnFD), "gosamba-conn")
	if f == nil {
		return errors.New("worker: no inherited connection fd")
	}
	conn, err := net.FileConn(f)
	// net.FileConn dups the fd; close our original handle either way.
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("worker: reconstruct conn: %w", err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
	}

	// The privilege drop performed in OnAuthenticated below uses the stdlib
	// syscall.Setres{u,g}id, which the Go runtime applies to ALL OS threads of
	// the process. There is therefore no need (and it would be misleading) to
	// pin this goroutine to a thread: every goroutine — including the async
	// CHANGE_NOTIFY handler that may run on a different thread — observes the
	// dropped, unprivileged identity once the drop completes.

	// Install the one-time privilege-drop hook. Guarded so a second
	// SESSION_SETUP requesting a *different* uid after a drop is rejected (we
	// cannot re-drop within a process). Same-uid re-auth is allowed.
	var dropped bool
	var droppedUID = -1
	opts.OnAuthenticated = func(sess *Session) error {
		uid, gid := sess.User.SystemUID, sess.User.SystemGID
		if dropped {
			if uid == droppedUID {
				return nil // same identity re-authenticating: fine
			}
			return fmt.Errorf("worker already dropped to uid=%d; refusing second user uid=%d on same connection", droppedUID, uid)
		}
		plan := decidePrivDrop(syscall.Geteuid(), uid, gid, nil)
		if plan.Skip {
			log.Warn("privilege drop skipped", "reason", plan.Reason,
				"smb_user", sess.User.Name, "uid", uid, "gid", gid)
			dropped = true
			droppedUID = uid
			return nil
		}
		// Resolve the target account's groups only once we know we are really
		// dropping, and do it while still root: applyPrivDrop installs them
		// with setgroups, which only root may call — hence its fixed
		// setgroups → setgid → setuid order.
		plan.Groups = privDropGroups(uid, gid, log)
		if err := applyPrivDrop(plan); err != nil {
			return fmt.Errorf("privilege drop: %w", err)
		}
		log.Info("privileges dropped", "smb_user", sess.User.Name, "uid", uid, "gid", gid, "groups", plan.Groups)
		dropped = true
		droppedUID = uid
		return nil
	}

	ServeConn(ctx, conn, log, maxFrame, opts)
	return nil
}
