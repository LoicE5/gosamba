package parent

import (
	"sync"

	"golang.org/x/sys/unix"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// Share-mode (deny-mode) enforcement — MS-SMB2 §3.3.5.9.
//
// Every SMB2 CREATE carries a ShareAccess mask saying which *other* opens the
// client is willing to tolerate on the same file. It is the only mechanism SMB
// offers for whole-file mutual exclusion, and a large amount of software leans
// on it: SQLite's -journal/-wal side files, Office lock files, Xcode, Photos
// libraries. The server is the only place it can be enforced — macOS keeps no
// cross-client bookkeeping of its own. smbfs_get_rights_shareMode() turns
// O_SHLOCK into deny-write and O_EXLOCK into deny-all, puts that on the wire,
// and then relies entirely on the server answering STATUS_SHARING_VIOLATION,
// which it maps to EBUSY. Decoding ShareAccess and discarding it means two
// machines can both take an exclusive open and neither is told.
//
// Scope: the table is process-global, for the same reason sharedLockManager is
// (see lockmanager.go). A per-connection table would let two clients hold
// mutually-exclusive opens on the same file and never see each other, which is
// exactly the bug.
//
// Keying: by file identity (device + inode), never by path. Hard links give one
// file two names, and the normalization-insensitive resolver
// (vfs.ResolveSecureNorm) lets the same file arrive under different byte
// sequences. Both must land on the same entry.

// SMB2 SHARE_ACCESS bits (MS-SMB2 §2.2.13). A zero mask denies everything.
const (
	shareAccessRead   uint32 = 0x00000001 // FILE_SHARE_READ
	shareAccessWrite  uint32 = 0x00000002 // FILE_SHARE_WRITE
	shareAccessDelete uint32 = 0x00000004 // FILE_SHARE_DELETE
)

// The DesiredAccess bits that make an open count as "reading", "writing" or
// "deleting" for the sharing check. These follow Windows' IoCheckShareAccess:
// only data access and DELETE participate — FILE_READ_ATTRIBUTES,
// READ_CONTROL, SYNCHRONIZE and the EA bits do not, so a pure stat-style open
// never trips a deny mode.
//
// MAXIMUM_ALLOWED (0x02000000) is deliberately absent. Windows resolves it to
// the access it actually granted; we grant the file's full POSIX-derived mask,
// so resolving it the same way would turn every MAXIMUM_ALLOWED open into
// read+write+delete and refuse ordinary deny-write opens alongside it. Treating
// it as requesting nothing is the permissive choice, and a false
// STATUS_SHARING_VIOLATION is far more visible than a missed one.
const (
	sharingReadAccess = smb2.AccessFileReadData | accFileExecute |
		smb2.AccessGenericRead | smb2.AccessGenericExecute | smb2.AccessGenericAll

	sharingWriteAccess = smb2.AccessFileWriteData | smb2.AccessFileAppendData |
		smb2.AccessGenericWrite | smb2.AccessGenericAll

	sharingDeleteAccess = accDelete | smb2.AccessGenericAll
)

// sharingAttrOnlyAccess is the set of DesiredAccess bits that, on their own,
// make an open "attribute only": it reads or writes metadata and never touches
// the file's data or its name.
//
// Two opens that disagree on this are exempt from the sharing check entirely,
// in both directions — an attribute open neither trips another handle's deny
// mode nor imposes its own. macOS issues these constantly (DesiredAccess
// 0x00100080 = SYNCHRONIZE|FILE_READ_ATTRIBUTES is all over a normal trace)
// and smbfs_get_rights_shareMode can hand them a deny-all ShareAccess, so
// honouring that deny mode refuses ordinary data opens on behalf of a handle
// that is not reading or writing anything. ksmbd draws the same exemption:
// fp->attrib_only in fs/smb/server/smb2pdu.c and the
// "prev_fp->attrib_only != curr_fp->attrib_only" skip in
// fs/smb/server/smb_common.c.
const sharingAttrOnlyAccess = accFileReadAttributes | accFileWriteAttributes | accSynchronize

// shareModeEntry is one live open's contribution to a file's share state: what
// it asked to do, and what it will let others do.
//
// The access side records the CREATE's *requested* DesiredAccess, not
// Open.GrantedAccess. GrantedAccess in this server is the maximal mask the
// object's POSIX permissions allow (see maxaccess.go) and is deliberately not
// narrowed to the request, so using it here would make every handle look like
// it wanted read+write+delete and would refuse practically every deny-write
// open. On Windows the granted mask equals the requested one, so checking the
// request is the faithful reading of §3.3.5.9 for this server.
type shareModeEntry struct {
	owner *Open
	read  bool
	write bool
	del   bool
	// attrOnly marks an open whose DesiredAccess is entirely within
	// sharingAttrOnlyAccess. See that constant for why it is exempt.
	attrOnly bool
	shared   uint32 // the open's ShareAccess mask
}

func newShareModeEntry(owner *Open, desired, share uint32) shareModeEntry {
	return shareModeEntry{
		owner:    owner,
		read:     desired&sharingReadAccess != 0,
		write:    desired&sharingWriteAccess != 0,
		del:      desired&sharingDeleteAccess != 0,
		attrOnly: desired&^sharingAttrOnlyAccess == 0,
		shared:   share,
	}
}

// shareConflict applies the MS-SMB2 §3.3.5.9 sharing-access check in both
// directions: what the newcomer wants must be permitted by what the existing
// open shares, AND what the existing open is doing must be permitted by what
// the newcomer shares. Either violation is STATUS_SHARING_VIOLATION.
func shareConflict(existing, incoming shareModeEntry) bool {
	// Opens that disagree about being attribute-only never conflict, in either
	// direction. See sharingAttrOnlyAccess.
	if existing.attrOnly != incoming.attrOnly {
		return false
	}
	// Does the existing open let the newcomer in?
	if incoming.read && existing.shared&shareAccessRead == 0 {
		return true
	}
	if incoming.write && existing.shared&shareAccessWrite == 0 {
		return true
	}
	if incoming.del && existing.shared&shareAccessDelete == 0 {
		return true
	}
	// Does the newcomer tolerate what the existing open is already doing?
	if existing.read && incoming.shared&shareAccessRead == 0 {
		return true
	}
	if existing.write && incoming.shared&shareAccessWrite == 0 {
		return true
	}
	if existing.del && incoming.shared&shareAccessDelete == 0 {
		return true
	}
	return false
}

// shareModeTable is the process-global set of live share reservations.
//
// byFile is the conflict index; owners is the reverse index that makes release
// O(1) without adding a field to Open. Keeping the back-pointer here rather
// than on the handle means there is no new struct field for a future code path
// to forget to populate — an Open either appears in owners or holds nothing.
type shareModeTable struct {
	mu     sync.Mutex
	byFile map[fileKey][]shareModeEntry
	owners map[*Open]fileKey
}

func newShareModeTable() *shareModeTable {
	return &shareModeTable{
		byFile: make(map[fileKey][]shareModeEntry),
		owners: make(map[*Open]fileKey),
	}
}

// sharedShareModes is the process-global share-mode table. It MUST be a single
// instance for the whole process: deny modes only prevent client-vs-client
// conflicts if every connection consults the same table. This mirrors
// sharedLockManager, which exists for exactly the same reason.
var sharedShareModes = newShareModeTable()

// shareKeyForFd returns the (device, inode) identity of the file behind fd.
//
// Both key constructors widen st.Dev the same way on purpose. st_dev is int32
// on darwin and uint64 on linux; a plain uint64() conversion sign-extends a
// negative darwin dev, which is fine as long as *every* key is built the same
// way. (devToUint64 in dispatch.go widens without sign extension because the
// QFid wire field must match what the client's own stat reports; mixing the two
// here would put the same file under two different keys.)
func shareKeyForFd(fd int) (fileKey, bool) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileKey{}, false
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}, true
}

// shareKeyForPath returns the (device, inode) identity of path without
// following a final symlink, for the pre-open check.
func shareKeyForPath(path string) (fileKey, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fileKey{}, false
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}, true
}

// shareModeApplies reports whether a handle participates in share-mode
// accounting at all.
//
// Three kinds of handle are deliberately exempt:
//
//   - Directories. macOS opens directories constantly — for enumeration, for
//     CHANGE_NOTIFY, as the tree root — and nothing in the deny-mode use cases
//     this check exists for (SQLite side files, Office lock files) is a
//     directory. Honouring a directory deny mode would risk serialising
//     ordinary browsing, which is a far more visible breakage than the bug.
//   - Named streams. These are synthetic in-memory buffers backed by an xattr
//     on the base file (see stream.go); they have no descriptor of their own,
//     so they would have to be keyed by the BASE file's inode. macOS opens
//     com.apple.metadata / AFP_AfpInfo / resource-fork streams on almost every
//     file it touches, and letting one of those reserve the base file's share
//     mode would refuse opens of the file itself. Deny modes over SMB are about
//     the unnamed data stream.
//   - IPC$ pipe handles, which have no file identity at all.
func shareModeApplies(o *Open) bool {
	return o != nil && !o.IsDir && !o.IsStream && !o.IsPipe && o.File != nil
}

// entryLive reports whether an entry still describes a real open on key.
//
// This is a safety net, not part of the protocol: a leaked entry makes a file
// permanently unopenable, which is strictly worse than the missing check this
// code replaces. If an entry's owner has lost its descriptor — or that
// descriptor now points at a different file — the entry is treated as dead and
// swept. Nothing depends on it triggering; every disposal path releases
// explicitly.
//
// Reading owner.File under t.mu is race-free: a handle's File field is only
// cleared after release() has removed it from this table, so no reader holding
// t.mu can still reach it.
func entryLive(e shareModeEntry, key fileKey) bool {
	if e.owner == nil || e.owner.File == nil {
		return false
	}
	k, ok := shareKeyForFd(int(e.owner.File.Fd()))
	return ok && k == key
}

// check runs the sharing-access test for a hypothetical open of key without
// reserving anything. handleCreate uses it before a disposition that would
// truncate or replace the file, so a refused open cannot destroy data on its
// way to being refused. The authoritative test is acquire.
func (t *shareModeTable) check(key fileKey, desired, share uint32) bool {
	probe := newShareModeEntry(nil, desired, share)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.byFile[key] {
		if !entryLive(e, key) {
			continue
		}
		if shareConflict(e, probe) {
			return false
		}
	}
	return true
}

// acquire runs the sharing-access test against every live open of key and, if
// it passes, records o's reservation. It returns false when the open must be
// refused with STATUS_SHARING_VIOLATION; nothing is recorded in that case.
//
// Test and insert happen under one lock so two clients racing on the same file
// cannot both be admitted.
func (t *shareModeTable) acquire(key fileKey, o *Open, desired, share uint32) bool {
	incoming := newShareModeEntry(o, desired, share)
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, dup := t.owners[o]; dup {
		// Already holds a reservation; never let one handle occupy two slots.
		return true
	}
	ents := t.byFile[key]
	kept := make([]shareModeEntry, 0, len(ents)+1)
	for _, e := range ents {
		if !entryLive(e, key) {
			delete(t.owners, e.owner)
			continue
		}
		kept = append(kept, e)
	}
	for _, e := range kept {
		if shareConflict(e, incoming) {
			t.store(key, kept)
			return false
		}
	}
	t.store(key, append(kept, incoming))
	t.owners[o] = key
	return true
}

// release drops o's reservation. It is idempotent and safe on a handle that
// never had one, so every disposal path can call it unconditionally.
func (t *shareModeTable) release(o *Open) {
	if o == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	key, ok := t.owners[o]
	if !ok {
		return
	}
	delete(t.owners, o)
	ents := t.byFile[key]
	kept := ents[:0]
	for _, e := range ents {
		if e.owner == o {
			continue
		}
		kept = append(kept, e)
	}
	t.store(key, kept)
}

// transfer moves a reservation from one *Open to another without ever giving up
// the slot. A durable-handle reclaim (DH2C/DHnC) builds a fresh Open around the
// same file and the same granted access, so the reservation must follow it
// rather than be released and re-acquired: release-then-acquire opens a window
// in which another client could take a conflicting mode, and would also let the
// reclaim fail for a reason the client cannot act on.
func (t *shareModeTable) transfer(from, to *Open) {
	if from == nil || to == nil || from == to {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	key, ok := t.owners[from]
	if !ok {
		return
	}
	delete(t.owners, from)
	ents := t.byFile[key]
	for i := range ents {
		if ents[i].owner == from {
			ents[i].owner = to
			break
		}
	}
	t.owners[to] = key
	t.byFile[key] = ents
}

// store writes back a file's entry list, dropping the map slot entirely when it
// is empty so the table does not accumulate keys for files nobody has open.
func (t *shareModeTable) store(key fileKey, ents []shareModeEntry) {
	if len(ents) == 0 {
		delete(t.byFile, key)
		return
	}
	t.byFile[key] = ents
}

// len reports how many reservations the table currently holds (test helper).
// A non-zero count once every handle has been disposed of is the leak this
// package must never have.
func (t *shareModeTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.owners)
}
