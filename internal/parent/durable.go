// Package parent durable-handle implementation.
//
// Limitation — per-user-privdrop: when --per-user-privdrop is enabled, each
// accepted TCP connection is served by a freshly re-exec'd worker process with
// its own private DurableTable. Because the table is process-local, a durable
// handle registered by one connection's worker cannot be reclaimed by a
// subsequent reconnect that arrives on a different (new) worker process.
// Clients will transparently re-open their handles; no data is lost, but the
// server cannot honour the MS-SMB2 durable-reconnect guarantee in this mode.
package parent

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// Create-context tags for durable handles and leases (MS-SMB2 §2.2.13.2).
var (
	tagDH2Q = []byte("DH2Q") // durable handle request v2
	tagDHnQ = []byte("DHnQ") // durable handle request v1
	tagDH2C = []byte("DH2C") // durable handle reconnect v2
	tagDHnC = []byte("DHnC") // durable handle reconnect v1
	tagRqLs = []byte("RqLs") // lease request
)

// Lease state bits (MS-SMB2 §2.2.13.2.8 "SMB2_CREATE_REQUEST_LEASE",
// LeaseState field). The order is READ, HANDLE, WRITE — HANDLE is 0x02 and
// WRITE is 0x04, NOT the other way round. Apple's client header agrees
// (SMBClient kernel/netsmb/smb_2.h: SMB2_LEASE_READ_CACHING 0x01,
// SMB2_LEASE_HANDLE_CACHING 0x02, SMB2_LEASE_WRITE_CACHING 0x04).
//
// Getting these backwards is not cosmetic: putting WRITE_CACHING on the wire
// when the intent was HANDLE_CACHING makes macOS clear its write-immediately
// flag and enable unsafe write-behind caching.
//
// We currently only ever grant leaseNone (see applyDurableAndLease), but the
// values must be right so that any future grant means what it says.
const (
	leaseNone          uint32 = 0x00
	leaseReadCaching   uint32 = 0x01
	leaseHandleCaching uint32 = 0x02
	leaseWriteCaching  uint32 = 0x04
)

// durableRequest is the parsed result of a fresh durable-handle request
// (DH2Q or DHnQ) extracted from a CREATE's create contexts.
type durableRequest struct {
	present bool
	v2      bool     // true for DH2Q, false for DHnQ
	timeout uint32   // requested timeout in ms (v2 only; 0 for v1)
	flags   uint32   // v2 flags (e.g. PERSISTENT)
	guid    [16]byte // CreateGuid (v2 only; zero for v1)
}

// durableReconnect is the parsed result of a reconnect request (DH2C or DHnC).
type durableReconnect struct {
	present bool
	v2      bool
	fileID  [16]byte
	guid    [16]byte // CreateGuid (v2 only)
}

// leaseRequest is the parsed RqLs create context.
//
// v1 and v2 share the same context name ("RqLs"), so the only thing that tells
// them apart is the request data length: 32 bytes is v1
// (SMB2_CREATE_REQUEST_LEASE, MS-SMB2 §2.2.13.2.8) and 52 bytes is v2
// (SMB2_CREATE_REQUEST_LEASE_V2, §2.2.13.2.10). The response must use the
// matching form or the client rejects it — clients treat a v1 response to a v2
// request as a lease failure, and directory leases are always v2.
type leaseRequest struct {
	present bool
	v2      bool // true when the request arrived in the 52-byte v2 form
	key     [16]byte
	state   uint32
}

// parseDurableContexts walks the raw create-context blob and extracts any
// durable-handle request, reconnect, and lease request present.
func parseDurableContexts(raw []byte) (durableRequest, durableReconnect, leaseRequest) {
	var dq durableRequest
	var dc durableReconnect
	var lr leaseRequest
	if len(raw) == 0 {
		return dq, dc, lr
	}
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		switch {
		case eqTag(c.Name, tagDH2Q):
			// Timeout(4) Flags(4) Reserved(8) CreateGuid(16)
			if len(c.Data) >= 32 {
				dq.present = true
				dq.v2 = true
				dq.timeout = binary.LittleEndian.Uint32(c.Data[0:])
				dq.flags = binary.LittleEndian.Uint32(c.Data[4:])
				copy(dq.guid[:], c.Data[16:32])
			}
		case eqTag(c.Name, tagDHnQ):
			// 16 reserved bytes.
			dq.present = true
			dq.v2 = false
		case eqTag(c.Name, tagDH2C):
			// FileId(16) CreateGuid(16) Flags(4)
			if len(c.Data) >= 36 {
				dc.present = true
				dc.v2 = true
				copy(dc.fileID[:], c.Data[0:16])
				copy(dc.guid[:], c.Data[16:32])
			}
		case eqTag(c.Name, tagDHnC):
			// FileId(16)
			if len(c.Data) >= 16 {
				dc.present = true
				dc.v2 = false
				copy(dc.fileID[:], c.Data[0:16])
			}
		case eqTag(c.Name, tagRqLs):
			// v1 (32 bytes): LeaseKey(16) LeaseState(4) LeaseFlags(4)
			//                LeaseDuration(8)
			// v2 (52 bytes): ... plus ParentLeaseKey(16) Epoch(2) Reserved(2)
			// The length is the only discriminator; record it so the response
			// goes back in the same form (MS-SMB2 §2.2.13.2.8 / §2.2.13.2.10).
			if len(c.Data) >= 20 {
				lr.present = true
				lr.v2 = len(c.Data) >= rqLsV2Size
				copy(lr.key[:], c.Data[0:16])
				lr.state = binary.LittleEndian.Uint32(c.Data[16:])
			}
		}
		return true
	})
	return dq, dc, lr
}

func eqTag(name, tag []byte) bool {
	if len(name) != len(tag) {
		return false
	}
	for i := range name {
		if name[i] != tag[i] {
			return false
		}
	}
	return true
}

// encodeDH2QResponse builds the DH2Q response context payload:
// Timeout(4) Flags(4).
func encodeDH2QResponse(timeout uint32, flags uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:], timeout)
	binary.LittleEndian.PutUint32(b[4:], flags)
	return b
}

// encodeDHnQResponse builds the DHnQ v1 response context payload: 8 reserved.
func encodeDHnQResponse() []byte { return make([]byte, 8) }

// RqLs create-context payload sizes. Both the request and the response use
// these exact lengths; a client that asked with one form and is answered with
// the other treats the reply as malformed (Apple's SMBClient rejects any RqLs
// response whose data length is neither 32 nor 52, and flags a version
// mismatch as a lease failure).
const (
	rqLsV1Size = 32 // LeaseKey(16) LeaseState(4) Flags(4) Duration(8)
	rqLsV2Size = 52 // ... + ParentLeaseKey(16) Epoch(2) Reserved(2)
)

// encodeRqLsResponse builds an RqLs response echoing the lease key and the
// granted lease state, in the same version the client asked with.
//
//	v1 (MS-SMB2 §2.2.14.2.10, 32 bytes):
//	    LeaseKey(16) LeaseState(4) LeaseFlags(4) LeaseDuration(8)
//	v2 (MS-SMB2 §2.2.14.2.11, 52 bytes):
//	    ... + ParentLeaseKey(16) Epoch(2) Reserved(2)
//
// Because we only ever grant LEASE_NONE, the v2 tail is all zeroes: no parent
// lease key is echoed and SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET stays clear, so
// a client will not compare the (absent) parent key, and Epoch 0 is correct for
// a lease that was never established.
func encodeRqLsResponse(key [16]byte, granted uint32, v2 bool) []byte {
	size := rqLsV1Size
	if v2 {
		size = rqLsV2Size
	}
	b := make([]byte, size)
	copy(b[0:16], key[:])
	binary.LittleEndian.PutUint32(b[16:], granted)
	return b
}

// durableKey identifies a durable-handle table entry. Keying by both the
// client's NEGOTIATE GUID and the per-open CreateGuid (v2) means a reconnect
// from the same client machine can reclaim its handle even across a dropped
// TCP connection. For v1 durable handles (no CreateGuid) the FileID stands in
// for the CreateGuid slot.
type durableKey struct {
	clientGuid [16]byte
	createGuid [16]byte
}

// durableEntry is a reclaimable open kept alive past its Connection's death
// until the deadline expires.
type durableEntry struct {
	open *Open
	// deadline is the instant this entry stops being reclaimable. It is only
	// meaningful once the entry is detached: while the owning connection is
	// still alive the entry is ATTACHED and deadline is the zero time, meaning
	// "not counting down". Starting the clock at CREATE instead would let the
	// sweeper close the fd of a handle a live client is still using.
	deadline time.Time
	// timeout is how long the entry stays reclaimable after it detaches.
	timeout   time.Duration
	shareName string // original share name; reconnect must arrive on same share
	// userName is the SMB user that opened the handle. A reconnect from a
	// different principal must not be able to take it over (MS-SMB2 §3.3.5.9.7
	// requires the reclaim to be made by the same security context).
	userName string
}

// attached reports whether the entry still belongs to a live connection, in
// which case it never expires.
func (e *durableEntry) attached() bool { return e.deadline.IsZero() }

// expired reports whether a detached entry is past its deadline.
func (e *durableEntry) expired(now time.Time) bool {
	return !e.attached() && now.After(e.deadline)
}

// releaseOpen gives up an abandoned durable open: it releases the byte-range
// locks the open still holds and closes its descriptor. Nothing else can reach
// the open once it has left the table, so skipping either step leaks a kernel
// fd and (on darwin) an entry in the process-global lock table forever.
//
// The order matters: releaseAll's key lookup does an Fstat on the fd, which
// fails — and then silently no-ops — once the file is closed.
func releaseOpen(o *Open) {
	if o == nil || o.File == nil {
		return
	}
	sharedLockManager.releaseAll(o)
	o.File.Close()
}

// DurableTable holds durable opens keyed by (ClientGuid, CreateGuid). It is
// server-scoped (created once and shared across every ServeConn) so an entry
// survives the drop of the TCP connection that created it: a client that
// reconnects within DurableTimeout can reclaim the handle.
type DurableTable struct {
	mu      sync.Mutex
	entries map[durableKey]*durableEntry
}

// NewDurableTable returns an empty, ready-to-use table.
func NewDurableTable() *DurableTable {
	return &DurableTable{entries: make(map[durableKey]*durableEntry)}
}

// Register records an open as durable. The entry starts ATTACHED: it belongs
// to a live connection and does not expire. Detach starts the timeout when that
// connection drops. The shareName and userName are stored and checked on
// reclaim (MS-SMB2 §3.3.5.9.7). A zero or negative timeout removes any existing
// entry (treated as non-durable).
//
// Register reports whether the open is now durable. It returns false — leaving
// the table untouched — when the key is already held by an entry that is still
// ATTACHED to a live connection, i.e. the client reused a CreateGuid that is
// currently in use. Overwriting that entry would orphan the previous open: the
// map slot is the only reference to it, so its descriptor could never be closed
// and its byte-range locks would stay held for the life of the process. The
// CREATE that triggered this still succeeds; it just does not get a durable
// grant, and a caller that sees false must not mark the open durable.
//
// A DETACHED entry under the same key belongs to a connection that is already
// gone, so a fresh registration legitimately supersedes it: its locks are
// released and its fd closed before the new entry takes the slot.
func (t *DurableTable) Register(clientGuid, createGuid [16]byte, open *Open, timeout time.Duration, shareName, userName string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	prev, exists := t.entries[k]
	// Re-registering the very same Open (e.g. refreshing the timeout) must not
	// touch its descriptor — it is the live handle we are about to record.
	superseded := exists && prev.open != open

	if timeout <= 0 {
		// Non-durable: drop any existing entry. A detached entry has no live
		// connection left to close its fd on teardown, so release it here; an
		// attached one is still owned by its connection, which closes it.
		if superseded && !prev.attached() {
			releaseOpen(prev.open)
		}
		delete(t.entries, k)
		return false
	}
	if superseded {
		if prev.attached() {
			// A live connection is still using this handle. Refuse rather than
			// silently clobbering (and thereby orphaning) it.
			return false
		}
		releaseOpen(prev.open)
	}
	t.entries[k] = &durableEntry{
		open:      open,
		timeout:   timeout,
		shareName: shareName,
		userName:  userName,
	}
	return true
}

// Detach marks an entry as no longer owned by a live connection and starts its
// reclaim countdown. Called during connection teardown; entries left attached
// would never expire, and entries expired from CREATE time would have their fd
// closed while still in use.
func (t *DurableTable) Detach(clientGuid, createGuid [16]byte) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[durableKey{clientGuid: clientGuid, createGuid: createGuid}]
	if !ok || !e.attached() {
		return
	}
	e.deadline = time.Now().Add(e.timeout)
}

// Reclaim returns the live open for (clientGuid, createGuid) and removes it from
// the table. It returns ok=false if no entry exists or the entry has expired
// (expired entries are evicted, and their open fd is closed to avoid leaks).
func (t *DurableTable) Reclaim(clientGuid, createGuid [16]byte) (*Open, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	e, ok := t.entries[k]
	if !ok {
		return nil, false
	}
	delete(t.entries, k)
	if e.expired(time.Now()) {
		// Lazy eviction: close the fd so we don't leak it. On darwin, locks
		// held by this open do not survive durable expiry (unlike linux OFD
		// locks, which the kernel releases automatically on close anyway) —
		// release the in-process ranges before closing so the global lock
		// table doesn't leak entries for a file we'll never touch again.
		releaseOpen(e.open)
		return nil, false
	}
	return e.open, true
}

// reclaimForReconnect is the DH2C/DHnC reconnect path. On top of the share and
// user checks it refuses any entry that is still ATTACHED: per MS-SMB2
// §3.3.5.9.7 a durable reconnect is only valid against an open whose Connection
// is gone. Without this a second connection presenting the same (ClientGuid,
// CreateGuid) could steal a live handle — and the fd — out from under the
// connection that is still using it.
func (t *DurableTable) reclaimForReconnect(clientGuid, createGuid [16]byte, shareName, userName string) (*Open, bool) {
	return t.reclaimChecked(clientGuid, createGuid, shareName, userName, true)
}

// reclaimChecked is the shared core of the reclaim paths. A failed
// check never consumes the entry, so a rejected attempt cannot be used to evict
// another connection's handle.
func (t *DurableTable) reclaimChecked(clientGuid, createGuid [16]byte, shareName, userName string, requireDetached bool) (*Open, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	e, ok := t.entries[k]
	if !ok {
		return nil, false
	}
	if e.expired(time.Now()) {
		// Lazy eviction: close the fd so we don't leak it. Release ranges
		// first (see the equivalent comment in Reclaim above).
		releaseOpen(e.open)
		delete(t.entries, k)
		return nil, false
	}
	// Still owned by a live connection: this is not a reconnect, it is a
	// takeover attempt. Reject without disturbing the entry.
	if requireDetached && e.attached() {
		return nil, false
	}
	// Share mismatch: reject without consuming the entry.
	if e.shareName != shareName {
		return nil, false
	}
	// Identity mismatch: a durable handle may only be reclaimed by the same
	// SMB user that opened it. Without this a second authenticated user who
	// learned the (ClientGuid, CreateGuid) pair could adopt another user's
	// open file handle, inheriting its granted access.
	if e.userName != userName {
		return nil, false
	}
	delete(t.entries, k)
	return e.open, true
}

// Has reports whether the table has a live (non-expired) entry for the given
// (clientGuid, createGuid) pair. It is used during connection teardown to
// distinguish durable opens (which must stay alive for reclaim) from ordinary
// opens (whose fds should be closed).
func (t *DurableTable) Has(clientGuid, createGuid [16]byte) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	e, ok := t.entries[k]
	if !ok {
		return false
	}
	return !e.expired(time.Now())
}

// StartSweeper launches a background goroutine that calls Expire at regular
// intervals until ctx is cancelled. It should be called once after the table
// is created.
func (t *DurableTable) StartSweeper(ctx context.Context, interval time.Duration) {
	if t == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.Expire(time.Now())
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Remove deletes the entry for (clientGuid, createGuid) — used on a clean CLOSE
// of a durable handle (a clean close means the handle is not reclaimable).
func (t *DurableTable) Remove(clientGuid, createGuid [16]byte) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, durableKey{clientGuid: clientGuid, createGuid: createGuid})
}

// Expire evicts every entry whose deadline is before now, closing the
// underlying file handle so we don't leak descriptors. It returns the number
// of entries evicted.
func (t *DurableTable) Expire(now time.Time) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, e := range t.entries {
		if e.expired(now) {
			// Release ranges first (see the equivalent comment in Reclaim).
			releaseOpen(e.open)
			delete(t.entries, k)
			n++
		}
	}
	return n
}

// len reports the current entry count (test helper).
func (t *DurableTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// durableLookupKey returns the CreateGuid slot used as the table key for a
// reconnect: the real CreateGuid for v2, or the FileID for v1 (which carries
// no CreateGuid).
func durableLookupKey(rec durableReconnect) [16]byte {
	if rec.v2 {
		return rec.guid
	}
	return rec.fileID
}

// handleDurableReconnect attempts to reclaim a durable open for a DH2C/DHnC
// reconnect. On success it re-opens the backing file, restores the original
// FileID into the new session, writes a SUCCESS CREATE response echoing the
// reconnect context, and returns true. It returns false if no live entry
// exists (caller then sends OBJECT_NAME_NOT_FOUND).
func (d *Dispatcher) handleDurableReconnect(rw io.ReadWriter, hdr smb2.Header, sess *Session, tree *Tree, rec durableReconnect) bool {
	if d.Conn == nil || d.Conn.Durable == nil {
		return false
	}
	saved, ok := d.Conn.Durable.reclaimForReconnect(d.Conn.ClientGuid, durableLookupKey(rec), tree.Share.Name, sess.User.Name)
	if !ok {
		return false
	}
	// reclaimForReconnect above already enforced all three MS-SMB2 §3.3.5.9.7
	// preconditions — same share, same user, and the owning connection gone —
	// so saved is non-nil only for a legitimate reconnect.

	// The saved descriptor belonged to the dropped connection; close it so we
	// don't leak the fd, then re-open fresh below. Release its byte-range
	// locks first: on darwin, locks do not survive a durable reclaim (unlike
	// linux OFD locks, which live in the kernel and are unaffected by which
	// *os.File we're using); this is an accepted darwin limitation. Doing
	// this also prevents the global lock table from leaking entries.
	releaseOpen(saved)

	// Re-open the backing file with a fresh descriptor on the same path. The
	// original *os.File belonged to the dropped connection; we cannot assume
	// it is still valid, so we always re-open.
	open := &Open{
		FileID:            saved.FileID,
		Path:              saved.Path,
		IsDir:             saved.IsDir,
		Tree:              tree,
		GrantedAccess:     saved.GrantedAccess,
		DeleteOnClose:     saved.DeleteOnClose,
		IsDurable:         true,
		DurableClientGuid: d.Conn.ClientGuid,
		DurableCreateGuid: durableLookupKey(rec),
	}
	var st os.FileInfo
	if !open.IsDir {
		f, err := os.OpenFile(open.Path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			f, err = os.OpenFile(open.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				// The file vanished while detached — treat as no longer
				// reclaimable.
				return false
			}
		}
		open.File = f
		st, _ = f.Stat()
	} else {
		st, _ = os.Lstat(open.Path)
	}

	sess.AddOpen(open)
	// Re-register so a subsequent drop can reclaim again. The reclaim above
	// removed the entry, so the slot is normally free; it can only be taken
	// again if a racing connection registered the same CreateGuid in between.
	// In that case leave this open non-durable — clobbering the racer's live
	// entry is exactly the orphaning Register refuses to do — so that teardown
	// closes our fd instead of leaving it for a reclaim that can never happen.
	if !d.Conn.Durable.Register(open.DurableClientGuid, open.DurableCreateGuid, open, d.Conn.DurableTimeout, tree.Share.Name, sess.User.Name) {
		open.IsDurable = false
		d.Log.Warn("durable handle re-registration refused after reconnect; handle is not reclaimable",
			"path", open.Path, "share", tree.Share.Name)
	}
	d.LastCreatedFileID = open.FileID
	d.HasLastCreated = true

	attrs := uint32(smb2.FileAttrNormal)
	var allocSize, endOfFile uint64
	if open.IsDir {
		attrs = smb2.FileAttrDirectory
	} else if st != nil {
		allocSize = uint64(st.Size())
		endOfFile = uint64(st.Size())
	}
	mtime := filetimeFromTime(time.Now())
	if st != nil {
		mtime = filetimeFromTime(st.ModTime())
	}

	// Echo the reconnect context back so the client knows the handle was
	// reclaimed: DH2C is acknowledged with a DH2Q response context.
	var echo []smb2.CreateContext
	if rec.v2 {
		echo = append(echo, smb2.CreateContext{
			Name: tagDH2Q,
			Data: encodeDH2QResponse(uint32(d.Conn.DurableTimeout/time.Millisecond), 0),
		})
	} else {
		echo = append(echo, smb2.CreateContext{Name: tagDHnQ, Data: encodeDHnQResponse()})
	}

	resp := smb2.EncodeCreateResponse(smb2.CreateResponse{
		CreateAction:   smb2.CreateActionOpened,
		CreationTime:   mtime,
		LastAccessTime: mtime,
		LastWriteTime:  mtime,
		ChangeTime:     mtime,
		AllocationSize: allocSize,
		EndOfFile:      endOfFile,
		FileAttributes: attrs,
		FileID:         open.FileID,
		CreateContexts: smb2.EncodeCreateContexts(echo),
	})
	d.respondSuccess(rw, hdr, sess, resp)
	return true
}

// applyDurableAndLease registers a fresh durable open (DH2Q/DHnQ) and appends
// the matching response contexts plus an RqLs lease grant to baseCtxs. The
// returned blob is the full, re-encoded create-context list for the response.
func (d *Dispatcher) applyDurableAndLease(open *Open, dq durableRequest, lr leaseRequest, baseCtxs []byte, userName string) []byte {
	// Decode the AAPL/MxAc contexts already built so we can append to them.
	var ctxs []smb2.CreateContext
	if len(baseCtxs) > 0 {
		smb2.IterateCreateContexts(baseCtxs, func(c smb2.CreateContext) bool {
			ctxs = append(ctxs, smb2.CreateContext{
				Name: append([]byte(nil), c.Name...),
				Data: append([]byte(nil), c.Data...),
			})
			return true
		})
	}

	if dq.present && d.Conn != nil && d.Conn.Durable != nil && d.Conn.DurableTimeout > 0 {
		// Clamp the requested timeout to the server cap.
		timeout := d.Conn.DurableTimeout
		if dq.v2 && dq.timeout > 0 {
			req := time.Duration(dq.timeout) * time.Millisecond
			if req < timeout {
				timeout = req
			}
		}
		clientGuid := d.Conn.ClientGuid
		createGuid := dq.guid
		if !dq.v2 {
			// v1 has no CreateGuid; key the entry by the FileID instead.
			createGuid = open.FileID
		}
		shareName := ""
		if open.Tree != nil {
			shareName = open.Tree.Share.Name
		}
		// Only mark the open durable — and only advertise the grant — if the
		// table actually took it. Register refuses a CreateGuid that another
		// LIVE connection is already using, because taking that slot would
		// orphan the other connection's descriptor.
		if d.Conn.Durable.Register(clientGuid, createGuid, open, timeout, shareName, userName) {
			open.IsDurable = true
			open.DurableClientGuid = clientGuid
			open.DurableCreateGuid = createGuid

			if dq.v2 {
				ctxs = append(ctxs, smb2.CreateContext{
					Name: tagDH2Q,
					Data: encodeDH2QResponse(uint32(timeout/time.Millisecond), 0),
				})
			} else {
				ctxs = append(ctxs, smb2.CreateContext{Name: tagDHnQ, Data: encodeDHnQResponse()})
			}
		} else {
			// The CREATE still succeeds, just without durability; the client
			// re-opens by path after a disconnect instead of reclaiming.
			d.Log.Warn("durable handle request refused: CreateGuid is in use by a live open",
				"path", open.Path, "share", shareName, "user", userName)
		}
	}

	if lr.present {
		// Grant NO caching (LEASE_NONE). A read-caching lease is a promise that
		// the server will send a lease break before the file changes under the
		// client; we implement no lease-break machinery (OPLOCK_BREAK is
		// answered STATUS_INVALID_OPLOCK_PROTOCOL and nothing ever sends an
		// unsolicited break), so a client that trusted a read lease would keep serving
		// stale data indefinitely whenever another opener — or a process on the
		// server itself — modified the file. Echoing LEASE_NONE keeps the
		// client re-reading from the server, which is always correct.
		ctxs = append(ctxs, smb2.CreateContext{
			Name: tagRqLs,
			Data: encodeRqLsResponse(lr.key, leaseNone, lr.v2),
		})
	}

	return smb2.EncodeCreateContexts(ctxs)
}
