package parent

import (
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
)

// Server-scoped session ownership.
//
// MS-SMB2 §3.3.5.5.3 requires the server to close the session named by
// PreviousSessionId when a client re-authenticates. The interesting case — and
// the one macOS actually hits — is a client whose own side broke (a Wi-Fi flap)
// reconnecting on a NEW TCP connection while the server still believes the old
// one is alive. SessionTable is created per ServeConn, so the old session is
// not reachable from the new connection at all; without a server-scoped index
// the old session's descriptors, byte-range locks, share-mode reservations,
// resume keys and change-notify watches survive until the idle reaper runs, and
// those stale reservations block the very client that just reconnected.
//
// Why an explicitly threaded table (the DurableTable precedent) rather than a
// process-global var (sharedLockManager / sharedShareModes): those two are
// global because they arbitrate between *different clients* and a correct
// answer is impossible unless there is exactly one of them in the process. This
// index is not an arbiter — it is server state, it is only ever consulted by
// the server that owns the listener, and a test (or a second Server in one
// process) must be able to have its own. DurableTable is server-scoped for
// exactly that reason and is threaded through ConnOptions; this follows it.
//
// --- lock order -------------------------------------------------------------
//
// The total order for the whole package, outermost first. A goroutine may hold
// several of these only in this order, and may skip levels.
//
//	1. SessionIndex.mu
//	2. SessionTable.mu
//	3. Open.mu
//	4. Session.mu
//	5. asyncTable.mu
//	6. DurableTable.mu
//	7. shareModeTable.mu
//	8. resumeKeyTable.mu, lockManager's internal mutex
//
// Levels 3→4 is the pre-existing dispatcher nesting (lockOpenForMessage holds
// the handle for the length of a message, and handlers then call
// Session.AddOpen / RemoveOpen). 2→4 is connection teardown ranging the session
// table. 6→7 and 4→7 are the orderings the concurrency work recorded.
//
// SessionIndex.mu is the new one, and it is the strictest: it is NEVER held
// while any other lock in this list is taken. supersede does its whole lookup,
// its identity check and its removal under the index lock, releases it, and
// only then calls into the owning connection. That is what keeps a
// cross-connection teardown from introducing any new ordering at all — the
// index lock has no edges out of it.

// nextSessionID allocates SMB2 SessionIds for the whole process.
//
// It has to be process-wide, not per SessionTable. SessionIds used to come from
// a per-table counter that started at the same value on every connection, so
// connection A and connection B both had a session 2. A PreviousSessionId of 2
// would then be ambiguous the moment the index could see more than one
// connection — the client would name its own old session and the server could
// pick someone else's. MS-SMB2 §3.3.5.5.3 only makes sense if a SessionId names
// exactly one session for the life of the server, so the counter moved here.
//
// The first id handed out is 1: zero is reserved by the protocol for "no
// session" and must never be allocated.
var nextSessionID atomic.Uint64

// allocSessionID returns a fresh, never-reused, non-zero SessionId.
func allocSessionID() uint64 { return nextSessionID.Add(1) }

// sessionHost is one connection's teardown entry point, registered with the
// index alongside every session that connection authenticates.
//
// It holds the connection-scoped state a release needs: the connection's
// session table (so the SessionId can be invalidated on the owner), its
// dispatcher (which owns the async table, the resume-key table, the durable
// table handle and the lock manager) and its Connection (for the ClientGuid
// used by the guest identity check).
type sessionHost struct {
	sessions *SessionTable
	disp     *Dispatcher
	conn     *Connection
	log      *slog.Logger
}

func (h *sessionHost) clientGuid() [16]byte {
	if h == nil || h.conn == nil {
		return [16]byte{}
	}
	return h.conn.ClientGuid
}

// closeSession tears one session down on the connection that owns it.
//
// --- the ownership rule -----------------------------------------------------
//
// A session's handles are owned by the Session.opens map, and removing an
// *Open from that map — under Session.mu, by exactly one of RemoveOpen,
// RemoveTreeAndOpens or TakeAllOpens — is what transfers ownership of the
// release to the remover. Whoever takes the handle out releases it, exactly
// once, and nobody else may. That is what makes a cross-connection teardown
// safe against a concurrent handleClose of the same handle: both of them go
// through the map, one of them gets the *Open and the other gets nil, and the
// one that got nil answers the client an error and releases nothing.
//
// Teardown is therefore three ordered steps, and the order is the protocol:
//
//  1. Remove the SessionId from the OWNING connection's SessionTable. Dispatch
//     resolves the session by id at the top of every message, so after this
//     returns no new message on that connection can reach any of these handles
//     — it is answered STATUS_USER_SESSION_DELETED instead.
//  2. TakeAllOpens. Whatever comes back is ours to release; whatever a
//     concurrent handleClose already took is its. TakeAllOpens also latches the
//     session dead, so nothing can be added behind it — step 1 alone does not
//     stop that, because handleCreate resolved its session at the top of the
//     message and can reach AddOpen long afterwards.
//  3. Release, through the owning connection's dispatcher, so the resume keys,
//     change-notify registrations and durable entries that are released are the
//     owner's own. releaseOpens takes each handle's Open.mu, which is the lock
//     the dispatcher holds for the length of every message naming that handle —
//     so an in-flight request finishes before its descriptor is closed.
//
// Step 1 still comes first, for the client rather than for safety: it is what
// makes the owner answer STATUS_USER_SESSION_DELETED instead of serving a
// session the server has decided is over.
func (h *sessionHost) closeSession(s *Session) {
	if h == nil || s == nil {
		return
	}
	if h.sessions != nil {
		h.sessions.Remove(s.ID)
	}
	opens := s.TakeAllOpens()
	if h.disp != nil {
		h.disp.releaseOpens(opens)
		return
	}
	// No dispatcher: only reachable from a unit test that built a
	// SessionSetupHandler by hand. Release what can be released without
	// connection-scoped state rather than leaking descriptors and locks.
	for _, o := range opens {
		releaseOpen(o)
	}
}

// sessionIndexEntry is one live authenticated session and the connection that
// owns it.
type sessionIndexEntry struct {
	sess *Session
	host *sessionHost
}

// SessionIndex maps SessionId to the session and to the connection that owns
// it, for the whole server. One is created where the listener lives and handed
// to every ServeConn through ConnOptions.
//
// It holds only sessions that have completed authentication. A session still
// mid-NTLM-handshake is nobody's — it has no security context to compare
// against — so a PreviousSessionId naming one finds nothing and does nothing.
//
// No entry cap: an entry is a pointer pair, and a peer that can hold N
// authenticated sessions is already holding N sessions' worth of signing and
// cipher keys, preauth state and open tables. A bound here would not change
// that exposure and would add a path where a legitimate session is silently
// invisible to its own reconnect.
type SessionIndex struct {
	mu   sync.Mutex
	byID map[uint64]sessionIndexEntry
}

// NewSessionIndex returns an empty, ready-to-use index.
func NewSessionIndex() *SessionIndex {
	return &SessionIndex{byID: make(map[uint64]sessionIndexEntry)}
}

// register records an authenticated session as owned by host. A re-
// authentication on the same SessionId simply overwrites its own entry.
func (idx *SessionIndex) register(s *Session, host *sessionHost) {
	if idx == nil || s == nil || s.ID == 0 {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if idx.byID == nil {
		idx.byID = make(map[uint64]sessionIndexEntry)
	}
	idx.byID[s.ID] = sessionIndexEntry{sess: s, host: host}
}

// unregister drops one SessionId. LOGOFF and the connection-teardown sweep both
// call it; it is idempotent, and it releases nothing — the caller owns that.
func (idx *SessionIndex) unregister(id uint64) {
	if idx == nil {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	delete(idx.byID, id)
}

// unregisterHost drops every session owned by one connection. Called from that
// connection's teardown, before it disposes of its own handles.
//
// It is a linear scan rather than a second host-keyed map on purpose: two maps
// can drift out of sync and one of them would then keep a dead connection
// reachable forever, whereas a scan cannot be wrong. The index holds a handful
// of entries on a real server, and this runs once per connection.
func (idx *SessionIndex) unregisterHost(host *sessionHost) {
	if idx == nil || host == nil {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for id, e := range idx.byID {
		if e.host == host {
			delete(idx.byID, id)
		}
	}
}

// get returns the session registered under id, or nil.
func (idx *SessionIndex) get(id uint64) *Session {
	if idx == nil {
		return nil
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return idx.byID[id].sess
}

// len reports how many sessions the index holds. A count that does not return
// to its baseline once every connection has gone is the leak this type must
// never have, so the tests assert on it directly.
func (idx *SessionIndex) len() int {
	if idx == nil {
		return 0
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return len(idx.byID)
}

// supersede implements MS-SMB2 §3.3.5.5.3's PreviousSessionId: the session
// named by prevID is closed because the client that owned it has just
// re-authenticated as `by`. It reports whether a session was actually closed.
//
// Everything that can refuse is decided under the index lock, and the entry is
// deleted before the lock is dropped, so two connections racing to supersede
// the same id cannot both reach the teardown: one finds the entry gone. The
// teardown itself runs with NO lock from this file held — see the lock-order
// note at the top — so it cannot participate in any cycle.
//
// Refusals are silent no-ops, never errors, because SESSION_SETUP must still
// succeed: a stale or unknown PreviousSessionId is the normal case after a
// server restart, and failing the setup would make a reconnecting client
// unmountable.
func (idx *SessionIndex) supersede(prevID uint64, by *Session, byGuid [16]byte, log *slog.Logger) bool {
	// Zero means "no previous session"; naming the session being set up is a
	// no-op the client sends when it re-authenticates in place.
	if idx == nil || by == nil || prevID == 0 || prevID == by.ID {
		return false
	}

	idx.mu.Lock()
	e, ok := idx.byID[prevID]
	if !ok {
		idx.mu.Unlock()
		return false
	}
	if !maySupersede(e, by, byGuid) {
		idx.mu.Unlock()
		if log != nil {
			log.Warn("ignoring PreviousSessionId naming a session owned by someone else",
				"previous_session_id", prevID, "session_id", by.ID, "smb_user", by.User.Name)
		}
		return false
	}
	delete(idx.byID, prevID)
	idx.mu.Unlock()

	e.host.closeSession(e.sess)
	if log != nil {
		log.Info("closed previous session on reconnect",
			"previous_session_id", prevID, "session_id", by.ID, "smb_user", by.User.Name)
	}
	return true
}

// maySupersede is the identity check: only the same authenticated user may
// close their own previous session.
//
// This is the whole security of the feature. PreviousSessionId is a bare
// 64-bit number chosen by the client, so without this check any client could
// name any other client's SessionId and have the server close its files,
// release its byte-range locks and drop its share-mode reservations. The same
// requirement is why a durable-handle reclaim compares e.userName (see
// DurableTable.reclaimChecked) and why that check refuses without consuming the
// entry: a rejected attempt must leave the victim untouched.
//
// The comparison is on the authenticated SMB user name, which is the session's
// security context — the same thing the durable path checks, and what the spec
// means by matching security contexts. The ClientGuid is deliberately NOT
// required for a named user: macOS regenerates it in some reconnect paths, and
// a reconnect that fails to supersede is the bug this whole change exists to
// fix.
//
// A guest session is the exception and DOES need the ClientGuid. "guest" is not
// an identity — every anonymous client authenticates as the same user — so the
// name comparison alone would let any machine on the network close any other
// machine's guest session. The ClientGuid the client put in its NEGOTIATE is
// the only thing distinguishing two guests, so for guests it is required.
func maySupersede(e sessionIndexEntry, by *Session, byGuid [16]byte) bool {
	prev := e.sess
	if prev == nil || by == nil {
		return false
	}
	// A session still mid-handshake has no security context to match.
	if !prev.Authenticated || !by.Authenticated {
		return false
	}
	if prev.IsGuest != by.IsGuest {
		return false
	}
	if !strings.EqualFold(prev.User.Name, by.User.Name) {
		return false
	}
	if by.IsGuest && e.host.clientGuid() != byGuid {
		return false
	}
	return true
}
