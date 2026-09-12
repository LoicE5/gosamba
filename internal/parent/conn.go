// Package parent contains the privileged SMB-server bootstrap.
package parent

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
)

const (
	// idleTimeout bounds how long a connection may go without delivering a
	// complete frame. It is reset before every read, so it only fires on a
	// genuinely idle or stalled peer (slow-loris), never on a busy one.
	idleTimeout = 5 * time.Minute
	// writeTimeout bounds a single response write, so a peer that stops
	// reading cannot pin the connection through TCP backpressure. One frame is
	// at most MaxIOSize, which completes far inside this window on any usable
	// link.
	writeTimeout = 2 * time.Minute
)

// bufRW is a tiny io.ReadWriter that pairs a buffered reader with the raw
// writer (so writes don't pass through the buffer and stall waiting for
// bufio's internal flushing). It also applies a per-write deadline when the
// underlying writer is a net.Conn.
type bufRW struct {
	r io.Reader
	w io.Writer
	c net.Conn
}

func (b *bufRW) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufRW) Write(p []byte) (int, error) {
	if b.c != nil {
		_ = b.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	}
	return b.w.Write(p)
}

// ConnOptions controls per-connection protocol behavior.
type ConnOptions struct {
	RequireEncryption bool
	RequireSigning    bool
	MaxIOSize         uint32
	ServerStartTime   uint64
	Users             []config.UserConfig
	Shares            []config.ShareConfig

	// Durable is the server-scoped durable-handle table, created once and
	// shared across every ServeConn so durable opens survive a dropped TCP
	// connection. If nil, durable handles are not granted.
	Durable *DurableTable
	// DurableTimeout caps how long a reclaimed handle stays alive.
	DurableTimeout time.Duration

	// OnAuthenticated, if non-nil, is invoked exactly once per session-setup
	// that resolves a user (the first time the connection authenticates). The
	// worker uses this hook to drop privileges to the authenticated user's
	// uid/gid. Returning a non-nil error tears down the connection. Default
	// (nil) is a no-op — the standard in-process serving path is unchanged.
	OnAuthenticated func(sess *Session) error
}

// releaseConnOpens disposes of every handle a dropped connection still owns.
//
// It closes each file descriptor that is NOT held by a live durable-table entry
// and gives up that handle's share-mode reservation. Durable opens are left
// alone: the table owns their fd so the client can reconnect and reclaim them,
// and a handle awaiting reclaim is still an open for the purposes of the
// sharing-access check (MS-SMB2 §3.3.5.9), so it keeps its deny mode until the
// durable entry expires. Detach starts that countdown — until now the entry was
// attached to this (live) connection and could not expire, so the sweeper could
// never close an fd still in use.
//
// This is the connection-teardown arm of handle disposal; the others are
// handleClose, Dispatcher.releaseOpens (TREE_DISCONNECT / LOGOFF / superseded
// session) and releaseOpen (durable expiry). Every one of them must drop the
// share-mode reservation: an entry nobody can release leaves the file
// permanently unopenable by every client, which is worse than the missing
// check it replaced.
func releaseConnOpens(sessions *SessionTable, durable *DurableTable) {
	if sessions == nil {
		return
	}
	sessions.RangeSessions(func(s *Session) {
		s.RangeOpens(func(o *Open) {
			if o.File == nil {
				// No descriptor means no share-mode reservation either: only
				// real file opens are ever registered (directories, named
				// streams and IPC$ pipes are exempt), so there is nothing to
				// release here.
				return
			}
			if o.IsDurable && durable != nil &&
				durable.Has(o.DurableClientGuid, o.DurableCreateGuid) {
				durable.Detach(o.DurableClientGuid, o.DurableCreateGuid)
				return
			}
			// This handle is gone for good.
			sharedShareModes.release(o)
			// Release any byte-range locks this open held before the fd
			// closes: releaseAll's keyFor does an Fstat on the fd, which
			// fails (and silently no-ops) once the file is closed.
			sharedLockManager.releaseAll(o)
			o.File.Close()
		})
	})
}

// ServeConn drives one TCP connection through SMB2 NEGOTIATE → SESSION_SETUP.
// Anything beyond SESSION_SETUP returns STATUS_INVALID_PARAMETER (Plan 4).
func ServeConn(ctx context.Context, c net.Conn, log *slog.Logger, maxFrame uint32, opts ConnOptions) {
	defer c.Close()
	log = log.With("remote", c.RemoteAddr().String())
	log.Info("connection opened")

	// Force the socket shut when the server context is cancelled, so a read
	// blocked on an idle peer unblocks and this connection tears down.
	//
	// The watcher must also exit when THIS connection ends. Selecting on
	// ctx.Done() alone parks the goroutine until server shutdown, so a server
	// that has handled many short-lived connections accumulates one parked
	// goroutine (and its captured net.Conn) per connection for the life of the
	// process — an unauthenticated peer could grow that without bound just by
	// connecting and disconnecting.
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-connDone:
		}
	}()

	// Wrap the connection in a bufio.Reader so we coalesce the small
	// NBSS-header read with whatever else is on the wire — one syscall
	// instead of two per frame.
	br := bufio.NewReaderSize(c, 64*1024)
	rw := &bufRW{r: br, w: c, c: c}

	conn, err := Negotiate(rw, NegotiatorOptions{
		RequireEncryption: opts.RequireEncryption,
		RequireSigning:    opts.RequireSigning,
		MaxIOSize:         opts.MaxIOSize,
		ServerStartTime:   opts.ServerStartTime,
	}, log)
	if err != nil {
		log.Warn("negotiate failed", "err", err)
		return
	}
	conn.Durable = opts.Durable
	conn.DurableTimeout = opts.DurableTimeout

	sessions := NewSessionTable()
	// dispatcher is assigned just below; the teardown closure needs to see it,
	// so it is declared before the defer that references it.
	var dispatcher *Dispatcher
	// On connection drop, close every file descriptor that is NOT held by a
	// live durable-table entry. Durable opens must stay alive so the client can
	// reconnect and reclaim them; ordinary (non-durable) opens must be closed
	// to release kernel fds.
	defer func() {
		// Wake every outstanding CHANGE_NOTIFY goroutine so it exits and drops
		// its watch descriptors instead of blocking forever on a dead client.
		if dispatcher != nil {
			dispatcher.CancelAllNotifies()
		}
		// Drop every server-side-copy resume key this connection issued. They
		// are capabilities naming open handles, so nothing may hold one (or,
		// through it, an *Open and its fd) once the connection is gone — not
		// even the durable opens deliberately left alive just below.
		conn.resumeKeys.clear()
		releaseConnOpens(sessions, opts.Durable)
	}()
	ssHandler := &SessionSetupHandler{
		Conn:              conn,
		Sessions:          sessions,
		Users:             opts.Users,
		Shares:            opts.Shares,
		Log:               log,
		RequireEncryption: opts.RequireEncryption,
	}
	dispatcher = &Dispatcher{
		Conn:              conn,
		Sessions:          sessions,
		Shares:            opts.Shares,
		Log:               log,
		locks:             sharedLockManager,
		RequireEncryption: opts.RequireEncryption,
		RequireSigning:    opts.RequireSigning,
	}
	// A reconnecting client names the session it is replacing in
	// PreviousSessionId; tearing that session's handles down is the same work
	// LOGOFF does, so it runs through the dispatcher (which also cancels its
	// CHANGE_NOTIFY watches and releases its byte-range locks).
	ssHandler.ClosePreviousSession = func(prev *Session) {
		dispatcher.releaseOpens(prev.TakeAllOpens())
	}

	for {
		// Bound how long a connection may sit without sending a complete frame.
		// Without a deadline a client that opens a socket and stalls (or dribbles
		// a partial NBSS header) pins a goroutine and its buffers indefinitely.
		// SMB clients are chatty — real ones send at least an ECHO keepalive
		// well inside this window — and the deadline is reset per frame.
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		frame, err := transport.ReadFrame(br, maxFrame)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Info("connection closed by peer")
				return
			}
			log.Warn("read error", "err", err)
			return
		}
		// SMB3 transform header: decrypt before any further handling.
		var encryptResp bool
		if smb3.IsTransform(frame) {
			if conn.Selection.Cipher == 0 {
				log.Warn("transform header received but no cipher negotiated")
				return
			}
			if len(frame) < smb3.TransformHeaderSize {
				log.Warn("transform frame too short", "len", len(frame))
				return
			}
			sessID := binary.LittleEndian.Uint64(frame[44:52])
			sess := sessions.Get(sessID)
			if sess == nil || len(sess.C2SCipherKey) == 0 {
				log.Warn("transform: unknown session or no key", "session_id", sessID)
				return
			}
			plain, _, err := smb3.DecryptTransform(uint16(conn.Selection.Cipher), sess.C2SCipherKey, frame)
			if err != nil {
				log.Warn("transform decrypt failed", "err", err)
				return
			}
			frame = plain
			encryptResp = true
			sess.SetGotEncrypted()
		}

		// Walk the (possibly compound) chain, dispatching each message over
		// its own slice. Compound chains: the first message's NextCommand
		// gives the offset of the next message; subsequent messages have
		// FlagRelatedOps set. Reset per-chain state (for "previous handle"
		// FileID substitution).
		dispatcher.ResetChainState()
		dispatcher.SetEncryptForChain(encryptResp)
		off := 0
		for off < len(frame) {
			if len(frame)-off < smb2.HeaderSize {
				log.Warn("undersized frame after negotiate", "off", off, "len", len(frame))
				return
			}
			hdr, err := smb2.DecodeHeader(frame[off : off+smb2.HeaderSize])
			if err != nil {
				log.Warn("bad header", "err", err, "off", off)
				return
			}
			end := len(frame)
			if hdr.NextCommand != 0 {
				// NextCommand is the byte offset from this message's header to
				// the next one in the chain. It must clear this message's own
				// 64-byte header and must not run past the frame; a value in
				// (0, HeaderSize) would make body = msgBytes[HeaderSize:] slice
				// out of range and panic the whole (unauthenticated) connection.
				if hdr.NextCommand < smb2.HeaderSize {
					log.Warn("NextCommand shorter than header", "next_command", hdr.NextCommand)
					return
				}
				end = off + int(hdr.NextCommand)
				if end > len(frame) {
					log.Warn("NextCommand overruns frame", "next_command", hdr.NextCommand, "len", len(frame))
					return
				}
			}
			msgBytes := frame[off:end]
			body := msgBytes[smb2.HeaderSize:]

			switch hdr.Command {
			case smb2.CommandSessionSetup:
				sess, err := ssHandler.HandleSessionSetup(rw, hdr, body, msgBytes)
				if err != nil {
					log.Warn("session-setup error", "err", err)
					return
				}
				// Fire the post-auth hook once per resolved session (used by the
				// privilege-drop worker). A nil hook is the default no-op path.
				if sess != nil && opts.OnAuthenticated != nil {
					if err := opts.OnAuthenticated(sess); err != nil {
						log.Error("post-auth hook failed; closing connection", "err", err)
						return
					}
				}
			default:
				if !dispatcher.Dispatch(rw, hdr, body, msgBytes) {
					return
				}
			}

			if hdr.NextCommand == 0 {
				break
			}
			off = end
		}
	}
}
