package parent

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/unix"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/inotify"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
	"github.com/ahmetozer/gosamba/internal/vfs"
)

// Dispatcher routes post-auth SMB2 commands to per-command handlers.
type Dispatcher struct {
	Conn     *Connection
	Sessions *SessionTable
	Shares   []config.ShareConfig
	Log      *slog.Logger

	// locks is the per-OS byte-range lock manager backing handleLock/handleClose.
	locks *lockManager

	// RequireEncryption / RequireSigning mirror the server security policy.
	// When set, an authenticated (non-guest) session's requests must arrive
	// encrypted / signed respectively; otherwise they are rejected. This is
	// what makes the "required" modes actually enforced on inbound traffic
	// rather than merely advertised in NEGOTIATE.
	RequireEncryption bool
	RequireSigning    bool

	// Chain state — set by handleCreate, consumed by the ServeConn loop
	// to satisfy "previous handle" FileIDs in compound related ops.
	LastCreatedFileID [16]byte
	HasLastCreated    bool

	// lastChainStatus is the status the most recent op in this compound
	// chain produced. Subsequent related ops referencing the previous-
	// handle sentinel FileID inherit this when it's non-success
	// (MS-SMB2 §3.3.5.2.7).
	lastChainStatus smb2.Status

	// encryptChain is set by ServeConn when the inbound frame arrived
	// inside an SMB3 transform header. All responses for this chain go
	// back encrypted. It is read by the CHANGE_NOTIFY async goroutine (via
	// writeFrame) while ServeConn sets it for the next chain, so it is atomic.
	encryptChain atomic.Bool

	// writeMu serializes writes to the connection so async goroutines
	// (CHANGE_NOTIFY completion) don't corrupt frames the main dispatcher
	// is sending.
	writeMu sync.Mutex

	// notifyMu guards notifies, the table of outstanding CHANGE_NOTIFY
	// requests. Each entry lets CLOSE / TREE_DISCONNECT / LOGOFF complete a
	// pending notify (MS-SMB2 §3.3.5.19 requires STATUS_NOTIFY_CLEANUP rather
	// than leaving the client waiting forever) and lets SMB2_CANCEL finish the
	// original request instead of being answered with a second response.
	notifyMu sync.Mutex
	notifies map[uint64]*notifyReg
	// nextAsyncID allocates AsyncIds for STATUS_PENDING responses.
	nextAsyncID atomic.Uint64
}

// notifyReg is one outstanding CHANGE_NOTIFY request. cancel is closed exactly
// once (guarded by the dispatcher's notifyMu) to wake the watching goroutine;
// status carries the completion the canceller wants the client to see.
type notifyReg struct {
	open      *Open
	cancel    chan struct{}
	status    smb2.Status
	cancelled bool
}

// registerNotify records an outstanding notify keyed by its MessageId.
func (d *Dispatcher) registerNotify(msgID uint64, reg *notifyReg) {
	d.notifyMu.Lock()
	defer d.notifyMu.Unlock()
	if d.notifies == nil {
		d.notifies = make(map[uint64]*notifyReg)
	}
	d.notifies[msgID] = reg
}

func (d *Dispatcher) unregisterNotify(msgID uint64) {
	d.notifyMu.Lock()
	defer d.notifyMu.Unlock()
	delete(d.notifies, msgID)
}

// cancelNotify completes one outstanding notify with the given status.
func (d *Dispatcher) cancelNotify(msgID uint64, status smb2.Status) bool {
	d.notifyMu.Lock()
	defer d.notifyMu.Unlock()
	reg, ok := d.notifies[msgID]
	if !ok || reg.cancelled {
		return false
	}
	reg.cancelled = true
	reg.status = status
	close(reg.cancel)
	return true
}

// cancelNotifiesForOpens completes every notify registered against any of the
// given handles. Called when those handles go away so the client is not left
// waiting on a watch whose directory handle no longer exists.
func (d *Dispatcher) cancelNotifiesForOpens(opens []*Open) {
	if len(opens) == 0 {
		return
	}
	set := make(map[*Open]struct{}, len(opens))
	for _, o := range opens {
		set[o] = struct{}{}
	}
	d.notifyMu.Lock()
	defer d.notifyMu.Unlock()
	for _, reg := range d.notifies {
		if reg.cancelled {
			continue
		}
		if _, ok := set[reg.open]; !ok {
			continue
		}
		reg.cancelled = true
		reg.status = smb2.StatusNotifyCleanup
		close(reg.cancel)
	}
}

// CancelAllNotifies completes every outstanding notify on this connection. It
// is called during connection teardown: the watcher goroutines block until an
// event or a cancel, so without this each abandoned CHANGE_NOTIFY would leak a
// goroutine and its watch descriptors for the life of the process.
func (d *Dispatcher) CancelAllNotifies() {
	d.notifyMu.Lock()
	defer d.notifyMu.Unlock()
	for _, reg := range d.notifies {
		if reg.cancelled {
			continue
		}
		reg.cancelled = true
		reg.status = smb2.StatusNotifyCleanup
		close(reg.cancel)
	}
}

// notifyFilterAllows reports whether an event action is one the client asked
// for in its CompletionFilter. A filter of 0 is treated as "everything", which
// is what clients that do not care send.
func notifyFilterAllows(filter, action uint32) bool {
	if filter == 0 {
		return true
	}
	switch action {
	case smb2.FileActionAdded, smb2.FileActionRemoved:
		return filter&(smb2.NotifyFileName|smb2.NotifyDirName) != 0
	case smb2.FileActionRenamedOldName, smb2.FileActionRenamedNewName:
		return filter&(smb2.NotifyFileName|smb2.NotifyDirName) != 0
	case smb2.FileActionModified:
		return filter&(smb2.NotifyLastWrite|smb2.NotifySize|smb2.NotifyAttributes) != 0
	}
	return false
}

// Per-session resource caps. A client that opens handles or trees without ever
// closing them would otherwise exhaust the process's file descriptors; these
// bounds are far above any legitimate workload (Finder and rclone peak in the
// low hundreds of concurrent opens) but keep a runaway or hostile client from
// taking the server down.
const (
	maxOpensPerSession = 4096
	maxTreesPerSession = 256
)

// maxStreamSize bounds an in-memory alternate-data-stream / resource-fork
// buffer. It caps client-driven allocation and, more importantly, keeps a
// wire-supplied stream offset from going negative when narrowed to int. The
// on-disk xattr store imposes its own (smaller) limit at CLOSE.
const maxStreamSize = 64 << 20 // 64 MiB

// encryptionExempt reports whether a command may arrive in cleartext even when
// encryption is required. These carry no confidential share data: TREE_CONNECT
// precedes the client learning the share's encryption policy, and the rest are
// keepalive / teardown / async-control messages that real clients (go-smb2)
// send unencrypted. They are still subject to the signing requirement.
func encryptionExempt(cmd smb2.Command) bool {
	switch cmd {
	case smb2.CommandTreeConnect, smb2.CommandTreeDisconnect, smb2.CommandLogoff,
		smb2.CommandEcho, smb2.CommandCancel, smb2.CommandOplockBreak:
		return true
	}
	return false
}

// ResetChainState clears per-chain (per-TCP-frame) state.
func (d *Dispatcher) ResetChainState() {
	d.LastCreatedFileID = [16]byte{}
	d.HasLastCreated = false
	d.lastChainStatus = smb2.StatusSuccess
}

// hasPreviousHandleSentinel reports whether body's FileID slot holds the
// all-FF "use the previous handle" sentinel.
func hasPreviousHandleSentinel(cmd smb2.Command, body []byte) bool {
	off := fileIDOffsetInBody(cmd)
	if off < 0 || len(body) < off+16 {
		return false
	}
	return [16]byte(body[off:off+16]) == previousHandleFileID
}

// SetEncryptForChain marks whether the current inbound chain was encrypted.
func (d *Dispatcher) SetEncryptForChain(b bool) { d.encryptChain.Store(b) }

// writeFrame serializes outbound frames and applies SMB3 transform-header
// encryption when the session demands it (or when the client encrypted us).
func (d *Dispatcher) writeFrame(rw io.Writer, sess *Session, frame []byte) error {
	if sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted() || d.encryptChain.Load()) {
		enc, err := smb3.EncryptTransform(uint16(d.Conn.Selection.Cipher), sess.S2CCipherKey, sess.ID, frame)
		if err != nil {
			return err
		}
		frame = enc
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return transport.WriteFrame(rw, frame)
}

// previousHandleFileID is the SMB2 sentinel meaning "use the FileID returned
// by the immediately preceding CREATE in this compound chain".
var previousHandleFileID = [16]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// fileIDOffsetInBody returns where the 16-byte FileID lives in the body of
// the given command, or -1 if the command has no FileID field.
func fileIDOffsetInBody(cmd smb2.Command) int {
	switch cmd {
	case smb2.CommandClose, smb2.CommandFlush, smb2.CommandIoctl, smb2.CommandLock:
		return 8
	case smb2.CommandRead, smb2.CommandWrite, smb2.CommandSetInfo:
		return 16
	case smb2.CommandQueryInfo:
		return 24
	case smb2.CommandQueryDirectory, smb2.CommandChangeNotify:
		return 8
	}
	return -1
}

// SubstitutePreviousHandleFileID replaces the all-FF sentinel FileID in body
// with the FileID returned by the most recent CREATE in this compound chain.
func (d *Dispatcher) SubstitutePreviousHandleFileID(cmd smb2.Command, body []byte) {
	if !d.HasLastCreated {
		return
	}
	off := fileIDOffsetInBody(cmd)
	if off < 0 || len(body) < off+16 {
		return
	}
	if [16]byte(body[off:off+16]) == previousHandleFileID {
		copy(body[off:off+16], d.LastCreatedFileID[:])
	}
}

// Dispatch handles one frame. Returns false to indicate the caller should
// drop the connection.
func (d *Dispatcher) Dispatch(rw io.ReadWriter, hdr smb2.Header, body, frame []byte) bool {
	sess := d.Sessions.Get(hdr.SessionID)
	if sess == nil {
		d.respondError(rw, hdr, smb2.StatusUserSessionDeleted, nil)
		return false
	}

	// Refuse every command on a session that has not completed SESSION_SETUP.
	// handleType1 registers the session (so the multi-leg NTLM handshake can
	// find it) before any credentials are verified; without this gate an
	// unauthenticated client could TREE_CONNECT to IPC$ and enumerate shares,
	// or reach the DCERPC parser, with only a NEGOTIATE + type-1 sent.
	if !sess.Authenticated {
		d.Log.Warn("command on unauthenticated session — denying",
			"cmd", hdr.Command, "session_id", hdr.SessionID)
		d.respondError(rw, hdr, smb2.StatusAccessDenied, nil)
		return false
	}

	encrypted := d.encryptChain.Load()

	// Enforce the server's inbound security policy. Guests carry no session
	// keys (they opted out of per-session crypto), so the requirements apply
	// only to key-bearing (non-guest) sessions; a guest_ok share is an
	// explicit decision to accept unauthenticated traffic.
	if !sess.IsGuest && len(sess.SigningKey) > 0 {
		// Require encryption for every message that can carry share data. The
		// no-data control commands are exempt: TREE_CONNECT must precede the
		// client learning the share's encryption policy, and ECHO/LOGOFF/
		// TREE_DISCONNECT/CANCEL/OPLOCK_BREAK carry no confidential payload —
		// go-smb2 (rclone) legitimately sends these in the clear. They remain
		// signing-enforced below. A policy miss here is answered ACCESS_DENIED
		// but does not drop the connection: a stray cleartext keepalive must
		// not tear down an otherwise-healthy mount.
		if d.RequireEncryption && !encrypted && !encryptionExempt(hdr.Command) {
			d.Log.Warn("unencrypted request but encryption required — denying",
				"cmd", hdr.Command, "session_id", hdr.SessionID)
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// Signing is subsumed by transform encryption (AEAD authenticates the
		// whole message). For cleartext frames, a signature is mandatory when
		// signing is required, and verified whenever one is present.
		if !encrypted {
			if d.RequireSigning || hdr.Flags&smb2.FlagSigned != 0 {
				if hdr.Flags&smb2.FlagSigned == 0 ||
					!smb3.VerifyMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, frame) {
					d.Log.Warn("inbound signature missing or invalid — dropping",
						"cmd", hdr.Command,
						"msg_id", hdr.MessageID,
						"session_id", hdr.SessionID,
						"required", d.RequireSigning,
					)
					d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
					return false
				}
			}
		}
	}

	// Now that signature verification is done, in a related compound
	// chain replace any "previous handle" sentinel FileID with the one
	// returned by the most recent CREATE. If the previous op failed and
	// this op is referencing that handle, inherit the prior status (per
	// MS-SMB2 §3.3.5.2.7) — otherwise we'd send INVALID_PARAMETER and
	// confuse clients (Finder reads it as a permission fault).
	if hdr.Flags&smb2.FlagRelatedOps != 0 {
		if d.lastChainStatus != smb2.StatusSuccess && hasPreviousHandleSentinel(hdr.Command, body) {
			d.respondError(rw, hdr, d.lastChainStatus, sess)
			return true
		}
		d.SubstitutePreviousHandleFileID(hdr.Command, body)
	}

	switch hdr.Command {
	case smb2.CommandTreeConnect:
		return d.handleTreeConnect(rw, hdr, body, sess)
	case smb2.CommandTreeDisconnect:
		return d.handleTreeDisconnect(rw, hdr, body, sess)
	case smb2.CommandCreate:
		return d.handleCreate(rw, hdr, body, sess)
	case smb2.CommandRead:
		return d.handleRead(rw, hdr, body, sess)
	case smb2.CommandWrite:
		return d.handleWrite(rw, hdr, body, sess)
	case smb2.CommandFlush:
		return d.handleFlush(rw, hdr, body, sess)
	case smb2.CommandSetInfo:
		return d.handleSetInfo(rw, hdr, body, sess)
	case smb2.CommandClose:
		return d.handleClose(rw, hdr, body, sess)
	case smb2.CommandQueryDirectory:
		return d.handleQueryDirectory(rw, hdr, body, sess)
	case smb2.CommandQueryInfo:
		return d.handleQueryInfo(rw, hdr, body, sess)
	case smb2.CommandIoctl:
		return d.handleIoctl(rw, hdr, body, sess)
	case smb2.CommandLogoff:
		return d.handleLogoff(rw, hdr, sess)
	case smb2.CommandEcho:
		d.respondSuccess(rw, hdr, sess, []byte{0x04, 0x00, 0x00, 0x00})
		return true
	case smb2.CommandChangeNotify:
		return d.handleChangeNotify(rw, hdr, body, sess)
	case smb2.CommandLock:
		return d.handleLock(rw, hdr, body, sess)
	case smb2.CommandCancel:
		// SMB2_CANCEL never gets a response of its own (MS-SMB2 §3.3.5.16):
		// the cancelled request completes with STATUS_CANCELLED instead.
		// Replying here produced a second response for one MessageId and
		// corrupted the client's outstanding-request table.
		if !d.cancelNotify(hdr.MessageID, smb2.StatusCancelled) {
			d.Log.Debug("cancel for unknown request", "msg_id", hdr.MessageID)
		}
		return true
	case smb2.CommandOplockBreak:
		// MS-SMB2 §3.3.5.22 lists STATUS_INVALID_OPLOCK_PROTOCOL,
		// STATUS_INVALID_PARAMETER and STATUS_FILE_CLOSED as the failures for a
		// break the server cannot match; STATUS_NOT_SUPPORTED is not among
		// them. We grant no oplocks or leases, so no acknowledgement can ever
		// match one.
		d.respondError(rw, hdr, smb2.StatusInvalidOplockProtocol, sess)
		return true
	default:
		d.Log.Warn("unhandled command", "cmd", hdr.Command)
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
}

// respondSuccess writes a signed STATUS_SUCCESS response with the given body.
func (d *Dispatcher) respondSuccess(rw io.ReadWriter, hdr smb2.Header, sess *Session, body []byte) {
	// Don't sign if we're going to wrap in transform header — encryption
	// already authenticates the frame, and signing under encryption is
	// disallowed for the wrapped message (MS-SMB2 §3.3.4.1.4).
	willEncrypt := sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted() || d.encryptChain.Load())
	sign := !willEncrypt && sess != nil && len(sess.SigningKey) > 0
	out := d.buildResponse(hdr, sess, smb2.StatusSuccess, body, sign)
	d.lastChainStatus = smb2.StatusSuccess
	_ = d.writeFrame(rw, sess, out)
}

// respondError writes a signed error response with a small error body.
func (d *Dispatcher) respondError(rw io.ReadWriter, hdr smb2.Header, status smb2.Status, sess *Session) {
	errBody := []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	willEncrypt := sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted() || d.encryptChain.Load())
	signed := !willEncrypt && sess != nil && len(sess.SigningKey) > 0
	out := d.buildResponse(hdr, sess, status, errBody, signed)
	d.lastChainStatus = status
	_ = d.writeFrame(rw, sess, out)
}

func (d *Dispatcher) buildResponse(reqHdr smb2.Header, sess *Session, status smb2.Status, body []byte, sign bool) []byte {
	respHdr := smb2.Header{
		CreditCharge:   reqHdr.CreditCharge,
		Status:         uint32(status),
		Command:        reqHdr.Command,
		CreditResponse: grantCredits(reqHdr.CreditCharge, reqHdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      reqHdr.MessageID,
		TreeID:         reqHdr.TreeID,
		SessionID:      reqHdr.SessionID,
	}
	out := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(out[:smb2.HeaderSize], respHdr)
	copy(out[smb2.HeaderSize:], body)
	if sign && sess != nil {
		smb3.SignMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, out)
	}
	return out
}

// --- TREE_CONNECT ---

func (d *Dispatcher) handleTreeConnect(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeTreeConnectRequest(body)
	if err != nil {
		d.Log.Warn("tree-connect decode failed", "err", err)
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if sess.TreeCount() >= maxTreesPerSession {
		d.Log.Warn("tree-connect: tree limit reached", "limit", maxTreesPerSession, "session_id", sess.ID)
		d.respondError(rw, hdr, smb2.StatusInsufficientResources, sess)
		return true
	}
	// Path is "\\server\share". Extract the trailing share name.
	parts := strings.Split(strings.ReplaceAll(req.Path, "/", "\\"), "\\")
	shareName := parts[len(parts)-1]
	// Don't log routine IPC$ probing — clients hit it constantly.
	if !strings.EqualFold(shareName, "IPC$") {
		d.Log.Debug("tree-connect", "path", req.Path, "share_name", shareName)
	}

	if shareName == "" {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	// IPC$ — accept the connect (Samba does the same; refusing causes some
	// clients to retry forever). Unsupported pipes are rejected at the
	// CREATE step with OBJECT_NAME_NOT_FOUND, which matches Samba's
	// smb2_create.c behavior for unknown pipe names.
	if strings.EqualFold(shareName, "IPC$") {
		ipc := config.ShareConfig{Name: "IPC$"}
		tree := sess.AddTree(ipc)
		resp := smb2.EncodeTreeConnectResponse(smb2.TreeConnectResponse{
			ShareType:     smb2.ShareTypePipe,
			ShareFlags:    0,
			Capabilities:  0,
			MaximalAccess: 0x001F00A9,
		})
		d.respondSuccessWithTreeID(rw, hdr, sess, resp, tree.ID)
		return true
	}

	var share *config.ShareConfig
	for i := range d.Shares {
		if strings.EqualFold(d.Shares[i].Name, shareName) {
			share = &d.Shares[i]
			break
		}
	}
	if share == nil {
		d.Log.Warn("tree-connect: unknown share", "share_name", shareName, "configured_shares", shareNames(d.Shares))
		d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
		return true
	}

	// Guests can only mount shares marked guest_ok.
	if sess.IsGuest && !share.GuestOK {
		d.Log.Warn("guest denied non-guest share", "share_name", shareName)
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}

	// Check user is allowed (named users only — guest passes via guest_ok).
	if !sess.IsGuest && !shareAllowed(sess.User, share.Name) {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}

	tree := sess.AddTree(*share)
	// SMB2 caching flags: MANUAL (0x0) for read-only, AUTO (0x10) for read-write.
	// Apple clients write-back-cache aggressively under AUTO, which surfaces as
	// phantom EACCES on RO shares — MANUAL avoids that.
	shareFlags := uint32(0x00000010) // AUTO_CACHING
	if share.ReadOnly {
		shareFlags = 0x00000000 // MANUAL_CACHING
	}
	if d.RequireEncryption {
		// SMB2_SHAREFLAG_ENCRYPT_DATA: tell the client that traffic on this
		// tree must be encrypted. Clients (go-smb2/rclone included) encrypt
		// per-tree based on this flag, not on the global NEGOTIATE cap alone;
		// without it they keep sending cleartext and our inbound encryption
		// check would reject every post-TREE_CONNECT request.
		shareFlags |= 0x00008000
	}
	maximalAccess := uint32(0x001F01FF) // generic all
	if share.ReadOnly {
		maximalAccess = 0x001200A9 // read + execute
	}
	respBody := smb2.EncodeTreeConnectResponse(smb2.TreeConnectResponse{
		ShareType:     smb2.ShareTypeDisk,
		ShareFlags:    shareFlags,
		Capabilities:  0,
		MaximalAccess: maximalAccess,
	})
	d.respondSuccessWithTreeID(rw, hdr, sess, respBody, tree.ID)
	return true
}

func shareNames(shares []config.ShareConfig) []string {
	names := make([]string, len(shares))
	for i, s := range shares {
		names[i] = s.Name
	}
	return names
}

func shareNamesAndPaths(shares []config.ShareConfig) []string {
	out := make([]string, len(shares))
	for i, s := range shares {
		out[i] = s.Name + "=" + s.Path
	}
	return out
}

// syntheticDirEntry stands in for "." and ".." in directory listings.
type syntheticDirEntry struct {
	name string
	info os.FileInfo
}

func (s syntheticDirEntry) Name() string      { return s.name }
func (s syntheticDirEntry) IsDir() bool       { return true }
func (s syntheticDirEntry) Type() os.FileMode { return os.ModeDir }

// Info never hands back a nil os.FileInfo. The "." / ".." entries are built
// from an os.Lstat that can fail (the directory can be renamed or removed
// between the ReadDir and the stat), and a nil interface here would be
// dereferenced by encodeDirRecord — panicking the whole server process, since
// nothing in the serve path recovers. Reporting an error instead makes the
// enumerator skip the entry.
func (s syntheticDirEntry) Info() (os.FileInfo, error) {
	if s.info == nil {
		return nil, os.ErrNotExist
	}
	return s.info, nil
}

func (d *Dispatcher) respondSuccessWithTreeID(rw io.ReadWriter, hdr smb2.Header, sess *Session, body []byte, treeID uint32) {
	respHdr := smb2.Header{
		CreditCharge:   hdr.CreditCharge,
		Status:         uint32(smb2.StatusSuccess),
		Command:        hdr.Command,
		CreditResponse: grantCredits(hdr.CreditCharge, hdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      hdr.MessageID,
		TreeID:         treeID,
		SessionID:      hdr.SessionID,
	}
	out := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(out[:smb2.HeaderSize], respHdr)
	copy(out[smb2.HeaderSize:], body)
	willEncrypt := len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted() || d.encryptChain.Load())
	if !willEncrypt && len(sess.SigningKey) > 0 {
		smb3.SignMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, out)
	}
	d.lastChainStatus = smb2.StatusSuccess
	_ = d.writeFrame(rw, sess, out)
}

func shareAllowed(u config.UserConfig, shareName string) bool {
	for _, a := range u.AllowShares {
		if a == "*" || strings.EqualFold(a, shareName) {
			return true
		}
	}
	return false
}

// visibleShares returns the shares sess is permitted to connect to, applying
// exactly the rules handleTreeConnect enforces. Share enumeration must not
// reveal shares the caller could not mount: without this filter NetShareEnumAll
// listed every configured share — including their names — to any authenticated
// user, regardless of their allow_shares list.
func visibleShares(all []config.ShareConfig, sess *Session) []config.ShareConfig {
	if sess == nil {
		return nil
	}
	out := make([]config.ShareConfig, 0, len(all))
	for _, s := range all {
		if sess.IsGuest {
			if s.GuestOK {
				out = append(out, s)
			}
			continue
		}
		if shareAllowed(sess.User, s.Name) {
			out = append(out, s)
		}
	}
	return out
}

// --- TREE_DISCONNECT ---

// releaseOpens closes a batch of handles: byte-range locks first, then the
// descriptor, and finally the durable-table entry so a disconnected tree or
// session cannot be reclaimed and does not pin an fd.
func (d *Dispatcher) releaseOpens(opens []*Open) {
	// Complete any CHANGE_NOTIFY still watching these handles first, so the
	// client gets STATUS_NOTIFY_CLEANUP rather than waiting on a dead handle.
	d.cancelNotifiesForOpens(opens)
	for _, o := range opens {
		if o == nil {
			continue
		}
		if o.IsDurable && d.Conn != nil && d.Conn.Durable != nil {
			d.Conn.Durable.Remove(o.DurableClientGuid, o.DurableCreateGuid)
		}
		if o.File != nil {
			if d.locks != nil {
				d.locks.releaseAll(o)
			}
			o.File.Close()
			o.File = nil
		}
	}
}

func (d *Dispatcher) handleTreeDisconnect(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	if _, err := smb2.DecodeTreeDisconnectRequest(body); err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// Close every handle opened on this tree — otherwise its fds and locks
	// survive until the whole connection drops.
	d.releaseOpens(sess.RemoveTreeAndOpens(hdr.TreeID))
	d.respondSuccess(rw, hdr, sess, smb2.EncodeTreeDisconnectResponse())
	return true
}

// handleLogoff tears the session down: every open is closed and the SessionId
// is invalidated. Previously LOGOFF only sent a success response, leaving the
// id usable and every descriptor and lock in place.
func (d *Dispatcher) handleLogoff(rw io.ReadWriter, hdr smb2.Header, sess *Session) bool {
	d.releaseOpens(sess.TakeAllOpens())
	d.respondSuccess(rw, hdr, sess, []byte{0x04, 0x00, 0x00, 0x00})
	if d.Sessions != nil {
		d.Sessions.Remove(sess.ID)
	}
	return true
}

// --- CREATE ---

func (d *Dispatcher) handleCreate(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeCreateRequest(body)
	if err != nil {
		d.Log.Warn("create decode failed", "err", err)
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	tree := sess.GetTree(hdr.TreeID)
	if tree == nil {
		d.Log.Warn("create: unknown tree", "tree_id", hdr.TreeID)
		d.respondError(rw, hdr, smb2.StatusNetworkNameDeleted, sess)
		return true
	}
	if sess.OpenCount() >= maxOpensPerSession {
		d.Log.Warn("create: open limit reached", "limit", maxOpensPerSession, "session_id", sess.ID)
		d.respondError(rw, hdr, smb2.StatusInsufficientResources, sess)
		return true
	}
	d.Log.Debug("create",
		"tree", tree.Share.Name,
		"name", req.Name,
		"disposition", req.CreateDisposition,
		"options", req.CreateOptions,
		"access", req.DesiredAccess,
	)

	// Parse durable-handle and lease create contexts up front. A reconnect
	// (DH2C/DHnC) short-circuits the normal CREATE path: we reclaim the saved
	// Open and re-open its backing file rather than re-running disposition.
	durReq, durRec, leaseReq := parseDurableContexts(req.CreateContexts)
	if durRec.present && tree.Share.Path != "" {
		if d.handleDurableReconnect(rw, hdr, sess, tree, durRec) {
			return true
		}
		// Reclaim failed/expired → OBJECT_NAME_NOT_FOUND so the client
		// re-opens fresh (MS-SMB2 §3.3.5.9.7/.12).
		d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
		return true
	}

	// IPC$ tree: open virtual pipe handles. We support \PIPE\srvsvc (share
	// enumeration); other pipes return OBJECT_NAME_NOT_FOUND so the client
	// stops retrying.
	if tree.Share.Path == "" {
		pipeName := strings.TrimPrefix(strings.TrimPrefix(req.Name, "\\"), "PIPE\\")
		pipeName = strings.TrimPrefix(pipeName, "pipe\\")
		switch strings.ToLower(pipeName) {
		case "srvsvc":
			open := &Open{
				Tree:     tree,
				IsPipe:   true,
				PipeName: "srvsvc",
			}
			if _, err := rand.Read(open.FileID[:]); err != nil {
				d.respondError(rw, hdr, smb2.StatusInternalError, sess)
				return true
			}
			sess.AddOpen(open)
			d.LastCreatedFileID = open.FileID
			d.HasLastCreated = true
			now := filetimeFromTime(time.Now())
			resp := smb2.EncodeCreateResponse(smb2.CreateResponse{
				CreateAction:   smb2.CreateActionOpened,
				CreationTime:   now,
				LastAccessTime: now,
				LastWriteTime:  now,
				ChangeTime:     now,
				FileAttributes: smb2.FileAttrNormal,
				FileID:         open.FileID,
			})
			d.respondSuccess(rw, hdr, sess, resp)
			return true
		default:
			d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
			return true
		}
	}

	baseName, streamName, streamOK := splitStreamName(req.Name)
	if !streamOK {
		// Non-$DATA stream type (e.g. $INDEX_ALLOCATION) — Samba returns
		// EINVAL here, which maps to STATUS_INVALID_PARAMETER.
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if streamName != "" {
		return d.handleCreateNamedStream(rw, hdr, sess, tree, req, baseName, streamName)
	}

	// Use normalization-insensitive resolution so an NFD-named file (created
	// on macOS) can be found by an NFC lookup (Windows/Linux), and vice-versa.
	// ResolveSecureNorm still enforces symlink-containment inside the share.
	osPath, err := vfs.ResolveSecureNorm(tree.Share.Path, baseName)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	wantedDir := req.CreateOptions&smb2.CreateOptDirectoryFile != 0
	wantedNonDir := req.CreateOptions&smb2.CreateOptNonDirFile != 0
	wantsWrite := req.DesiredAccess&(smb2.AccessFileWriteData|smb2.AccessFileAppendData|smb2.AccessGenericAll|smb2.AccessGenericWrite) != 0

	// Enforce read-only share restrictions before any mutation.
	if tree.Share.ReadOnly {
		// Any disposition other than plain Open (=1) would create, overwrite, or
		// supersede — deny all of them.
		if req.CreateDisposition != smb2.CreateDispositionOpen {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// Deny write/append/delete access bits, generic-write/all.
		const writeMask = smb2.AccessFileWriteData | smb2.AccessFileAppendData |
			smb2.AccessGenericWrite | smb2.AccessGenericAll |
			0x00000100 | // FILE_WRITE_ATTRIBUTES
			0x00010000 // DELETE
		if req.DesiredAccess&writeMask != 0 {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// DELETE_ON_CLOSE would silently remove the file on close.
		if req.CreateOptions&smb2.CreateOptDeleteOnClose != 0 {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// mkdir on a read-only share: DirectoryFile + any creating disposition.
		// (We already rejected non-Open dispositions above, so this is covered;
		// guard here for clarity if the logic above ever changes.)
		if wantedDir && req.CreateDisposition != smb2.CreateDispositionOpen {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
	}

	st, statErr := os.Lstat(osPath)
	exists := statErr == nil
	isDir := exists && st.IsDir()
	if !exists && !os.IsNotExist(statErr) {
		d.Log.Warn("create: lstat failed", "path", osPath, "err", statErr)
		d.respondError(rw, hdr, statusFromErr(statErr), sess)
		return true
	}

	// Apply disposition logic.
	createAction := uint32(smb2.CreateActionOpened)
	switch req.CreateDisposition {
	case smb2.CreateDispositionOpen:
		if !exists {
			d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
			return true
		}
	case smb2.CreateDispositionCreate:
		if exists {
			d.respondError(rw, hdr, smb2.StatusObjectNameCollision, sess)
			return true
		}
		if wantedDir {
			if err := os.Mkdir(osPath, 0775); err != nil {
				d.Log.Warn("create: mkdir failed", "path", osPath, "err", err)
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			isDir = true
		} else {
			f, err := os.OpenFile(osPath, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0664)
			if err != nil {
				d.Log.Warn("create: open EXCL failed", "path", osPath, "err", err)
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			f.Close()
		}
		st, _ = os.Lstat(osPath)
		exists = true
		createAction = smb2.CreateActionCreated
	case smb2.CreateDispositionOpenIf:
		if !exists {
			if wantedDir {
				if err := os.Mkdir(osPath, 0775); err != nil {
					d.respondError(rw, hdr, statusFromErr(err), sess)
					return true
				}
				isDir = true
			} else {
				f, err := os.OpenFile(osPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0664)
				if err != nil {
					d.respondError(rw, hdr, statusFromErr(err), sess)
					return true
				}
				f.Close()
			}
			st, _ = os.Lstat(osPath)
			exists = true
			createAction = smb2.CreateActionCreated
		}
	case smb2.CreateDispositionOverwrite:
		if !exists {
			d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
			return true
		}
		if !isDir {
			if err := os.Truncate(osPath, 0); err != nil {
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
		}
		createAction = smb2.CreateActionOverwritten
		st, _ = os.Lstat(osPath)
	case smb2.CreateDispositionOverwriteIf, smb2.CreateDispositionSupersede:
		if exists && !isDir {
			if err := os.Truncate(osPath, 0); err != nil {
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			createAction = smb2.CreateActionOverwritten
		} else if !exists {
			f, err := os.OpenFile(osPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0664)
			if err != nil {
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			f.Close()
			createAction = smb2.CreateActionCreated
		}
		st, _ = os.Lstat(osPath)
		exists = true
	default:
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	if wantedDir && !isDir {
		d.respondError(rw, hdr, smb2.StatusNotADirectory, sess)
		return true
	}
	if wantedNonDir && isDir {
		d.respondError(rw, hdr, smb2.StatusFileIsADirectory, sess)
		return true
	}

	// Granted-access mask, reported back both in the MxAc create context and
	// via FileAccessInformation / FileAllInformation.
	//
	// It is deliberately NOT narrowed to what the client asked for in CREATE —
	// Samba reports the maximum too, and macOS refuses to LIST a directory
	// whose mask lacks FILE_LIST_DIRECTORY (= FILE_READ_DATA) even when the
	// CREATE itself succeeded.
	//
	// It IS narrowed to what this object's POSIX permissions really grant. For
	// macOS the MxAc mask is the only input to smbfs_vnop_access(): the client
	// never asks for FileAccessInformation separately, so a share-wide constant
	// made access(W_OK) answer true on a mode 0444 file (the write then failing
	// with EACCES) and marked every file on the share executable — the AAPL
	// reply declares the server UNIX-based, so the client takes the execute bit
	// at face value instead of falling back to "readable implies executable".
	// That also contradicted the POSIX mode the AAPL directory overlay ships,
	// so ls -l and access() disagreed about the same file.
	//
	// The share's read-only flag remains the ceiling; permissions only subtract
	// from it, so a read-only share still reports no write access for a mode
	// 0666 file.
	granted := maximalAccess(osPath, tree.Share.ReadOnly)

	open := &Open{
		Path:          osPath,
		IsDir:         isDir,
		Tree:          tree,
		GrantedAccess: granted,
		DeleteOnClose: req.CreateOptions&smb2.CreateOptDeleteOnClose != 0,
	}
	if !isDir {
		// Always open RW when possible so that later SET_INFO (truncate / EOF)
		// or rename ops on this handle don't fail with EBADF. If RW fails
		// (e.g. read-only filesystem), fall back to read-only when the client
		// only asked for read-only access.
		// O_NOFOLLOW on the leaf closes the TOCTOU window where a symlink
		// swapped in after ResolveSecure would otherwise be followed silently.
		f, err := os.OpenFile(osPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
				return true
			}
			if !wantsWrite {
				f, err = os.OpenFile(osPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			}
			if err != nil {
				if errors.Is(err, syscall.ELOOP) {
					d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
					return true
				}
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
		}
		open.File = f
	}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		if open.File != nil {
			open.File.Close()
		}
		d.respondError(rw, hdr, smb2.StatusInternalError, sess)
		return true
	}
	sess.AddOpen(open)

	d.LastCreatedFileID = open.FileID
	d.HasLastCreated = true

	attrs := uint32(smb2.FileAttrNormal)
	allocSize := uint64(0)
	endOfFile := uint64(0)
	if isDir {
		attrs = smb2.FileAttrDirectory
	} else if st != nil {
		allocSize = uint64(st.Size())
		endOfFile = uint64(st.Size())
	}
	mtime := filetimeFromTime(time.Now())
	if st != nil {
		mtime = filetimeFromTime(st.ModTime())
	}
	// F9: use real birth time (statx btime) for CreationTime in the CREATE
	// response when the filesystem provides it. Falls back to ModTime.
	createCtime := mtime
	if bt, ok := birthTime(osPath); ok {
		createCtime = filetimeFromTime(bt)
	}

	// SMB2_CREATE_QUERY_ON_DISK_ID (QFid) wants the real POSIX identity of the
	// object we just opened. Prefer fstat on the handle (immune to a rename
	// racing the CREATE); directories have no *os.File here, so fall back to
	// the lstat we already did. A failed stat leaves both zero, and QFid is
	// then omitted rather than answered with a zero id.
	qfidInfo := st
	if open.File != nil {
		if fi, ferr := open.File.Stat(); ferr == nil {
			qfidInfo = fi
		}
	}
	diskFileID, volumeID := unixInodeAndDev(qfidInfo)

	// Register a durable handle and collect the extra response contexts
	// (DH2Q/DHnQ echo, RqLs lease grant) to append to the AAPL/MxAc/QFid set.
	respCtxs := buildCreateResponseContexts(req.CreateContexts, d.Conn, granted, diskFileID, volumeID)
	respCtxs = d.applyDurableAndLease(open, durReq, leaseReq, respCtxs, sess.User.Name)

	resp := smb2.EncodeCreateResponse(smb2.CreateResponse{
		CreateAction:   createAction,
		CreationTime:   createCtime,
		LastAccessTime: mtime,
		LastWriteTime:  mtime,
		ChangeTime:     mtime,
		AllocationSize: allocSize,
		EndOfFile:      endOfFile,
		FileAttributes: attrs,
		FileID:         open.FileID,
		CreateContexts: respCtxs,
	})
	d.respondSuccess(rw, hdr, sess, resp)
	return true
}

// statusFromErr maps a filesystem error to the NTSTATUS a client expects.
//
// Getting this right is directly user-visible: clients branch on the status to
// decide whether to retry, to surface "disk full", or to give up. Collapsing
// every errno to STATUS_INTERNAL_ERROR makes a full disk look like a server
// bug, and makes rmdir-on-non-empty look unrecoverable.
//
// The errno→NTSTATUS table follows Samba's unix_dos_nt_errmap
// (source3/lib/errmap_unix.c) so we behave like the reference POSIX-backed SMB
// server. errors.Is unwraps the *os.PathError / *os.LinkError wrappers the os
// package returns.
func statusFromErr(err error) smb2.Status {
	if err == nil {
		return smb2.StatusSuccess
	}
	// The specific errno tests run first. The os.Is* predicates below are
	// deliberately coarse — syscall.Errno.Is folds ENOTEMPTY into fs.ErrExist,
	// for instance — so consulting them first would report a non-empty
	// directory as OBJECT_NAME_COLLISION.
	switch {
	// ENOSPC/EDQUOT/EFBIG all mean "the write cannot be stored". Reporting
	// DISK_FULL lets the client tell the user why instead of retrying.
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT), errors.Is(err, syscall.EFBIG):
		return smb2.StatusDiskFull
	case errors.Is(err, syscall.ENOTEMPTY):
		return smb2.StatusDirectoryNotEmpty
	case errors.Is(err, syscall.EISDIR):
		return smb2.StatusFileIsADirectory
	case errors.Is(err, syscall.ENOTDIR):
		return smb2.StatusNotADirectory
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		return smb2.StatusTooManyOpenedFiles
	// Samba maps a read-only filesystem to ACCESS_DENIED rather than
	// MEDIA_WRITE_PROTECTED; every client already handles ACCESS_DENIED.
	case errors.Is(err, syscall.EROFS):
		return smb2.StatusAccessDenied
	case errors.Is(err, syscall.ENAMETOOLONG):
		return smb2.StatusObjectNameInvalid
	case errors.Is(err, syscall.EXDEV):
		return smb2.StatusNotSameDevice
	// ELOOP means a path component was a symlink loop (or O_NOFOLLOW hit a
	// symlink). Samba reports it as a path lookup failure.
	case errors.Is(err, syscall.ELOOP):
		return smb2.StatusObjectPathNotFound
	case errors.Is(err, syscall.EMLINK):
		return smb2.StatusTooManyLinks
	case errors.Is(err, syscall.ENOMEM), errors.Is(err, syscall.ENOBUFS):
		return smb2.StatusInsufficientResources
	case errors.Is(err, syscall.EIO):
		return smb2.StatusIODeviceError
	case errors.Is(err, syscall.EBADF):
		return smb2.StatusInvalidHandle
	case errors.Is(err, syscall.EINVAL):
		return smb2.StatusInvalidParameter
	case errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.ENOTSUP):
		return smb2.StatusNotSupported
	}
	// Fall back to the portable sentinels (fs.ErrNotExist, fs.ErrPermission,
	// fs.ErrExist) for errors that carry no errno at all.
	switch {
	case os.IsNotExist(err):
		return smb2.StatusObjectNameNotFound
	case os.IsPermission(err):
		return smb2.StatusAccessDenied
	case os.IsExist(err):
		return smb2.StatusObjectNameCollision
	}
	return smb2.StatusInternalError
}

// --- READ ---

func (d *Dispatcher) handleRead(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeReadRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if open.IsPipe {
		// Drain any queued DCE/RPC response from a prior WRITE.
		if len(open.pipeOut) == 0 {
			d.respondError(rw, hdr, smb2.StatusEndOfFile, sess)
			return true
		}
		n := int(req.Length)
		if n > len(open.pipeOut) {
			n = len(open.pipeOut)
		}
		out := open.pipeOut[:n]
		open.pipeOut = open.pipeOut[n:]
		d.respondSuccess(rw, hdr, sess, smb2.EncodeReadResponse(smb2.ReadResponse{Data: out}))
		return true
	}
	if open.IsStream {
		// Compare in uint64 before narrowing to int: a wire offset past 2^63
		// would otherwise become negative and panic the streamBuf slice.
		if req.Offset >= uint64(len(open.streamBuf)) {
			d.respondError(rw, hdr, smb2.StatusEndOfFile, sess)
			return true
		}
		off := int(req.Offset)
		end := off + int(req.Length)
		if end > len(open.streamBuf) || end < off {
			end = len(open.streamBuf)
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeReadResponse(smb2.ReadResponse{Data: open.streamBuf[off:end]}))
		return true
	}
	if open.File == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// Clamp the request to the negotiated MaxReadSize so a single READ can't
	// force an arbitrary (up to 4 GiB) allocation. A compliant client never
	// asks for more than it negotiated.
	if maxIO := d.Conn.MaxIOSize; maxIO != 0 && req.Length > maxIO {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// A read may not cross another handle's exclusive byte-range lock.
	if d.locks != nil && d.locks.conflictsWith(open, req.Offset, uint64(req.Length), false) {
		d.respondError(rw, hdr, smb2.StatusFileLockConflict, sess)
		return true
	}
	buf := make([]byte, req.Length)
	n, err := open.File.ReadAt(buf, int64(req.Offset))
	if err != nil && err != io.EOF {
		d.Log.Warn("read failed", "path", open.Path, "err", err)
		d.respondError(rw, hdr, statusFromErr(err), sess)
		return true
	}
	if n == 0 {
		d.respondError(rw, hdr, smb2.StatusEndOfFile, sess)
		return true
	}
	resp := smb2.EncodeReadResponse(smb2.ReadResponse{Data: buf[:n]})
	d.respondSuccess(rw, hdr, sess, resp)
	return true
}

// --- WRITE ---

func (d *Dispatcher) handleWrite(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeWriteRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// Enforce read-only share: writes are never permitted.
	if open.Tree != nil && open.Tree.Share.ReadOnly && !open.IsPipe {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	if open.IsPipe {
		// Run DCE/RPC and queue the response for the next READ.
		if open.PipeName == "srvsvc" {
			if out := dcerpcHandle(req.Data, visibleShares(d.Shares, sess)); out != nil {
				open.pipeOut = append(open.pipeOut, out...)
			}
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeWriteResponse(smb2.WriteResponse{Count: uint32(len(req.Data))}))
		return true
	}
	if open.IsStream {
		// Streams are held wholly in memory and persisted as an xattr, so a
		// huge offset is both meaningless and dangerous: int(req.Offset) on a
		// >2^63 value goes negative (panicking the slice), and a large offset
		// would drive an unbounded make([]byte, end). Reject anything past the
		// stream size cap before touching the buffer.
		if req.Offset > maxStreamSize || uint64(len(req.Data)) > maxStreamSize ||
			req.Offset+uint64(len(req.Data)) > maxStreamSize {
			d.respondError(rw, hdr, smb2.StatusDiskFull, sess)
			return true
		}
		off := int(req.Offset)
		end := off + len(req.Data)
		if end > len(open.streamBuf) {
			grown := make([]byte, end)
			copy(grown, open.streamBuf)
			open.streamBuf = grown
		}
		copy(open.streamBuf[off:end], req.Data)
		open.streamWritten = true
		d.respondSuccess(rw, hdr, sess, smb2.EncodeWriteResponse(smb2.WriteResponse{Count: uint32(len(req.Data))}))
		return true
	}
	if open.File == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// A write may not touch any byte another handle holds locked, shared or
	// exclusive.
	if d.locks != nil && d.locks.conflictsWith(open, req.Offset, uint64(len(req.Data)), true) {
		d.respondError(rw, hdr, smb2.StatusFileLockConflict, sess)
		return true
	}
	n, err := open.File.WriteAt(req.Data, int64(req.Offset))
	if err != nil {
		d.Log.Warn("write failed", "path", open.Path, "err", err)
		d.respondError(rw, hdr, statusFromErr(err), sess)
		return true
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeWriteResponse(smb2.WriteResponse{Count: uint32(n)}))
	return true
}

// --- FLUSH ---

func (d *Dispatcher) handleFlush(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeFlushRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if open.File != nil {
		_ = open.File.Sync()
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeFlushResponse())
	return true
}

// --- SET_INFO ---

func (d *Dispatcher) handleSetInfo(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeSetInfoRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("set-info",
		"info_type", req.InfoType,
		"info_class", req.FileInfoClass,
		"path", open.Path,
		"buf_len", len(req.Buffer),
	)
	// Enforce read-only share: SET_INFO is always a write mutation.
	if open.Tree != nil && open.Tree.Share.ReadOnly {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	if open.IsStream {
		// Honor EOF (resize the in-memory buffer) and Disposition (delete-on-
		// close → remove the backing xattr at CLOSE). Rename/EA/Basic on a
		// stream are accepted silently.
		switch {
		case req.InfoType == smb2.InfoTypeFile && req.FileInfoClass == smb2.FileEndOfFileInformation && len(req.Buffer) >= 8:
			// The size is client-chosen and drives a make() on an in-memory
			// buffer, so it needs exactly the cap the stream WRITE path
			// already applies — otherwise one SET_INFO makes the server
			// allocate terabytes. Compare as uint64 first: int() of a value
			// past 2^63 goes negative and would slip through as "truncate".
			wire := binary.LittleEndian.Uint64(req.Buffer[0:])
			if wire > maxStreamSize {
				d.respondError(rw, hdr, smb2.StatusDiskFull, sess)
				return true
			}
			size := int(wire)
			switch {
			case size <= 0:
				open.streamBuf = nil
			case size <= len(open.streamBuf):
				open.streamBuf = open.streamBuf[:size]
			default:
				grown := make([]byte, size)
				copy(grown, open.streamBuf)
				open.streamBuf = grown
			}
		case req.InfoType == smb2.InfoTypeFile && req.FileInfoClass == smb2.FileDispositionInformation && len(req.Buffer) >= 1:
			open.DeleteOnClose = req.Buffer[0] != 0
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeSetInfoResponse())
		return true
	}
	// Silently accept SD / quota / FS-info SET_INFO. We don't persist ACLs,
	// but Samba and Windows answer SUCCESS here so clients (Finder especially)
	// don't conclude the handle is broken. Refusing surfaces as "you don't
	// have permission to see its contents" on macOS for newly created dirs.
	if req.InfoType == smb2.InfoTypeSecurity ||
		req.InfoType == smb2.InfoTypeQuota ||
		req.InfoType == smb2.InfoTypeFilesystem {
		d.respondSuccess(rw, hdr, sess, smb2.EncodeSetInfoResponse())
		return true
	}
	if req.InfoType != smb2.InfoTypeFile {
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
	switch req.FileInfoClass {
	case smb2.FileEndOfFileInformation:
		if len(req.Buffer) < 8 {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		size := int64(binary.LittleEndian.Uint64(req.Buffer[0:]))
		if err := truncateOpen(open, size); err != nil {
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
	case smb2.FileAllocationInformation:
		// Best-effort: ignore (POSIX doesn't have a portable preallocation primitive).
	case smb2.FileDispositionInformation:
		if len(req.Buffer) < 1 {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		open.DeleteOnClose = req.Buffer[0] != 0
	case smb2.FileRenameInformation:
		// Buffer: ReplaceIfExists(1) + Reserved(7) + RootDirectory(8) + FileNameLength(4) + FileName(N)
		if len(req.Buffer) < 20 {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		replace := req.Buffer[0] != 0
		nameLen := binary.LittleEndian.Uint32(req.Buffer[16:])
		if 20+int(nameLen) > len(req.Buffer) {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		newName := decodeUTF16LE(req.Buffer[20 : 20+nameLen])
		// Use normalization-insensitive resolution for the rename destination so
		// that lookups across NFC/NFD boundaries work. For a new name (doesn't
		// exist yet), it falls through to the requested name unchanged.
		newPath, err := vfs.ResolveSecureNorm(open.Tree.Share.Path, newName)
		if err != nil {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		if !replace {
			if _, err := os.Lstat(newPath); err == nil {
				d.respondError(rw, hdr, smb2.StatusObjectNameCollision, sess)
				return true
			}
		}
		if err := os.Rename(open.Path, newPath); err != nil {
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
		open.Path = newPath
	case smb2.FileFullEaInformation:
		// Parse the FILE_FULL_EA_INFORMATION list (MS-FSCC §2.4.15) and persist
		// each EA as a user.* xattr. macOS uses this to seed Versions/Quarantine/
		// AppleDouble metadata. If the filesystem lacks xattr support we accept
		// silently (matching the prior accept-and-drop behavior) so clients
		// don't conclude the handle is broken.
		for _, ea := range parseFullEaList(req.Buffer) {
			if err := setEAOnFile(open.File, open.Path, ea.Name, ea.Value); err != nil {
				if errors.Is(err, errXattrUnsupported) {
					break
				}
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
		}
	case smb2.FileBasicInformationSet:
		// Only LastWriteTime/LastAccessTime are applied; POSIX has no setter
		// for CreationTime or ChangeTime, and a 0 / -1 field means "leave
		// unchanged" (MS-FSCC §2.4.7).
		if len(req.Buffer) >= 32 {
			lastWrite := int64(binary.LittleEndian.Uint64(req.Buffer[16:]))
			lastAccess := int64(binary.LittleEndian.Uint64(req.Buffer[8:]))
			if lastWrite > 0 && lastWrite != -1 {
				wt := timeFromFiletime(uint64(lastWrite))
				at := wt
				if lastAccess > 0 && lastAccess != -1 {
					at = timeFromFiletime(uint64(lastAccess))
				}
				// Report a failed timestamp write instead of swallowing it.
				// rclone compares modification times to decide whether a file
				// still needs uploading; answering SUCCESS for a time we never
				// set makes it treat a stale copy as up to date indefinitely.
				if err := setTimesOnOpen(open, at, wt); err != nil {
					d.Log.Warn("set-info: setting times failed", "path", open.Path, "err", err)
					d.respondError(rw, hdr, statusFromErr(err), sess)
					return true
				}
			}
		}
	default:
		d.Log.Warn("set-info: unsupported class", "class", req.FileInfoClass)
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeSetInfoResponse())
	return true
}

// truncateOpen resizes the file behind an Open.
//
// It uses the descriptor CREATE already opened with O_NOFOLLOW rather than
// re-resolving the path: os.Truncate follows symlinks, so a symlink swapped in
// between CREATE and this SET_INFO would redirect the resize to whatever it
// points at, bypassing the O_NOFOLLOW protection on the open. Directory
// handles carry no descriptor and fall back to the path (where truncate is
// EISDIR anyway).
func truncateOpen(open *Open, size int64) error {
	if open.File != nil {
		return open.File.Truncate(size)
	}
	return os.Truncate(open.Path, size)
}

// setTimesOnOpen applies access/modification times to the file behind an Open.
//
// os.Chtimes resolves the path and follows symlinks, which reopens the TOCTOU
// window that CREATE's O_NOFOLLOW closed. utimensat with AT_SYMLINK_NOFOLLOW
// never traverses a symlink at the leaf and, unlike futimes(2), keeps the full
// nanosecond resolution the client's 100 ns FILETIME deserves — a microsecond
// rounding would make the mtime the client reads back differ from the one it
// set.
func setTimesOnOpen(open *Open, atime, mtime time.Time) error {
	ts := []unix.Timespec{
		unix.NsecToTimespec(atime.UnixNano()),
		unix.NsecToTimespec(mtime.UnixNano()),
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, open.Path, ts, unix.AT_SYMLINK_NOFOLLOW)
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	// Surrogate pairs must be recombined into one rune; decoding each code
	// unit separately corrupts every non-BMP filename (emoji and friends),
	// which utf16leName then re-encodes as U+FFFD.
	return string(utf16.Decode(u))
}

func timeFromFiletime(ft uint64) time.Time {
	if ft == 0 {
		return time.Now()
	}
	secs := int64(ft/10_000_000) - filetimeEpochDelta
	nanos := int64(ft%10_000_000) * 100
	return time.Unix(secs, nanos).UTC()
}

// --- CLOSE ---

func (d *Dispatcher) handleClose(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeCloseRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.RemoveOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// Closing the directory handle must complete any CHANGE_NOTIFY watching it
	// (MS-SMB2 §3.3.5.19), otherwise the client waits on a handle that is gone.
	d.cancelNotifiesForOpens([]*Open{open})
	// A clean CLOSE of a durable handle means it is no longer reclaimable —
	// drop its durable-table entry (a dropped connection, by contrast, leaves
	// it for reclaim until expiry).
	if open.IsDurable && d.Conn != nil && d.Conn.Durable != nil {
		d.Conn.Durable.Remove(open.DurableClientGuid, open.DurableCreateGuid)
	}
	if open.File != nil {
		if d.locks != nil {
			d.locks.releaseAll(open)
		}
		open.File.Close()
	}
	if open.IsPipe {
		// No POSTQUERY_ATTRIB echo here even when asked: a pipe has no times,
		// no size and no attributes, so the only thing we could report is a
		// block of zeros — which the client would reject anyway (see
		// closeAttribsUsable).
		d.respondSuccess(rw, hdr, sess, smb2.EncodeCloseResponse(smb2.CloseResponse{}))
		return true
	}
	if open.IsStream {
		// Persist the stream buffer to its backing xattr, or remove it on
		// delete-on-close. A zero-length buffer still writes an (empty) xattr so
		// the stream "exists". ENOTSUP (no xattr support) is tolerated silently.
		//
		// This branch always returns, which is what keeps delete-on-close of a
		// stream from ever reaching the os.Remove(open.Path) below: deleting
		// `dir:com.apple.metadata:...` drops the xattr and leaves the directory
		// (and, for a file stream, the file) untouched.
		if open.DeleteOnClose {
			if err := removeStreamXattr(open.Path, open.StreamName); err != nil && !errors.Is(err, errXattrUnsupported) {
				// The client asked for the stream to be gone; if it isn't,
				// say so rather than reporting a delete that never happened.
				d.Log.Warn("stream delete-on-close failed", "path", open.Path, "stream", open.StreamName, "err", err)
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
		} else if open.streamSynthetic && !open.streamWritten {
			// A fabricated blob (e.g. empty AFP_AfpInfo) the client only read —
			// don't persist it, so we don't litter the file with metadata xattrs.
		} else if err := writeStreamXattr(open.Path, open.StreamName, open.streamBuf); err != nil && !errors.Is(err, errXattrUnsupported) {
			// This is the only point at which stream bytes reach disk, so a
			// swallowed error here loses everything the client wrote while
			// CLOSE still reports SUCCESS. Every failure must be surfaced.
			//
			// Linux user.* xattrs are size-limited (~64 KiB on ext4). A resource
			// fork larger than that yields E2BIG — map to STATUS_DISK_FULL,
			// which is the closest "your data did not fit" status.
			d.Log.Warn("stream flush failed", "path", open.Path, "stream", open.StreamName, "err", err)
			if errors.Is(err, syscall.E2BIG) {
				d.respondError(rw, hdr, smb2.StatusDiskFull, sess)
				return true
			}
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
		now := filetimeFromTime(time.Now())
		resp := smb2.CloseResponse{
			CreationTime:   now,
			LastAccessTime: now,
			LastWriteTime:  now,
			ChangeTime:     now,
			AllocationSize: uint64(len(open.streamBuf)),
			EndOfFile:      uint64(len(open.streamBuf)),
			FileAttributes: smb2.FileAttrNormal,
		}
		// The stream's size is exact and the times are the ones a fresh
		// QUERY_INFO on this handle would have reported, so the echo is honest.
		if closeAttribsUsable(req, resp) {
			resp.Flags = smb2.CloseFlagPostQueryAttrib
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeCloseResponse(resp))
		return true
	}
	if open.DeleteOnClose {
		// Never let DELETE_ON_CLOSE on the tree root remove the shared
		// directory itself — that would take the whole share offline. The
		// refusal has to be visible: a SUCCESS here would tell the client the
		// share directory is gone when it is not.
		if open.Tree != nil && open.Tree.Share.Path != "" &&
			filepath.Clean(open.Path) == filepath.Clean(open.Tree.Share.Path) {
			d.Log.Warn("refusing delete-on-close of the share root", "path", open.Path)
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// A failed unlink must not be reported as a successful CLOSE: the
		// client (rclone especially) records the file as deleted and never
		// retries, while the file is still on disk. Surface the real reason —
		// STATUS_DIRECTORY_NOT_EMPTY for a populated directory, ACCESS_DENIED
		// for a sticky/read-only parent, and so on.
		//
		// An already-vanished path is not an error: the client's intent (the
		// name is gone) holds either way.
		if err := os.Remove(open.Path); err != nil && !os.IsNotExist(err) {
			d.Log.Warn("delete-on-close failed", "path", open.Path, "err", err)
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
	}
	st, _ := os.Lstat(open.Path)
	resp := smb2.CloseResponse{}
	if st != nil {
		mt := filetimeFromTime(st.ModTime())
		// F9: use btime for CreationTime in CLOSE response when available.
		ct := mt
		if bt, ok := birthTime(open.Path); ok {
			ct = filetimeFromTime(bt)
		}
		resp.CreationTime = ct
		resp.LastAccessTime = mt
		resp.LastWriteTime = mt
		resp.ChangeTime = mt
		resp.AllocationSize = uint64(st.Size())
		resp.EndOfFile = uint64(st.Size())
		if st.IsDir() {
			resp.FileAttributes = smb2.FileAttrDirectory
		} else {
			resp.FileAttributes = smb2.FileAttrNormal
		}
	}
	// A failed Lstat (deleted by DELETE_ON_CLOSE, or the name vanished under
	// us) leaves resp zeroed, and the guard keeps the flag off — the client
	// then asks for the attributes itself instead of trusting a lie.
	if closeAttribsUsable(req, resp) {
		resp.Flags = smb2.CloseFlagPostQueryAttrib
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeCloseResponse(resp))
	return true
}

// closeAttribsUsable reports whether a CLOSE response may echo
// SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB. Two conditions must hold: the client asked
// for the attributes, and we actually have them.
//
// The second condition is not optional. macOS sets the flag on every CLOSE and
// its parser throws away the *entire* attribute block if CreationTime,
// LastAccessTime, LastWriteTime or ChangeTime comes back as zero, logging the
// peer as a "Bad SMB 2/3 Server". Echoing the flag over a zeroed response is
// therefore strictly worse than not echoing it: the client re-reads the
// metadata with a fresh CREATE/QUERY_INFO/CLOSE either way, and we have also
// told it we are broken.
func closeAttribsUsable(req smb2.CloseRequest, resp smb2.CloseResponse) bool {
	if req.Flags&smb2.CloseFlagPostQueryAttrib == 0 {
		return false
	}
	return resp.CreationTime != 0 && resp.LastAccessTime != 0 &&
		resp.LastWriteTime != 0 && resp.ChangeTime != 0
}

// --- QUERY_DIRECTORY ---

func (d *Dispatcher) handleQueryDirectory(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeQueryDirectoryRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil || !open.IsDir {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("query-dir",
		"path", open.Path,
		"info_class", req.FileInformationClass,
		"flags", req.Flags,
		"pattern", req.FileName,
		"buf_len", req.OutputBufferLength,
	)
	// OutputBufferLength comes straight off the wire and is used as an
	// allocation size, so an unclamped value lets one request ask for up to
	// 4 GiB. MS-SMB2 §3.3.5.18 says a request whose OutputBufferLength exceeds
	// Connection.MaxTransactSize is failed with STATUS_INVALID_PARAMETER; a
	// compliant client never asks for more than it negotiated. Mirrors the
	// READ length clamp in handleRead.
	if d.Conn != nil && d.Conn.MaxIOSize != 0 && req.OutputBufferLength > d.Conn.MaxIOSize {
		d.Log.Warn("query-dir: output buffer exceeds negotiated max",
			"requested", req.OutputBufferLength, "max", d.Conn.MaxIOSize)
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// Reject an information class we have no encoder for *before* enumerating.
	// Falling through to a differently-shaped record makes the client parse
	// garbage; MS-SMB2 §3.3.5.18 mandates STATUS_INVALID_INFO_CLASS instead.
	if !supportedDirInfoClass(req.FileInformationClass) {
		d.Log.Warn("query-dir: unsupported info class",
			"class", req.FileInformationClass, "path", open.Path)
		d.respondError(rw, hdr, smb2.StatusInvalidInfoClass, sess)
		return true
	}
	if req.Flags&smb2.QueryDirRestartScans != 0 || open.dirEntries == nil {
		entries, err := os.ReadDir(open.Path)
		if err != nil {
			d.Log.Warn("query-dir: ReadDir failed", "path", open.Path, "err", err, "status", statusFromErr(err))
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
		// Prepend synthetic "." and ".." entries — Windows/macOS clients expect
		// them. Both stats can fail even though the ReadDir above succeeded
		// (the directory may be renamed or removed in between), and a nil
		// os.FileInfo baked into a syntheticDirEntry is later dereferenced
		// during record encoding, panicking the server. Omit an entry we
		// cannot stat rather than carrying a nil through.
		all := make([]os.DirEntry, 0, len(entries)+2)
		dirInfo, dirErr := os.Lstat(open.Path)
		if dirErr == nil {
			all = append(all, syntheticDirEntry{name: ".", info: dirInfo})
		} else {
			d.Log.Warn("query-dir: cannot stat directory, omitting \".\"", "path", open.Path, "err", dirErr)
		}
		parentInfo, parentErr := os.Lstat(filepath.Dir(open.Path))
		if parentErr != nil {
			// Fall back to the directory's own info — but only when that stat
			// actually succeeded, otherwise ".." is omitted too.
			parentInfo, parentErr = dirInfo, dirErr
		}
		if parentErr == nil {
			all = append(all, syntheticDirEntry{name: "..", info: parentInfo})
		} else {
			d.Log.Warn("query-dir: cannot stat parent, omitting \"..\"", "path", open.Path, "err", parentErr)
		}
		all = append(all, entries...)

		// Apply pattern filter (SMB-style glob, case-insensitive). Hide
		// names containing `:` so any pre-existing stream-syntax pollution
		// (created before stream parsing was wired up) is invisible to
		// clients — `:` is illegal in NTFS names anyway, so a real SMB
		// client could never have legitimately created such a name.
		pattern := req.FileName
		if pattern == "" {
			pattern = "*"
		}
		filtered := all[:0:0]
		for _, e := range all {
			if strings.ContainsRune(e.Name(), ':') {
				continue
			}
			if matchSMBPattern(pattern, e.Name()) {
				filtered = append(filtered, e)
			}
		}
		open.dirEntries = filtered
		open.dirSent = 0
		d.Log.Debug("query-dir: enumerated",
			"path", open.Path,
			"total", len(all),
			"matched", len(filtered),
			"pattern", pattern,
		)
	}

	// Empty result on a fresh enumeration → STATUS_NO_SUCH_FILE.
	// Empty result on a continuation → STATUS_NO_MORE_FILES.
	if len(open.dirEntries) == 0 {
		d.respondError(rw, hdr, smb2.StatusNoSuchFile, sess)
		return true
	}
	if open.dirSent >= len(open.dirEntries) {
		d.respondError(rw, hdr, smb2.StatusNoMoreFiles, sess)
		return true
	}

	limit := len(open.dirEntries) - open.dirSent
	if req.Flags&smb2.QueryDirReturnSingleEntry != 0 {
		limit = 1
	}
	// AAPL READ_DIR_ATTR overlay applies only on disk shares (not IPC$) and
	// only for the level-37 record class.
	useAAPL := d.Conn != nil && d.Conn.AAPLReadDirAttr &&
		open.Tree != nil && open.Tree.Share.Path != "" &&
		req.FileInformationClass == smb2.InfoFileIdBothDirectoryInformation
	buf, consumed, encoded, err := encodeDirEntriesLimited(open, int(req.OutputBufferLength), req.FileInformationClass, limit, useAAPL)
	if err != nil {
		if errors.Is(err, errUnsupportedDirInfoClass) {
			d.respondError(rw, hdr, smb2.StatusInvalidInfoClass, sess)
			return true
		}
		d.respondError(rw, hdr, smb2.StatusInternalError, sess)
		return true
	}
	// Advance the enumeration cursor by the entries actually *consumed*, not
	// by the records encoded. An entry skipped during encoding (it vanished
	// between the scan and the encode) otherwise leaves dirSent pointing at an
	// entry we already walked past, so the next QUERY_DIRECTORY re-emits files
	// the client has already seen. rclone re-lists directories constantly, so
	// a drifting cursor is immediately visible as duplicated entries.
	open.dirSent += consumed
	if encoded == 0 {
		if open.dirSent >= len(open.dirEntries) {
			d.respondError(rw, hdr, smb2.StatusNoMoreFiles, sess)
			return true
		}
		// Entries remain but not even one fits in OutputBufferLength.
		// Answering NO_MORE_FILES here silently truncates the listing;
		// MS-SMB2 §3.3.5.18 requires STATUS_INFO_LENGTH_MISMATCH so the
		// client retries with a buffer big enough for one record.
		d.Log.Warn("query-dir: output buffer too small for one entry",
			"path", open.Path, "buf_len", req.OutputBufferLength)
		d.respondError(rw, hdr, smb2.StatusInfoLengthMismatch, sess)
		return true
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryDirectoryResponse(smb2.QueryDirectoryResponse{Buffer: buf}))
	return true
}

// matchSMBPattern matches name against an SMB glob pattern, case-insensitively.
// Supports `*` and `?`. Empty pattern means match all.
func matchSMBPattern(pattern, name string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(name))
	return ok
}

// errUnsupportedDirInfoClass is returned when encodeDirRecord has no encoder
// for the requested class. handleQueryDirectory turns it into
// STATUS_INVALID_INFO_CLASS — the request is pre-validated by
// supportedDirInfoClass, so this is a belt-and-braces guard that keeps a
// newly-listed class from silently emitting a wrong-shaped record.
var errUnsupportedDirInfoClass = errors.New("query-dir: unsupported information class")

// supportedDirInfoClass reports whether encodeDirRecord can emit the requested
// FileInformationClass. It must stay in lockstep with encodeDirRecord's switch.
func supportedDirInfoClass(c uint8) bool {
	switch c {
	case smb2.InfoFileDirectoryInformation,
		smb2.InfoFileFullDirectoryInformation,
		smb2.InfoFileBothDirectoryInformation,
		smb2.InfoFileNamesInformation,
		smb2.InfoFileIdBothDirectoryInformation,
		smb2.InfoFileIdFullDirectoryInformation:
		return true
	}
	return false
}

// encodeDirEntriesLimited packs at most `limit` records (or as many as fit in
// maxBytes) starting at open.dirSent. When useAAPL is true and infoClass is
// FileIdBothDirectoryInformation, each record carries the Apple overlay so
// Finder gets FinderInfo/rfork/mode in one round-trip.
//
// It returns the packed buffer, the number of entries consumed from
// open.dirEntries (what the caller must add to open.dirSent), and the number
// of records actually encoded. The two counts differ whenever an entry is
// dropped mid-batch because its Info() failed — it was unlinked between
// os.ReadDir and here. The cursor has to follow `consumed`: advancing by the
// record count would leave it behind the scan position, so the next call
// re-encodes entries the client already received.
//
// Records are linked as they are appended, carrying the previous record's start
// offset in a local. Re-deriving it by walking the NextEntryOffset chain from
// the head of the buffer made linking quadratic in the number of records in a
// *single* response: at the 8 MiB this server advertises as MaxTransactSize
// that is ~75k records and ~2.8G list steps, seconds of CPU that any client
// honouring the advertised buffer can ask for over and over.
//
// Every record is also priced from its name before a single syscall is made for
// it. A record is a fixed size per class plus two bytes per UTF-16 code unit of
// the name, rounded up to 8, so the entry that straddles the end of the buffer
// is left for the next call instead of being stat'ed, xattr-probed, encoded and
// then discarded.
func encodeDirEntriesLimited(open *Open, maxBytes int, infoClass uint8, limit int, useAAPL bool) (out []byte, consumed, encoded int, err error) {
	fixed, ok := dirRecordFixedSize(infoClass)
	if !ok {
		return nil, 0, 0, errUnsupportedDirInfoClass
	}
	// maxBytes is client-chosen (bounded by MaxTransactSize upstream) and most
	// listings are far smaller, so cap the up-front reservation and let append
	// grow rather than allocating megabytes on every request.
	initial := maxBytes
	if initial > 64<<10 {
		initial = 64 << 10
	}
	if initial < 0 {
		initial = 0
	}
	out = make([]byte, 0, initial)
	maxAccess := uint32(0x001F01FF)
	if open.Tree != nil && open.Tree.Share.ReadOnly {
		maxAccess = 0x001200A9
	}
	// FILE_NAMES_INFORMATION is NextEntryOffset + FileIndex + FileNameLength +
	// the name (MS-FSCC §2.4.26) — nothing the stat could fill in. Calling
	// Info() for it is one lstat per entry for fields that are never encoded.
	needStat := infoClass != smb2.InfoFileNamesInformation
	// Start offset of the record appended most recently, so the chain is linked
	// in constant time per record rather than by re-walking it.
	prevStart := 0
	for i := open.dirSent; i < len(open.dirEntries) && encoded < limit; i++ {
		ent := open.dirEntries[i]
		name := ent.Name()
		// Price the record from the name alone, before any I/O. An entry that
		// does not fit is re-offered on the next call, so its lstat and
		// resource-fork probe would be done twice and used once.
		if len(out)+padTo8(fixed+utf16leLen(name)) > maxBytes {
			break
		}
		var info os.FileInfo
		if needStat {
			fi, ierr := ent.Info()
			if ierr != nil || fi == nil {
				// The entry vanished between the scan and now (or is an
				// unstattable synthetic "."/".."). Skip the record but still
				// count the entry as consumed so the cursor keeps pace with i.
				consumed = i + 1 - open.dirSent
				continue
			}
			info = fi
		}
		var rforkSize uint64
		if useAAPL && info != nil && !info.IsDir() {
			// Report the AAPL resource-fork size from its backing ADS xattr.
			// Only the length is wanted, so size the attribute rather than
			// reading the whole fork into memory to call len() on it.
			if n, xerr := streamXattrSize(filepath.Join(open.Path, name), rforkStreamName); xerr == nil {
				rforkSize = uint64(n)
			}
		}
		rec := encodeDirRecord(name, info, infoClass, useAAPL, maxAccess, rforkSize)
		if rec == nil {
			return nil, 0, 0, errUnsupportedDirInfoClass
		}
		// Pad from the encoded record, never from the estimate above: the
		// estimate only gates the fit check, and a one-byte drift in the
		// padding is a silent wire corruption rather than an error. Should the
		// real record ever overrun the budget, leave it for the next call.
		padded := padTo8(len(rec))
		if len(out)+padded > maxBytes {
			break
		}
		if encoded > 0 {
			binary.LittleEndian.PutUint32(out[prevStart:], uint32(len(out)-prevStart))
		}
		prevStart = len(out)
		out = append(out, rec...)
		out = append(out, dirRecordPadding[:padded-len(rec)]...)
		encoded++
		consumed = i + 1 - open.dirSent
	}
	return out, consumed, encoded, nil
}

// dirRecordPadding supplies the zero bytes that align a record to 8; a record
// never needs more than seven.
var dirRecordPadding [8]byte

// padTo8 rounds n up to the next multiple of 8. Directory records are 8-byte
// aligned, so a record's padded length is exactly its NextEntryOffset.
func padTo8(n int) int {
	if r := n % 8; r != 0 {
		return n + 8 - r
	}
	return n
}

// dirRecordFixedSize returns the size of the name-independent part of a record
// for infoClass, and whether encodeDirRecord can emit that class at all.
//
// It must stay in lockstep with encodeDirRecord's per-class layout: these sizes
// are fixed by MS-FSCC, and they are what lets the enumerator decide whether an
// entry fits before doing any I/O for it. TestDirEncode_FixedSizesMatchEncoder
// pins them to what encodeDirRecord actually emits.
func dirRecordFixedSize(infoClass uint8) (int, bool) {
	switch infoClass {
	case smb2.InfoFileDirectoryInformation:
		return 64, true // MS-FSCC §2.4.10
	case smb2.InfoFileFullDirectoryInformation:
		return 68, true // MS-FSCC §2.4.14
	case smb2.InfoFileNamesInformation:
		return 12, true // MS-FSCC §2.4.26
	case smb2.InfoFileBothDirectoryInformation:
		return 94, true // MS-FSCC §2.4.8
	case smb2.InfoFileIdFullDirectoryInformation:
		return 80, true // MS-FSCC §2.4.20
	case smb2.InfoFileIdBothDirectoryInformation:
		return 104, true // MS-FSCC §2.4.17
	}
	return 0, false
}

// encodeDirRecord builds a single directory entry record. Supported classes:
// FileDirectoryInformation, FileFullDirectoryInformation,
// FileBothDirectoryInformation, FileNamesInformation,
// FileIdBothDirectoryInformation and FileIdFullDirectoryInformation.
//
// It returns nil for any other class. It must NOT fall back to a different
// class: every class has its own fixed-part size, so emitting (say) a
// 94-byte FILE_BOTH_DIR_INFORMATION record for a client that asked for the
// 80-byte FILE_ID_FULL_DIR_INFORMATION makes the client parse garbage —
// mis-sized names, bogus sizes, and a corrupt listing. Callers turn nil into
// STATUS_INVALID_INFO_CLASS.
//
// When useAAPL is true and infoClass is FileIdBothDirectoryInformation, the
// record overlays Apple's AAPL fields onto the record per Apple's spec
// (max_access in EaSize, rfork_size+FinderInfo in ShortName, UNIX mode in
// Reserved2). maxAccess is the per-share maximal access mask reported as
// max_access. See Samba's smb2_trans2.c SMB_FIND_ID_BOTH_DIRECTORY_INFO case.
func encodeDirRecord(name string, info os.FileInfo, infoClass uint8, useAAPL bool, maxAccess uint32, rforkSize uint64) []byte {
	nameU16 := utf16leName(name)
	switch infoClass {
	case smb2.InfoFileDirectoryInformation:
		// MS-FSCC §2.4.10 — 64 fixed bytes + name.
		const fixed = 64
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileFullDirectoryInformation:
		// MS-FSCC §2.4.14 — 68 fixed bytes (adds EaSize) + name.
		const fixed = 68
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileNamesInformation:
		// MS-FSCC §2.4.26 — 12 fixed (NextEntryOffset+FileIndex+FileNameLength) + name.
		const fixed = 12
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint32(out[8:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileIdBothDirectoryInformation:
		// Layout (104 fixed bytes + name):
		// 0  NextEntryOffset (4)
		// 4  FileIndex (4)
		// 8  CreationTime (8)
		// 16 LastAccessTime (8)
		// 24 LastWriteTime (8)
		// 32 ChangeTime (8)
		// 40 EndOfFile (8)
		// 48 AllocationSize (8)
		// 56 FileAttributes (4)
		// 60 FileNameLength (4)
		// 64 EaSize (4)
		// 68 ShortNameLength (1)
		// 69 Reserved (1)
		// 70 ShortName (24)
		// 94 Reserved2 (2)
		// 96 FileId (8)
		// 104 FileName (variable)
		const fixed = 104
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		unixMode, inode := unixModeAndInode(info)
		if useAAPL {
			// Apple overlay (matches Samba's vfs_fruit + smb2_trans2.c):
			//  EaSize          = max_access
			//  ShortNameLength = 24 (Apple writes literal 24 even though spec says 0)
			//  ShortName[0..7] = rfork_size (always 0 — no resource fork store)
			//  ShortName[8..23]= compressed FinderInfo (16 bytes of zeros)
			//  Reserved2       = UNIX mode (low 16 bits)
			//  FileId          = inode
			binary.LittleEndian.PutUint32(out[64:], maxAccess)
			out[68] = 24
			out[69] = 0
			// ShortName[0..7] = rfork_size (from the AFP_AfpResource ADS xattr;
			// 0 when no resource fork is stored).
			binary.LittleEndian.PutUint64(out[70:], rforkSize)
			// out[78..93] FinderInfo = 0 (already zero)
			binary.LittleEndian.PutUint16(out[94:], unixMode)
			binary.LittleEndian.PutUint64(out[96:], inode)
		} else if inode != 0 {
			// Always populate FileId so clients have a stable identifier.
			binary.LittleEndian.PutUint64(out[96:], inode)
		}
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileIdFullDirectoryInformation:
		// MS-FSCC §2.4.20 FILE_ID_FULL_DIR_INFORMATION — 80 fixed bytes + name:
		// 0  NextEntryOffset (4)
		// 4  FileIndex (4)
		// 8  CreationTime (8)
		// 16 LastAccessTime (8)
		// 24 LastWriteTime (8)
		// 32 ChangeTime (8)
		// 40 EndOfFile (8)
		// 48 AllocationSize (8)
		// 56 FileAttributes (4)
		// 60 FileNameLength (4)
		// 64 EaSize (4)
		// 68 Reserved (4)
		// 72 FileId (8)
		// 80 FileName (variable)
		const fixed = 80
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		// EaSize (64) and Reserved (68) stay zero. FileId carries the inode so
		// clients have a stable identifier, matching what the IdBoth class does.
		if _, inode := unixModeAndInode(info); inode != 0 {
			binary.LittleEndian.PutUint64(out[72:], inode)
		}
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileBothDirectoryInformation:
		// MS-FSCC §2.4.8 FILE_BOTH_DIR_INFORMATION: like IdBoth but with no
		// FileId field. Layout (94 bytes fixed + name).
		const fixed = 94
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	default:
		return nil
	}
}

// --- QUERY_INFO ---

func (d *Dispatcher) handleQueryInfo(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeQueryInfoRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.Log.Warn("query-info: unknown file id")
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("query-info",
		"info_type", req.InfoType,
		"info_class", req.FileInfoClass,
		"path", open.Path,
	)

	switch req.InfoType {
	case smb2.InfoTypeFile:
		info := openFileInfo(open)
		buf, ok := encodeFileInfo(req.FileInfoClass, info, open)
		if !ok {
			d.Log.Warn("query-info: unsupported file info class", "class", req.FileInfoClass, "path", open.Path)
			d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
			return true
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryInfoResponse(smb2.QueryInfoResponse{Buffer: buf}))
		return true
	case smb2.InfoTypeFilesystem:
		buf, ok := encodeFsInfo(req.FileInfoClass, open)
		if !ok {
			d.Log.Warn("query-info: unsupported fs info class", "class", req.FileInfoClass, "path", open.Path)
			d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
			return true
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryInfoResponse(smb2.QueryInfoResponse{Buffer: buf}))
		return true
	case smb2.InfoTypeSecurity:
		buf := minimalSelfRelativeSD()
		d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryInfoResponse(smb2.QueryInfoResponse{Buffer: buf}))
		return true
	default:
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
}

func openFileInfo(o *Open) os.FileInfo {
	if o.IsStream {
		return streamFileInfo{name: o.StreamName, size: int64(len(o.streamBuf))}
	}
	info, _ := os.Lstat(o.Path)
	return info
}

// fileIDFor returns the identifier this server reports for a handle. It is the
// exact value encodeDirRecord writes into the FileId field of the
// FILE_ID_BOTH/FULL_DIR_INFORMATION records — the real inode, obtained from the
// same unixModeAndInode helper — so a file enumerated in a directory listing and
// the same file stat'ed through QUERY_INFO can never report two different ids.
//
// This is not cosmetic on macOS. smbfs treats a changed id for a path as "this
// path now holds a different object": see node_vtype_changed and smbfs_nget in
// smbfs_node.c, which purge the vnode from the name cache, pull it out of the
// node hash and drop it, zero the attribute and symlink cache timers, and
// invalidate the page cache. Two encoders disagreeing means that happens for
// every file, on every stat.
//
// Named-stream handles carry a synthetic streamFileInfo with no syscall.Stat_t
// behind it, so they have no inode of their own; we fall back to the inode of
// the base file the stream hangs off (o.Path is the base file even for a stream
// Open). That matches NTFS, where every stream of a file shares the file's MFT
// record number, and it keeps a stream handle from reporting 0 — a zero id tells
// the client the server has no usable File IDs and makes it stop trusting them.
func fileIDFor(info os.FileInfo, o *Open) uint64 {
	if _, ino := unixModeAndInode(info); ino != 0 {
		return ino
	}
	// Synthetic FileInfo (named streams): report the base file's inode.
	if o != nil && o.Path != "" {
		if st, err := os.Lstat(o.Path); err == nil {
			if _, ino := unixModeAndInode(st); ino != 0 {
				return ino
			}
		}
	}
	return 0
}

func encodeFileInfo(class uint8, info os.FileInfo, o *Open) ([]byte, bool) {
	if info == nil {
		return nil, false
	}
	t := filetimeFromTime(info.ModTime())
	// F9: use real birth time (statx btime) for CreationTime when available.
	// Falls back to ModTime when the filesystem/kernel doesn't provide btime
	// (e.g. tmpfs, older kernels < 4.11, or filesystems that don't populate
	// stx_btime). LastAccess / LastWrite / ChangeTime remain as ModTime.
	ctime := t
	if o != nil && o.Path != "" && !o.IsStream {
		if bt, ok := birthTime(o.Path); ok {
			ctime = filetimeFromTime(bt)
		}
	}
	attrs := uint32(smb2.FileAttrNormal)
	if info.IsDir() {
		attrs = smb2.FileAttrDirectory
	}
	switch class {
	case smb2.FileBasicInformation:
		out := make([]byte, 40)
		binary.LittleEndian.PutUint64(out[0:], ctime) // CreationTime
		binary.LittleEndian.PutUint64(out[8:], t)     // LastAccessTime
		binary.LittleEndian.PutUint64(out[16:], t)    // LastWriteTime
		binary.LittleEndian.PutUint64(out[24:], t)    // ChangeTime
		binary.LittleEndian.PutUint32(out[32:], attrs)
		return out, true
	case smb2.FileStandardInformation:
		out := make([]byte, 24)
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[0:], size)
		binary.LittleEndian.PutUint64(out[8:], size)
		binary.LittleEndian.PutUint32(out[16:], 1) // NumberOfLinks
		if info.IsDir() {
			out[21] = 0x01
		}
		return out, true
	case smb2.FileInternalInformation:
		out := make([]byte, 8)
		// IndexNumber — the real inode, the same value the directory encoder
		// reports as this file's FileId.
		binary.LittleEndian.PutUint64(out[0:], fileIDFor(info, o))
		return out, true
	case smb2.FileEaInformation:
		return make([]byte, 4), true
	case smb2.FileFullEaInformation:
		// Encode the persisted EAs as a FILE_FULL_EA_INFORMATION list. An empty
		// list (no EAs, or a filesystem without xattr support) is a valid
		// zero-length buffer — what NTFS returns for "no EAs".
		eas, err := listEAs(o.Path)
		if err != nil {
			return []byte{}, true
		}
		return encodeFullEaList(eas), true
	case smb2.FileAccessInformation:
		out := make([]byte, 4)
		access := o.GrantedAccess
		if access == 0 {
			access = smb2.AccessFileReadData | smb2.AccessFileReadAttributes | smb2.AccessFileReadEa | smb2.AccessReadControl
		}
		binary.LittleEndian.PutUint32(out[0:], access)
		return out, true
	case smb2.FilePositionInformation:
		return make([]byte, 8), true
	case smb2.FileModeInformation:
		return make([]byte, 4), true
	case smb2.FileAlignmentInformation:
		return make([]byte, 4), true
	case smb2.FileNetworkOpenInformation:
		out := make([]byte, 56)
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[0:], ctime) // CreationTime
		binary.LittleEndian.PutUint64(out[8:], t)     // LastAccessTime
		binary.LittleEndian.PutUint64(out[16:], t)    // LastWriteTime
		binary.LittleEndian.PutUint64(out[24:], t)    // ChangeTime
		binary.LittleEndian.PutUint64(out[32:], size)
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint32(out[48:], attrs)
		return out, true
	case smb2.FileAttributeTagInformation:
		// FileAttributes(4) + ReparseTag(4)
		out := make([]byte, 8)
		binary.LittleEndian.PutUint32(out[0:], attrs)
		return out, true
	case smb2.FileAlternateNameInformation:
		// FileNameLength(4) + FileName(N) — empty 8.3 alt name.
		out := make([]byte, 4)
		return out, true
	case smb2.FileStreamInformation:
		// Default ::$DATA entry plus one :<name>:$DATA entry per persisted ADS
		// stream. A directory reports only its named streams (it has no unnamed
		// data stream) — encodeStreamInfoList drops the ::$DATA entry for one,
		// so a folder carrying Finder metadata enumerates it here instead of
		// always claiming it has no streams at all.
		return encodeStreamInfoList(o.Path, info.Size()), true
	case smb2.FileNameInformation:
		// FileNameLength(4) + FileName(N) — return basename.
		nameU16 := utf16leName(filepath.Base(o.Path))
		out := make([]byte, 4+len(nameU16))
		binary.LittleEndian.PutUint32(out[0:], uint32(len(nameU16)))
		copy(out[4:], nameU16)
		return out, true
	case smb2.FileAllInformation:
		nameU16 := utf16leName(filepath.Base(o.Path))
		const fixedHead = 40 + 24 + 8 + 4 + 4 + 8 + 4 + 4 // 96
		out := make([]byte, fixedHead+4+len(nameU16))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		// Basic (40)
		binary.LittleEndian.PutUint64(out[0:], ctime) // CreationTime
		binary.LittleEndian.PutUint64(out[8:], t)     // LastAccessTime
		binary.LittleEndian.PutUint64(out[16:], t)    // LastWriteTime
		binary.LittleEndian.PutUint64(out[24:], t)    // ChangeTime
		binary.LittleEndian.PutUint32(out[32:], attrs)
		// Standard (24) at offset 40
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		binary.LittleEndian.PutUint32(out[56:], 1)
		if info.IsDir() {
			out[61] = 0x01 // Directory
		}
		// Internal (8) at offset 64 — IndexNumber, the real inode. Identical
		// to FileInternalInformation and to the directory encoder's FileId.
		binary.LittleEndian.PutUint64(out[64:], fileIDFor(info, o))
		// Ea (4) at 72 — zero
		// Access (4) at 76
		access := o.GrantedAccess
		if access == 0 {
			access = smb2.AccessFileReadData | smb2.AccessFileReadAttributes | smb2.AccessFileReadEa | smb2.AccessReadControl
		}
		binary.LittleEndian.PutUint32(out[76:], access)
		// Position (8) at 80 — zero
		// Mode (4) at 88 — zero
		// Alignment (4) at 92 — zero
		// NameInformation: FileNameLength(4) + FileName at offset 96
		binary.LittleEndian.PutUint32(out[fixedHead:], uint32(len(nameU16)))
		copy(out[fixedHead+4:], nameU16)
		return out, true
	}
	return nil, false
}

func encodeFsInfo(class uint8, o *Open) ([]byte, bool) {
	switch class {
	case smb2.FileFsAttributeInformation:
		// FileSystemAttributes(4) + MaxFileNameLength(4) + FileSystemNameLength(4) + Name (UTF-16LE)
		//
		// Bits we claim (MS-FSCC §2.5.1):
		//   0x00000001 FILE_CASE_SENSITIVE_SEARCH
		//   0x00000002 FILE_CASE_PRESERVED_NAMES
		//   0x00000004 FILE_UNICODE_ON_DISK
		//   0x00000008 FILE_PERSISTENT_ACLS
		//   0x00000040 FILE_SUPPORTS_SPARSE_FILES
		//   0x00040000 FILE_NAMED_STREAMS  — needed so macOS will round-trip
		//                                    AppleDouble metadata via streams
		//                                    rather than creating ._foo files.
		//   0x00800000 FILE_SUPPORTS_EXTENDED_ATTRIBUTES — required for macOS
		//                                    Versions ("permanent version
		//                                    storage") to enable on the share.
		const fsAttrs uint32 = 0x0084004F
		name := utf16leName("NTFS")
		out := make([]byte, 12+len(name))
		binary.LittleEndian.PutUint32(out[0:], fsAttrs)
		binary.LittleEndian.PutUint32(out[4:], 255)
		binary.LittleEndian.PutUint32(out[8:], uint32(len(name)))
		copy(out[12:], name)
		return out, true
	case smb2.FileFsVolumeInformation:
		// CreationTime(8) + SerialNumber(4) + LabelLength(4) + Reserved(2) + Label
		label := utf16leName(filepath.Base(o.Tree.Share.Path))
		out := make([]byte, 18+len(label))
		binary.LittleEndian.PutUint64(out[0:], filetimeNow())
		binary.LittleEndian.PutUint32(out[8:], 0xCAFE1337)
		binary.LittleEndian.PutUint32(out[12:], uint32(len(label)))
		copy(out[18:], label)
		return out, true
	case smb2.FileFsSizeInformation:
		total, avail, spu, bps := fsStats(o.Tree.Share.Path)
		out := make([]byte, 24)
		binary.LittleEndian.PutUint64(out[0:], total)
		binary.LittleEndian.PutUint64(out[8:], avail)
		binary.LittleEndian.PutUint32(out[16:], spu)
		binary.LittleEndian.PutUint32(out[20:], bps)
		return out, true
	case smb2.FileFsFullSizeInformation:
		total, avail, spu, bps := fsStats(o.Tree.Share.Path)
		out := make([]byte, 32)
		binary.LittleEndian.PutUint64(out[0:], total)
		binary.LittleEndian.PutUint64(out[8:], avail)
		binary.LittleEndian.PutUint64(out[16:], avail)
		binary.LittleEndian.PutUint32(out[24:], spu)
		binary.LittleEndian.PutUint32(out[28:], bps)
		return out, true
	case smb2.FileFsDeviceInformation:
		// DeviceType(4) + Characteristics(4)
		out := make([]byte, 8)
		binary.LittleEndian.PutUint32(out[0:], 0x07) // FILE_DEVICE_DISK
		binary.LittleEndian.PutUint32(out[4:], 0x20) // FILE_DEVICE_IS_MOUNTED
		return out, true
	}
	return nil, false
}

// --- IOCTL ---

func (d *Dispatcher) handleIoctl(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeIoctlRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("ioctl", "ctl_code", fmt.Sprintf("0x%08x", req.CtlCode), "input_len", len(req.InputBuffer))
	switch req.CtlCode {
	case smb2.FsctlPipeTransceive:
		open := sess.GetOpen(req.FileID)
		if open == nil || !open.IsPipe || open.PipeName != "srvsvc" {
			// Unknown pipe — reply with bind_nak so the client stops retrying.
			var callID uint32
			if len(req.InputBuffer) >= 16 {
				callID = binary.LittleEndian.Uint32(req.InputBuffer[12:16])
			}
			d.respondSuccess(rw, hdr, sess, smb2.EncodeIoctlResponse(smb2.IoctlResponse{
				CtlCode:      req.CtlCode,
				FileID:       req.FileID,
				OutputBuffer: dcerpcBindNakBytes(callID),
			}))
			return true
		}
		out := dcerpcHandle(req.InputBuffer, visibleShares(d.Shares, sess))
		if out == nil {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeIoctlResponse(smb2.IoctlResponse{
			CtlCode:      req.CtlCode,
			FileID:       req.FileID,
			OutputBuffer: out,
		}))
		return true
	case smb2.FsctlDfsGetReferrals:
		// We are not a DFS root. Reply with FSDRIVER_NOT_DFS so the client
		// stops asking. Some old clients use STATUS_NOT_FOUND here too.
		d.respondError(rw, hdr, smb2.StatusFsDriverRequired, sess)
		return true
	case smb2.FsctlSrvCopyChunk, smb2.FsctlSrvRequestResumeKey, smb2.FsctlPipeWait:
		// Decline gracefully so clients fall back to read+write.
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	case smb2.FsctlValidateNegotiateInfo:
		// Echo back a minimal response confirming we agree on the negotiate info.
		// Body: Capabilities(4) + ClientGuid(16) + SecurityMode(2) + Dialect(2)
		out := make([]byte, 24)
		binary.LittleEndian.PutUint32(out[0:], 0)
		copy(out[4:20], d.Conn.ServerGuid[:])
		binary.LittleEndian.PutUint16(out[20:], 1) // signing enabled
		binary.LittleEndian.PutUint16(out[22:], uint16(d.Conn.Selection.Dialect))
		resp := smb2.EncodeIoctlResponse(smb2.IoctlResponse{
			CtlCode:      req.CtlCode,
			FileID:       req.FileID,
			OutputBuffer: out,
		})
		d.respondSuccess(rw, hdr, sess, resp)
		return true
	default:
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
}

// --- helpers ---

// unixModeAndInode pulls the POSIX mode bits (low 16 bits of st_mode, including
// the type field) and inode number out of os.FileInfo. Returns (0, 0) for
// FileInfo implementations that don't expose syscall.Stat_t (synthetic streams,
// non-Linux platforms).
func unixModeAndInode(info os.FileInfo) (uint16, uint64) {
	if info == nil {
		return 0, 0
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0
	}
	return uint16(st.Mode & 0xFFFF), uint64(st.Ino)
}

// unixInodeAndDev pulls the inode and device numbers out of os.FileInfo for the
// SMB2_CREATE_QUERY_ON_DISK_ID (QFid) response context. Returns (0, 0) for
// FileInfo implementations that don't expose syscall.Stat_t (synthetic stream
// handles), which is the caller's signal to omit the context entirely.
func unixInodeAndDev(info os.FileInfo) (uint64, uint64) {
	if info == nil {
		return 0, 0
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0
	}
	return uint64(st.Ino), devToUint64(st.Dev)
}

// devToUint64 widens a st_dev to uint64 without sign-extending. The concrete
// type of syscall.Stat_t.Dev differs per platform (int32 on darwin, uint64 on
// linux), so this goes through an interface type switch rather than needing a
// per-GOOS file.
func devToUint64(dev any) uint64 {
	switch v := dev.(type) {
	case int32:
		return uint64(uint32(v))
	case uint32:
		return uint64(v)
	case int64:
		return uint64(v)
	case uint64:
		return v
	}
	return 0
}

const filetimeEpochDelta = 11644473600

func filetimeFromTime(t time.Time) uint64 {
	t = t.UTC()
	if t.Year() < 1601 {
		return 0
	}
	secs := uint64(t.Unix() + filetimeEpochDelta)
	return secs*10_000_000 + uint64(t.Nanosecond())/100
}

func utf16leName(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r <= 0xFFFF {
			out = append(out, byte(r), byte(r>>8))
		} else {
			r -= 0x10000
			hi := 0xD800 + uint16(r>>10)
			lo := 0xDC00 + uint16(r&0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return out
}

// utf16leLen returns the number of bytes utf16leName would produce for s,
// without building the encoding. The enumerator uses it to size a record before
// deciding whether the entry fits; it must agree with utf16leName byte for
// byte, which TestDirEncode_UTF16LenMatchesEncoder checks.
func utf16leLen(s string) int {
	n := 0
	for _, r := range s {
		if r <= 0xFFFF {
			n += 2
		} else {
			n += 4
		}
	}
	return n
}

// silence unused-vars for the dispatcher's helpers when not referenced.
var _ = errors.New
var _ = fmt.Errorf

// handleChangeNotify watches the directory referenced by FileID via inotify
// and replies asynchronously when an event arrives. The immediate reply is
// STATUS_PENDING with an AsyncId; the eventual completion is signed and
// posted from a goroutine.
func (d *Dispatcher) handleChangeNotify(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeChangeNotifyRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil || !open.IsDir {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	w, err := inotify.New(open.Path)
	if err != nil {
		d.Log.Warn("inotify init failed", "path", open.Path, "err", err)
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}

	asyncID := d.nextAsyncID.Add(1)
	watchTree := req.Flags&smb2.NotifyWatchTree != 0
	filter := req.CompletionFilter
	maxOut := req.OutputBufferLength

	reg := &notifyReg{open: open, cancel: make(chan struct{}), status: smb2.StatusCancelled}
	d.registerNotify(hdr.MessageID, reg)

	// Send STATUS_PENDING (async-format header) immediately.
	d.sendAsync(rw, hdr, sess, asyncID, smb2.StatusPending, []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// accept filters one raw watcher event down to a wire entry, honouring
	// SMB2_WATCH_TREE (without it only the immediate directory is reported)
	// and the client's CompletionFilter.
	accept := func(ev inotify.InotifyEvent) (smb2.NotifyEntry, bool) {
		rel, err := filepath.Rel(open.Path, ev.Path)
		if err != nil {
			return smb2.NotifyEntry{}, false
		}
		if !watchTree && strings.Contains(rel, string(filepath.Separator)) {
			// A change in a subdirectory: only a recursive watch reports it.
			return smb2.NotifyEntry{}, false
		}
		action := actionForEvent(ev.Event)
		if action == 0 || !notifyFilterAllows(filter, action) {
			return smb2.NotifyEntry{}, false
		}
		return smb2.NotifyEntry{Action: action, Name: strings.ReplaceAll(rel, "/", "\\")}, true
	}

	go func() {
		defer w.Close()
		defer d.unregisterNotify(hdr.MessageID)
		go w.Watch()

		var entries []smb2.NotifyEntry
		cancelled := false

		for len(entries) == 0 && !cancelled {
			select {
			case ev, ok := <-w.Events:
				if !ok || ev.Event == inotify.WatchStop {
					cancelled = true
					continue
				}
				e, keep := accept(ev)
				if !keep {
					continue
				}
				entries = append(entries, e)
				// Drain a short burst so a batch of changes ships in one reply.
				drainTimer := time.NewTimer(30 * time.Millisecond)
				for drain := true; drain; {
					select {
					case ev2, ok := <-w.Events:
						if !ok || ev2.Event == inotify.WatchStop {
							drain = false
							continue
						}
						if e2, keep2 := accept(ev2); keep2 {
							entries = append(entries, e2)
						}
					case <-drainTimer.C:
						drain = false
					case <-reg.cancel:
						drain = false
					}
				}
				drainTimer.Stop()
			case <-reg.cancel:
				cancelled = true
			}
		}

		if cancelled && len(entries) == 0 {
			// CLOSE/TREE_DISCONNECT/CANCEL completed us: answer the original
			// request with a plain error frame, not a CHANGE_NOTIFY body.
			d.notifyMu.Lock()
			status := reg.status
			d.notifyMu.Unlock()
			d.sendAsync(rw, hdr, sess, asyncID, status,
				[]byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}

		buf := smb2.EncodeFileNotifyInformation(entries)
		// MS-SMB2 §3.3.5.19: if the changes do not fit in the buffer the client
		// offered, report STATUS_NOTIFY_ENUM_DIR with no records so it re-scans
		// the directory itself. Previously the oversized buffer was sent anyway.
		if maxOut != 0 && uint32(len(buf)) > maxOut {
			d.sendAsync(rw, hdr, sess, asyncID, smb2.StatusNotifyEnumDir,
				smb2.EncodeChangeNotifyResponse(smb2.ChangeNotifyResponse{}))
			return
		}
		d.sendAsync(rw, hdr, sess, asyncID, smb2.StatusSuccess,
			smb2.EncodeChangeNotifyResponse(smb2.ChangeNotifyResponse{Buffer: buf}))
	}()
	return true
}

func actionForEvent(t inotify.EventType) uint32 {
	switch t {
	case inotify.FileCreate, inotify.FolderCreate:
		return smb2.FileActionAdded
	case inotify.Delete:
		return smb2.FileActionRemoved
	case inotify.Modified:
		return smb2.FileActionModified
	case inotify.MovedFrom:
		return smb2.FileActionRenamedOldName
	case inotify.MovedTo:
		return smb2.FileActionRenamedNewName
	}
	return 0
}

// sendAsync builds and writes an SMB2 async-format response (FlagAsyncCommand
// set, AsyncId in bytes 32-39 instead of TreeId/Reserved). The whole frame
// is signed end-to-end like a sync response.
func (d *Dispatcher) sendAsync(rw io.ReadWriter, reqHdr smb2.Header, sess *Session, asyncID uint64, status smb2.Status, body []byte) {
	respHdr := smb2.Header{
		CreditCharge:   reqHdr.CreditCharge,
		Status:         uint32(status),
		Command:        reqHdr.Command,
		CreditResponse: grantCredits(reqHdr.CreditCharge, reqHdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      reqHdr.MessageID,
		SessionID:      reqHdr.SessionID,
	}
	out := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeAsyncHeader(out[:smb2.HeaderSize], respHdr, asyncID)
	copy(out[smb2.HeaderSize:], body)
	willEncrypt := sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		sess.GotEncrypted()
	if !willEncrypt && sess != nil && len(sess.SigningKey) > 0 {
		smb3.SignMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, out)
	}
	_ = d.writeFrame(rw, sess, out)
}
