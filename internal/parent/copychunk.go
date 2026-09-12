package parent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// Server-side-copy ceilings.
//
// MS-SMB2 §3.3.1.1 gives a server three per-request limits for FSCTL_SRV_COPYCHUNK
// — ServerSideCopyMaxNumberofChunks, ServerSideCopyMaxChunkSize and
// ServerSideCopyMaxDataSize — and §3.3.5.15.6 says a request exceeding any of
// them is failed with STATUS_INVALID_PARAMETER *and* an SRV_COPYCHUNK_RESPONSE
// reporting the three ceilings, so the client can retry within them. These are
// the values Windows uses, and they are also exactly what the macOS client
// already assumes (SMB2_COPYCHUNK_ARR_SIZE 16, SMB2_COPYCHUNK_MAX_CHUNK_LEN
// 1 MiB in smb_rq_2.h), so a well-behaved macOS copy never trips them.
//
// They also bound the work one IOCTL can ask for: 16 MiB of copying per request
// with no allocation larger than copyBufSize behind it.
const (
	maxCopyChunkCount uint32 = 256
	maxCopyChunkSize  uint32 = 1 << 20  // 1 MiB per chunk
	maxCopyChunkTotal uint32 = 16 << 20 // 16 MiB per request
)

// copyChunkReadAccess / copyChunkWriteAccess are the granted-access bits a
// handle must carry to be, respectively, the source and the target of a
// server-side copy. The client gets no more through COPYCHUNK than it would get
// through READ and WRITE on the same two handles.
const (
	copyChunkReadAccess  = smb2.AccessFileReadData | smb2.AccessGenericRead | smb2.AccessGenericAll
	copyChunkWriteAccess = smb2.AccessFileWriteData | smb2.AccessFileAppendData |
		smb2.AccessGenericWrite | smb2.AccessGenericAll
)

// copyChunkLimits is the SRV_COPYCHUNK_RESPONSE that accompanies every
// STATUS_INVALID_PARAMETER refusal of a copychunk request: read against that
// status the three fields mean "max chunks", "max bytes per chunk" and "max
// bytes per request". macOS retries once using ChunkBytesWritten as its new
// chunk size (see <rdar://problem/14750992> in smbfs_smb_2.c), so sending the
// numbers rather than a bare error is what makes an oversized request recover
// instead of falling back to a client-side copy.
func copyChunkLimits() []byte {
	return smb2.EncodeSrvCopyChunkResponse(maxCopyChunkCount, maxCopyChunkSize, maxCopyChunkTotal)
}

// --- resume keys ---

// resumeKeyEntry binds one issued SRV_RESUME_KEY to the open it names and to
// the session that asked for it.
//
// The session is the security boundary. A resume key is a bearer capability: it
// is the *only* thing an SRV_COPYCHUNK_COPY carries to name its source, so
// anyone holding one can read from that handle. MS-SMB2 §3.3.5.15.6 therefore
// requires the server to check that the open the key names belongs to the
// session issuing the copy, and to fail the request otherwise. Without that
// check a second session on the same connection — a different authenticated
// user, or a guest — could read any file some other user had open simply by
// replaying a 24-byte value.
type resumeKeyEntry struct {
	open *Open
	sess *Session
}

// resumeKeyTable is the per-connection map of issued resume keys. It hangs off
// Connection, so its whole lifetime is the connection's: keys cannot outlive
// the socket they were minted on even if the handle behind them is durable and
// gets reclaimed elsewhere. Within that, each entry's lifetime is the open's —
// release() runs from CLOSE, TREE_DISCONNECT, LOGOFF and previous-session
// teardown, all of which funnel through handleClose or releaseOpens.
type resumeKeyTable struct {
	mu     sync.Mutex
	byKey  map[[smb2.ResumeKeyLen]byte]resumeKeyEntry
	byOpen map[*Open][smb2.ResumeKeyLen]byte
}

// issue returns the resume key for open, minting a fresh random one the first
// time and returning the same key on every later request for the same handle.
//
// Re-issuing the stored key rather than a new one is deliberate: it keeps the
// table one entry per open (so a client looping on the FSCTL cannot grow it
// without bound) and it matches what clients expect from a key described as
// naming the handle.
func (t *resumeKeyTable) issue(sess *Session, open *Open) ([smb2.ResumeKeyLen]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if key, ok := t.byOpen[open]; ok {
		// Re-key if the handle somehow changed hands; an open belongs to one
		// session for its whole life, so this is belt and braces.
		if e, ok := t.byKey[key]; ok && e.sess == sess {
			return key, nil
		}
		delete(t.byKey, key)
		delete(t.byOpen, open)
	}
	var key [smb2.ResumeKeyLen]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("resume key: %w", err)
	}
	if t.byKey == nil {
		t.byKey = make(map[[smb2.ResumeKeyLen]byte]resumeKeyEntry)
		t.byOpen = make(map[*Open][smb2.ResumeKeyLen]byte)
	}
	t.byKey[key] = resumeKeyEntry{open: open, sess: sess}
	t.byOpen[open] = key
	return key, nil
}

// resolve returns the open a key names, but only for the session that was
// issued it. An unknown key and a key belonging to another session are the same
// answer — nil — so a caller probing keys learns nothing from the reply beyond
// "not yours".
func (t *resumeKeyTable) resolve(key [smb2.ResumeKeyLen]byte, sess *Session) *Open {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.byKey[key]
	if !ok || e.sess != sess {
		return nil
	}
	return e.open
}

// release drops the key issued for open, if any. Called from every path that
// retires a handle, so a key never outlives the descriptor it names.
func (t *resumeKeyTable) release(open *Open) {
	if open == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if key, ok := t.byOpen[open]; ok {
		delete(t.byKey, key)
		delete(t.byOpen, open)
	}
}

// clear empties the table. The connection teardown path calls it so nothing is
// left holding an *Open (and through it an fd) after the socket is gone.
func (t *resumeKeyTable) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byKey = nil
	t.byOpen = nil
}

// len reports how many keys are outstanding. Used by tests to prove the table
// does not leak.
func (t *resumeKeyTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byKey)
}

// --- FSCTL handlers ---

// respondWithStatus writes a response body under a caller-chosen status.
//
// respondSuccess hardcodes STATUS_SUCCESS and respondError sends a bare 9-byte
// SMB2 error body, and copychunk needs neither: a refused copy carries a full
// StructureSize-49 IOCTL response holding the SRV_COPYCHUNK_RESPONSE *under* a
// failure status. That is what MS-SMB2 §3.3.5.15.6 specifies and what the macOS
// client parses — on EINVAL it re-reads the failed reply as an IOCTL response
// and rejects anything whose StructureSize is not 49.
func (d *Dispatcher) respondWithStatus(rw io.Writer, hdr smb2.Header, sess *Session, status smb2.Status, body []byte) {
	d.lastChainStatus = status
	d.emit(rw, sess, d.buildResponse(hdr, status, body))
}

// respondCopyChunkRefusal answers a copychunk the server will not perform with
// STATUS_INVALID_PARAMETER and the server's ceilings, wrapped in a normal IOCTL
// response.
func (d *Dispatcher) respondCopyChunkRefusal(rw io.ReadWriter, hdr smb2.Header, sess *Session, req smb2.IoctlRequest) {
	d.respondWithStatus(rw, hdr, sess, smb2.StatusInvalidParameter, smb2.EncodeIoctlResponse(smb2.IoctlResponse{
		CtlCode:      req.CtlCode,
		FileID:       req.FileID,
		OutputBuffer: copyChunkLimits(),
	}))
}

// handleResumeKey answers FSCTL_SRV_REQUEST_RESUME_KEY with a 24-byte opaque
// capability naming the open the IOCTL was issued on.
//
// macOS probes this FSCTL once per mount (smb2fs_smb_cmpd_check_copyfile:
// CREATE + IOCTL + CLOSE) and only advertises VOL_CAP_INT_COPYFILE — the thing
// that routes copyfile(2) through server-side copy instead of dragging every
// byte over the wire twice — if it succeeds. The probe runs against the share
// root, a *directory*, so refusing directories here would silently disable
// server-side copy for the whole mount.
func (d *Dispatcher) handleResumeKey(rw io.ReadWriter, hdr smb2.Header, req smb2.IoctlRequest, sess *Session) bool {
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// A pipe has no file behind it and a stream handle is a synthetic xattr
	// buffer; neither can ever be a copy source, so decline rather than hand
	// out a key that COPYCHUNK would only refuse later.
	if open.IsPipe || open.IsStream {
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
	key, err := d.Conn.resumeKeys.issue(sess, open)
	if err != nil {
		d.Log.Warn("resume key generation failed", "err", err)
		d.respondError(rw, hdr, smb2.StatusInsufficientResources, sess)
		return true
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeIoctlResponse(smb2.IoctlResponse{
		CtlCode:      req.CtlCode,
		FileID:       req.FileID,
		OutputBuffer: smb2.EncodeResumeKeyResponse(key),
	}))
	return true
}

// handleCopyChunk performs FSCTL_SRV_COPYCHUNK / FSCTL_SRV_COPYCHUNK_WRITE: the
// target handle is the one the IOCTL was issued on, the source is named by the
// resume key inside the request, and the copy happens entirely on the server.
//
// The two control codes differ only in the access they demand of the target
// (MS-SMB2 §3.3.5.15.6): plain COPYCHUNK wants read *and* write, COPYCHUNK_WRITE
// only write. Both are handled here.
func (d *Dispatcher) handleCopyChunk(rw io.ReadWriter, hdr smb2.Header, req smb2.IoctlRequest, sess *Session) bool {
	target := sess.GetOpen(req.FileID)
	if target == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if target.File == nil || target.IsDir || target.IsPipe || target.IsStream {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// A read-only share is read-only however the write is spelled. Doing the
	// copy inside the server does not make it less of a write.
	if target.Tree != nil && target.Tree.Share.ReadOnly {
		d.Log.Warn("copychunk refused on read-only share",
			"share", target.Tree.Share.Name, "path", target.Path, "session_id", sess.ID)
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	if target.GrantedAccess&copyChunkWriteAccess == 0 {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	if req.CtlCode == smb2.FsctlSrvCopyChunk && target.GrantedAccess&copyChunkReadAccess == 0 {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}

	cc, err := smb2.DecodeSrvCopyChunkCopy(req.InputBuffer, maxCopyChunkCount)
	if err != nil {
		// Malformed and over-limit both answer STATUS_INVALID_PARAMETER; only
		// the over-limit case reads the limits body, and a client that
		// misparsed its own request is no worse off for receiving it.
		d.Log.Debug("copychunk request rejected", "err", err)
		d.respondCopyChunkRefusal(rw, hdr, sess, req)
		return true
	}

	source := d.Conn.resumeKeys.resolve(cc.SourceKey, sess)
	if source == nil {
		// Unknown key, or a key minted for a different session. Same answer
		// either way, so nothing is learned by guessing.
		d.Log.Warn("copychunk source key not resolvable for this session", "session_id", sess.ID)
		d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
		return true
	}
	if source.File == nil || source.IsDir || source.IsPipe || source.IsStream {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if source.GrantedAccess&copyChunkReadAccess == 0 {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}

	srcInfo, err := source.File.Stat()
	if err != nil {
		d.Log.Warn("copychunk source stat failed", "path", source.Path, "err", err)
		d.respondError(rw, hdr, statusFromErr(err), sess)
		return true
	}
	srcSize := uint64(srcInfo.Size())

	// Validate every chunk before copying a single byte, so a request that is
	// bad at chunk 9 does not leave chunks 1-8 already applied to the target.
	if status, ok := validateCopyChunks(cc.Chunks, srcSize); !ok {
		if status == smb2.StatusInvalidParameter {
			d.respondCopyChunkRefusal(rw, hdr, sess, req)
		} else {
			d.respondError(rw, hdr, status, sess)
		}
		return true
	}
	// Copying a file onto itself through two handles is legal; copying one
	// range of a file onto an overlapping range of the same file is not
	// something we can do without a staging buffer, and the obvious
	// implementations silently produce wrong bytes. Refuse it instead.
	if sameUnderlyingFile(source.File, target.File) && chunksOverlap(cc.Chunks) {
		d.respondCopyChunkRefusal(rw, hdr, sess, req)
		return true
	}

	var chunksWritten, totalWritten uint32
	for _, ch := range cc.Chunks {
		n, err := copyRange(target.File, source.File,
			int64(ch.SourceOffset), int64(ch.TargetOffset), int64(ch.Length))
		totalWritten += uint32(n)
		if err != nil || n != int64(ch.Length) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			d.Log.Warn("copychunk copy failed",
				"src", source.Path, "dst", target.Path,
				"chunk", chunksWritten, "copied", n, "want", ch.Length, "err", err)
			// ChunkBytesWritten under a failure status is how much of the
			// chunk that failed did get through (MS-SMB2 2.2.32.2).
			d.respondWithStatus(rw, hdr, sess, statusFromErr(err), smb2.EncodeIoctlResponse(smb2.IoctlResponse{
				CtlCode:      req.CtlCode,
				FileID:       req.FileID,
				OutputBuffer: smb2.EncodeSrvCopyChunkResponse(chunksWritten, uint32(n), totalWritten),
			}))
			return true
		}
		chunksWritten++
	}

	d.Log.Debug("copychunk complete",
		"src", source.Path, "dst", target.Path, "chunks", chunksWritten, "bytes", totalWritten)
	// ChunkBytesWritten is 0 on full success: it only carries a partial count
	// when the operation failed part-way through a chunk.
	d.respondSuccess(rw, hdr, sess, smb2.EncodeIoctlResponse(smb2.IoctlResponse{
		CtlCode:      req.CtlCode,
		FileID:       req.FileID,
		OutputBuffer: smb2.EncodeSrvCopyChunkResponse(chunksWritten, 0, totalWritten),
	}))
	return true
}

// maxFileOffset is the largest offset a POSIX pwrite/pread can address. Wire
// offsets are uint64; anything at or above this cannot be converted to the
// int64 the syscalls take without wrapping negative.
const maxFileOffset uint64 = 1<<63 - 1

// validateCopyChunks checks every chunk against the server's limits and the
// source file's size. It returns the status to fail with and false on the first
// problem; STATUS_INVALID_PARAMETER means "and send the limits body".
//
// The two kinds of check run as separate passes, in the order MS-SMB2
// §3.3.5.15.6 gives them: the whole request is measured against the server's
// ceilings first, and only a request that fits is checked chunk by chunk
// against the source file. The order is what the client sees — "too big, retry
// smaller" has to win over "that range does not exist", because a request that
// is over the limit will be resent in a different shape anyway.
func validateCopyChunks(chunks []smb2.SrvCopyChunk, srcSize uint64) (smb2.Status, bool) {
	var total uint64
	for _, ch := range chunks {
		// A zero-length chunk is meaningless and a chunk above the ceiling is
		// the case the limits response exists for.
		if ch.Length == 0 || ch.Length > maxCopyChunkSize {
			return smb2.StatusInvalidParameter, false
		}
		total += uint64(ch.Length)
		if total > uint64(maxCopyChunkTotal) {
			return smb2.StatusInvalidParameter, false
		}
	}
	for _, ch := range chunks {
		// Offsets arrive as uint64 and end up as int64 file offsets; reject
		// anything that would wrap rather than seeking to a negative offset.
		if ch.SourceOffset > maxFileOffset || ch.TargetOffset > maxFileOffset {
			return smb2.StatusInvalidParameter, false
		}
		srcEnd := ch.SourceOffset + uint64(ch.Length)
		if srcEnd > maxFileOffset || ch.TargetOffset+uint64(ch.Length) > maxFileOffset {
			return smb2.StatusInvalidParameter, false
		}
		// MS-SMB2 §3.3.5.15.6: a source range running past the end of the
		// source file is STATUS_INVALID_VIEW_SIZE, not INVALID_PARAMETER —
		// the client must not read it as a chunk-size hint and retry.
		if srcEnd > srcSize {
			return smb2.StatusInvalidViewSize, false
		}
	}
	return smb2.StatusSuccess, true
}

// sameUnderlyingFile reports whether two descriptors name the same inode.
func sameUnderlyingFile(a, b *os.File) bool {
	ai, err := a.Stat()
	if err != nil {
		return false
	}
	bi, err := b.Stat()
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// chunksOverlap reports whether any chunk's source range intersects its own
// target range. Only meaningful once the two handles are known to be the same
// file.
func chunksOverlap(chunks []smb2.SrvCopyChunk) bool {
	for _, ch := range chunks {
		n := uint64(ch.Length)
		if ch.SourceOffset < ch.TargetOffset+n && ch.TargetOffset < ch.SourceOffset+n {
			return true
		}
	}
	return false
}

// --- the copy itself ---

// errCopyRangeUnsupported signals that the in-kernel copy is unavailable for
// this pair of descriptors (no such syscall, different filesystems, a kernel
// that refuses the combination) and the portable read/write loop should finish
// the job. It is never returned to the client.
var errCopyRangeUnsupported = errors.New("parent: in-kernel copy range unavailable")

// copyBufSize bounds the staging buffer of the portable fallback. Chunks are at
// most maxCopyChunkSize, but a fixed, poolable buffer keeps the per-request
// allocation flat regardless of how many chunks arrive.
const copyBufSize = 256 << 10

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufSize)
		return &b
	},
}

// copyRange copies length bytes from src at srcOff to dst at dstOff, returning
// how many bytes reached dst.
//
// It tries the in-kernel copy first (copy_file_range on linux, where the bytes
// never enter this process at all) and finishes whatever that leaves — all of
// it, on platforms that have no such syscall, darwin included — with a pread/
// pwrite loop. Neither path moves either descriptor's file position, so a copy
// does not disturb a concurrent sequential READ or WRITE on the same handle.
func copyRange(dst, src *os.File, srcOff, dstOff, length int64) (int64, error) {
	var done int64
	for done < length {
		n, err := copyFileRange(dst, src, srcOff+done, dstOff+done, length-done)
		if err != nil {
			if errors.Is(err, errCopyRangeUnsupported) {
				break
			}
			return done, err
		}
		if n == 0 {
			// Kernel reported EOF on the source. The fallback below turns a
			// genuinely short source into a proper error.
			break
		}
		done += n
	}
	if done >= length {
		return done, nil
	}

	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	buf := *bufp
	for done < length {
		want := length - done
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		n, rerr := src.ReadAt(buf[:want], srcOff+done)
		if n > 0 {
			w, werr := dst.WriteAt(buf[:n], dstOff+done)
			done += int64(w)
			if werr != nil {
				return done, werr
			}
			if w != n {
				return done, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				// The source shrank between validation and the read.
				return done, io.ErrUnexpectedEOF
			}
			return done, rerr
		}
	}
	return done, nil
}
