package parent

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// AAPL create-context tag and command codes (libcli/smb/smb2_create_ctx.h).
var aaplTag = []byte("AAPL")

// mxAcTag is the SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST create-context name.
// Clients (notably iOS Files) read a share's writability from the MxAc
// *response* context's MaximalAccess field rather than the TREE_CONNECT
// MaximalAccess; omitting it makes iOS mount the share read-only.
var mxAcTag = []byte("MxAc")

// qFidTag is the SMB2_CREATE_QUERY_ON_DISK_ID create-context name ("QFid",
// 0x51466964 read big-endian). macOS attaches it to every CREATE that actually
// creates something and stores the returned DiskFileId as the vnode's inode.
// Dropping the context — or answering it with a zero DiskFileId — makes the
// client permanently clear FILE_IDS_SUPPORTED for the whole session and fall
// back to synthesising inode numbers from a hash of the file name.
var qFidTag = []byte("QFid")

// rforkStreamName is the NTFS stream name macOS/SMB uses for a file's resource
// fork. We persist it like any other ADS stream (user.gosamba.ads.AFP_AfpResource)
// and report its size as rfork_size in AAPL directory overlays.
const rforkStreamName = "AFP_AfpResource"

const (
	aaplCmdServerQuery = 1

	aaplBitServerCaps = 1
	aaplBitVolumeCaps = 2
	aaplBitModelInfo  = 4

	// Server-capability bits (SMB2_CRTCTX_AAPL_*).
	aaplCapReadDirAttr = 1
	aaplCapUnixBased   = 4

	// Volume-capability bits (AAPL_VOLUME_CAPS reply).
	//
	// CASE_SENSITIVE is asserted ONLY when the share's backing filesystem
	// really distinguishes names that differ in case — see shareCaseSensitive.
	// The claim is not cosmetic: once AAPL negotiation marks us an OS X server,
	// SMBClient's smbfs_check_name (smbfs_node.c) switches its name-cache
	// comparison to bcmp when this bit is set and to strncasecmp when it is
	// not, and smbfs_vfsops.c maps the bit onto VOL_CAP_FMT_CASE_SENSITIVE for
	// applications. Claiming it on a case-INSENSITIVE volume (the APFS/HFS+
	// default) makes the client hash `Foo` and `foo` to two distinct vnodes
	// that alias one inode — two page caches for one file, so a write through
	// one is lost when the other flushes.
	aaplVolCaseSensitive = 2
	// FULL_SYNC asserts the server honors F_FULLFSYNC semantics. We answer
	// FLUSH with file.Sync() which is the strongest durability POSIX exposes
	// on Linux ext4/xfs, so the claim is honest. (We do NOT advertise
	// SUPPORT_RESOLVE_ID — pairing that bit with our decline-by-default
	// RESOLVE_ID handler made iPad and macOS Finder break the mount on first
	// CREATE; revisit only with a real inverse-lookup implementation.)
	aaplVolFullSync = 4
)

// buildAAPLResponse, given the AAPL request blob (24 bytes per Apple spec),
// returns the response blob and a flag indicating whether READ_DIR_ATTR was
// negotiated. Returns (nil, false) if the request isn't a SERVER_QUERY we
// can answer.
//
// caseSensitive is the share's real, probed case sensitivity; it must be the
// same value encodeFsInfo puts in FILE_CASE_SENSITIVE_SEARCH, or a client that
// reads one and not the other gets two different answers about one volume.
func buildAAPLResponse(reqData []byte, caseSensitive bool) ([]byte, bool) {
	if len(reqData) < 24 {
		return nil, false
	}
	cmd := binary.LittleEndian.Uint32(reqData[0:])
	if cmd != aaplCmdServerQuery {
		return nil, false
	}
	reqBitmap := binary.LittleEndian.Uint64(reqData[8:])
	clientCaps := binary.LittleEndian.Uint64(reqData[16:])

	var resp bytes.Buffer
	// Echo command + 4 reserved bytes + reqBitmap.
	var tmp [16]byte
	binary.LittleEndian.PutUint32(tmp[0:], aaplCmdServerQuery)
	binary.LittleEndian.PutUint32(tmp[4:], 0)
	binary.LittleEndian.PutUint64(tmp[8:], reqBitmap)
	resp.Write(tmp[:16])

	readDirAttr := false
	if reqBitmap&aaplBitServerCaps != 0 {
		// Always advertise UNIX_BASED. Echo READ_DIR_ATTR back when the client
		// also supports it: Finder then trusts the level-37 dir responses to
		// carry FinderInfo/rfork/mode inline and skips its per-entry
		// CREATE/QUERY_INFO/CLOSE storm. We DO NOT advertise SUPPORTS_OSX_COPYFILE
		// (no copy-chunk FSCTL handler) or SUPPORTS_NFS_ACE (no NFS ACL store).
		serverCaps := uint64(aaplCapUnixBased)
		if clientCaps&aaplCapReadDirAttr != 0 {
			serverCaps |= aaplCapReadDirAttr
			readDirAttr = true
		}
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], serverCaps)
		resp.Write(b[:])
	}
	if reqBitmap&aaplBitVolumeCaps != 0 {
		volCaps := uint64(aaplVolFullSync)
		if caseSensitive {
			volCaps |= aaplVolCaseSensitive
		}
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], volCaps)
		resp.Write(b[:])
	}
	if reqBitmap&aaplBitModelInfo != 0 {
		// pad(4) + len(4) + UTF-16LE model with no NUL.
		model := utf16leName("MacSamba1,1")
		var hdr [8]byte
		binary.LittleEndian.PutUint32(hdr[0:], 0)
		binary.LittleEndian.PutUint32(hdr[4:], uint32(len(model)))
		resp.Write(hdr[:])
		resp.Write(model)
	}
	return resp.Bytes(), readDirAttr
}

// buildCreateResponseContexts inspects the requested create contexts and
// returns the contexts we want to ship back: AAPL response (when negotiated),
// MxAc, and QFid where applicable. Only contexts the client actually asked for
// are ever emitted: macOS treats an unsolicited/unknown response context name
// as EBADRPC and fails the CREATE. Other contexts (RqLs lease, DHnQ/DH2Q
// durable) are intentionally NOT echoed — that's how the server signals
// "feature declined" to the client without erroring out.
//
// When AAPL with READ_DIR_ATTR is negotiated, this latches conn.AAPLReadDirAttr
// so subsequent QUERY_DIRECTORY calls on this connection emit the Apple block.
func buildCreateResponseContexts(raw []byte, conn *Connection, tree *Tree, maxAccess uint32, diskFileID, volumeID uint64) []byte {
	if len(raw) == 0 {
		return nil
	}
	var out []smb2.CreateContext
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		switch {
		case bytes.Equal(c.Name, aaplTag):
			// shareCaseSensitive is consulted here rather than up front so a
			// client that never sends an AAPL context never triggers the probe.
			r, readDirAttr := buildAAPLResponse(c.Data, shareCaseSensitive(tree))
			if r != nil {
				out = append(out, smb2.CreateContext{Name: aaplTag, Data: r})
				if readDirAttr && conn != nil {
					conn.AAPLReadDirAttr = true
				}
			}
		case bytes.Equal(c.Name, mxAcTag):
			// SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE (MS-SMB2 §2.2.14.2.5):
			// QueryStatus(4, 0=STATUS_SUCCESS) + MaximalAccess(4). Report the
			// access the share actually grants so clients (iOS Files) treat a
			// read-write share as writable instead of defaulting to read-only.
			var d [8]byte
			binary.LittleEndian.PutUint32(d[0:], 0)
			binary.LittleEndian.PutUint32(d[4:], maxAccess)
			out = append(out, smb2.CreateContext{Name: mxAcTag, Data: d[:]})
		case bytes.Equal(c.Name, qFidTag):
			// SMB2_CREATE_QUERY_ON_DISK_ID response (MS-SMB2 2.2.14.2.9):
			// DiskFileId(8) + VolumeId(8) + 16 reserved zero bytes, which must
			// total EXACTLY 32 — macOS fails the whole CREATE with EBADRPC on
			// any other DataLength, and that failure is not retried.
			//
			// Skip the context entirely when we have no real inode (named
			// streams, pipes, a failed stat). Answering with a zero DiskFileId
			// is what makes the client give up on file IDs for the session;
			// staying silent just leaves it using the handle-derived id.
			if diskFileID == 0 {
				break
			}
			var q [32]byte
			binary.LittleEndian.PutUint64(q[0:], diskFileID)
			binary.LittleEndian.PutUint64(q[8:], volumeID)
			out = append(out, smb2.CreateContext{Name: qFidTag, Data: q[:]})
		}
		return true
	})
	return smb2.EncodeCreateContexts(out)
}

// --- backing-filesystem case sensitivity -------------------------------------
//
// Two places on the wire tell a client whether this volume distinguishes `Foo`
// from `foo`: the AAPL volume-capability bit (aaplVolCaseSensitive) and
// FILE_CASE_SENSITIVE_SEARCH in FileFsAttributeInformation. Both must report
// what the backing filesystem actually does, and both must report the SAME
// thing — a client that reads one and not the other must not end up with a
// contradiction. They therefore both go through shareCaseSensitive, which
// probes each share's root exactly once and caches the answer.
//
// The same probe also has to reach the two places that ACT on case, or the
// server contradicts itself in a way no bit on the wire can fix: the SMB
// pattern matcher that answers a lookup (matchSMBPattern, driven by
// shareCaseSensitive) and the path resolver that answers the open that follows
// it (vfs.ResolveSecureNorm, driven by shareFoldsCase). Those two used to
// disagree — the matcher folded case unconditionally, the resolver never did —
// so on a case-sensitive share a lookup for `foo` found `Foo`, the client was
// told the file existed, and the CREATE behind it answered STATUS_NO_SUCH_FILE
// into the client's negative name cache.

const (
	// fileCaseSensitiveSearch is FILE_CASE_SENSITIVE_SEARCH (MS-FSCC 2.5.1).
	fileCaseSensitiveSearch uint32 = 0x00000001
	// fsAttrsBase is every FileFsAttributeInformation bit we claim
	// unconditionally: CASE_PRESERVED_NAMES | UNICODE_ON_DISK |
	// PERSISTENT_ACLS | SUPPORTS_SPARSE_FILES | NAMED_STREAMS |
	// SUPPORTS_EXTENDED_ATTRIBUTES. FILE_CASE_SENSITIVE_SEARCH is deliberately
	// absent: fsAttributes adds it only for a share that earns it.
	fsAttrsBase uint32 = 0x0084004E
)

// fsAttributes returns the FileSystemAttributes mask to report for a share.
func fsAttributes(tree *Tree) uint32 {
	attrs := fsAttrsBase
	if shareCaseSensitive(tree) {
		attrs |= fileCaseSensitiveSearch
	}
	return attrs
}

// caseSensitivityFallback is what we report for a share we could not probe.
//
// Case-INSENSITIVE is the conservative answer, because the two errors are not
// symmetric. Understating sensitivity makes SMBClient compare cached names with
// strncasecmp, so `Foo` and `foo` collapse onto one vnode: at worst two names
// that the server does distinguish share a cache entry, and a lookup that
// misses re-reads from the server. Overstating it makes the client build two
// vnodes — two independent page caches — for one inode, and a write through one
// is silently lost when the other flushes. Losing data beats a redundant
// lookup, so an unprobed share is reported insensitive.
const caseSensitivityFallback = false

// caseProbePrefix names the temporary file the write probe creates. It is
// deliberately all-lowercase and carries letters in the constant part, so the
// uppercased spelling always differs from it even if the random suffix happens
// to be all digits.
const caseProbePrefix = ".gosamba-case-probe-"

// caseProbeScanLimit bounds how many root entries the read-only probe reads
// before giving up. One usable name is enough; a share root whose first 64
// entries contain no ASCII letter at all is not worth a full directory walk.
const caseProbeScanLimit = 64

// probeLstat is indirected so tests can make the probe fail *after* it has
// created its temporary file and assert that the cleanup still runs.
var probeLstat = os.Lstat

// probeCaseSensitivityFn is indirected so tests can count probes and prove one
// runs per share rather than per request.
var probeCaseSensitivityFn = probeCaseSensitivity

type caseProbe struct {
	once      sync.Once
	sensitive bool
	// measured records whether sensitive came from a probe that actually ran
	// or from caseSensitivityFallback. The wire does not care — both answers
	// look identical to a client — but the resolver does: see shareFoldsCase.
	measured bool
}

var (
	caseProbeMu sync.Mutex
	caseProbes  = map[string]*caseProbe{}
)

// shareCaseSensitive reports whether the share's backing filesystem really
// distinguishes names that differ only in case.
//
// The filesystem is probed once per share root, on first use, and the answer is
// cached for the life of the process: the sensitivity of a mounted filesystem
// cannot change under us, and a probe on every CREATE or QUERY_INFO would put
// filesystem writes on the hot path. A share we cannot probe falls back to
// caseSensitivityFallback; the probe never fails the share.
func shareCaseSensitive(tree *Tree) bool {
	// No tree, or IPC$ (which has no backing path): nothing to probe.
	if tree == nil || tree.Share.Path == "" {
		return caseSensitivityFallback
	}
	return shareCaseProbe(tree).sensitive
}

// shareFoldsCase reports whether the SERVER has to fold letter case itself when
// it resolves a name in this share. It is passed to vfs.ResolveSecureNorm as
// foldCase, and it is deliberately NOT the complement of shareCaseSensitive,
// because three states matter where the wire only has two:
//
//  1. Probed case-sensitive. `Foo` and `foo` are different files, the matcher
//     says so, and the resolver must not paper over it. No folding.
//
//  2. Probed case-insensitive. The filesystem folds case before we ever see
//     the name: the single Lstat vfs.ResolveNorm starts with already resolves
//     every spelling, and a miss there is conclusive. Folding again would find
//     nothing the kernel did not, and would cost a full directory read on every
//     new-file CREATE — the hottest path there is. No folding.
//
//  3. Not probed at all (an empty read-only share, an unreadable root). We
//     still report case-insensitive, because caseSensitivityFallback trades a
//     redundant client lookup for the risk of aliased page caches — but nothing
//     underneath is folding for us. This is the ONLY state where the server has
//     to do it, and the only one that pays a directory read for a name it
//     cannot otherwise find.
//
// Without the third state the matcher would keep telling a client that `foo`
// names the on-disk `Foo` on a share the resolver then refuses to open, which
// is precisely the negative-name-cache poisoning this pair of functions exists
// to prevent.
func shareFoldsCase(tree *Tree) bool {
	// IPC$ has no backing filesystem, so there is nothing to fold and nothing
	// this could ever be asked to resolve.
	if tree == nil || tree.Share.Path == "" {
		return false
	}
	p := shareCaseProbe(tree)
	return !p.sensitive && !p.measured
}

// shareCaseProbe returns the share root's probe entry, running the probe once
// if it has not run yet. tree must have a backing path.
func shareCaseProbe(tree *Tree) *caseProbe {
	root := filepath.Clean(tree.Share.Path)

	caseProbeMu.Lock()
	p := caseProbes[root]
	if p == nil {
		p = &caseProbe{}
		caseProbes[root] = p
	}
	caseProbeMu.Unlock()

	// The lock is released before the probe runs so a slow filesystem cannot
	// block lookups for other shares; once.Do still guarantees exactly one
	// probe per root, and every concurrent caller waits for that one.
	p.once.Do(func() {
		sensitive, err := probeCaseSensitivityFn(root, tree.Share.ReadOnly)
		if err != nil {
			slog.Default().Warn("case-sensitivity probe failed; reporting case-insensitive",
				"share", tree.Share.Name, "path", root, "read_only", tree.Share.ReadOnly, "err", err)
			p.sensitive = caseSensitivityFallback
			p.measured = false
			return
		}
		p.sensitive = sensitive
		p.measured = true
		slog.Default().Debug("case-sensitivity probed",
			"share", tree.Share.Name, "path", root, "case_sensitive", sensitive)
	})
	return p
}

// probeCaseSensitivity determines whether root's filesystem is case sensitive.
//
// A writable share is probed by creating a file, which is unambiguous: the name
// is fresh, so nothing but case folding can make the flipped spelling resolve.
// A read-only share cannot be probed that way, so it falls back to inspecting
// an entry that is already there. A writable share whose create fails (a
// read-only mount, a root we lack write permission on, a full filesystem) also
// falls back to the read-only probe rather than giving up.
func probeCaseSensitivity(root string, readOnly bool) (bool, error) {
	if readOnly {
		return probeCaseByExistingEntry(root)
	}
	sensitive, createErr := probeCaseByCreate(root)
	if createErr == nil {
		return sensitive, nil
	}
	sensitive, entryErr := probeCaseByExistingEntry(root)
	if entryErr == nil {
		return sensitive, nil
	}
	return false, fmt.Errorf("create probe: %v; existing-entry probe: %w", createErr, entryErr)
}

// probeCaseByCreate creates a uniquely named lowercase file in root and looks
// for it under the uppercased spelling. The file is removed on every exit path.
func probeCaseByCreate(root string) (bool, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return false, fmt.Errorf("probe name: %w", err)
	}
	lower := caseProbePrefix + hex.EncodeToString(suffix[:])
	upper := strings.ToUpper(lower)
	lowerPath := filepath.Join(root, lower)

	f, err := os.OpenFile(lowerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	// Registered immediately after the create, so every path out of this
	// function below — including a panic — takes the probe file with it.
	defer func() {
		f.Close()
		if rmErr := os.Remove(lowerPath); rmErr != nil && !os.IsNotExist(rmErr) {
			slog.Default().Warn("case-sensitivity probe file could not be removed",
				"path", lowerPath, "err", rmErr)
		}
	}()

	created, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("stat probe file: %w", err)
	}
	flipped, err := probeLstat(filepath.Join(root, upper))
	if err != nil {
		if os.IsNotExist(err) {
			// The name we just wrote does not answer to a different case.
			return true, nil
		}
		return false, fmt.Errorf("lstat flipped probe name: %w", err)
	}
	// The flipped spelling resolved. Same file means the filesystem folded the
	// case; a *different* file means two names differing only in case coexist
	// in one directory, which only a case-sensitive filesystem permits.
	return !os.SameFile(created, flipped), nil
}

// probeCaseByExistingEntry answers the same question without writing anything,
// by taking a name that is already in root and looking it up with its ASCII
// letters case-swapped. Used for read-only shares.
func probeCaseByExistingEntry(root string) (bool, error) {
	d, err := os.Open(root)
	if err != nil {
		return false, err
	}
	defer d.Close()
	names, err := d.Readdirnames(caseProbeScanLimit)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	for _, name := range names {
		flipped, ok := flipASCIICase(name)
		if !ok {
			// No ASCII letter: the "other case" is the same string, which
			// proves nothing.
			continue
		}
		orig, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			// Raced with a delete, or a dangling entry — try the next name.
			continue
		}
		other, err := probeLstat(filepath.Join(root, flipped))
		if err != nil {
			if os.IsNotExist(err) {
				return true, nil
			}
			continue
		}
		return !os.SameFile(orig, other), nil
	}
	return false, errors.New("no directory entry usable for a case-sensitivity probe")
}

// flipASCIICase swaps the case of every ASCII letter in s, leaving every other
// byte (including all of UTF-8's multi-byte sequences) untouched. ok is false
// when s has no ASCII letter, i.e. when the result would equal the input.
//
// Only ASCII is folded on purpose: non-ASCII case mapping is locale- and
// normalization-dependent (Turkish dotless i, ß/SS, the Kelvin sign), so a
// non-ASCII flip could differ from the one the filesystem performs and make a
// case-insensitive volume look sensitive.
func flipASCIICase(s string) (string, bool) {
	b := []byte(s)
	flipped := false
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c >= 'a' && c <= 'z':
			b[i] = c - 'a' + 'A'
			flipped = true
		case c >= 'A' && c <= 'Z':
			b[i] = c - 'A' + 'a'
			flipped = true
		}
	}
	if !flipped {
		return s, false
	}
	return string(b), true
}
