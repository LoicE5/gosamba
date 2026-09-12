package parent

import (
	"bytes"
	"encoding/binary"

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
func buildAAPLResponse(reqData []byte) ([]byte, bool) {
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
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], aaplVolCaseSensitive|aaplVolFullSync)
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
func buildCreateResponseContexts(raw []byte, conn *Connection, maxAccess uint32, diskFileID, volumeID uint64) []byte {
	if len(raw) == 0 {
		return nil
	}
	var out []smb2.CreateContext
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		switch {
		case bytes.Equal(c.Name, aaplTag):
			r, readDirAttr := buildAAPLResponse(c.Data)
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
