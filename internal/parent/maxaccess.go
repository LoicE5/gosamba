package parent

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// Access-mask bits (MS-DTYP §2.4.3, MS-SMB2 §2.2.13.1.1 / §2.2.13.1.2).
//
// The file and directory spellings of these rights are the SAME bit values —
// only their names change with the object type:
//
//	FILE_READ_DATA    == FILE_LIST_DIRECTORY
//	FILE_WRITE_DATA   == FILE_ADD_FILE
//	FILE_APPEND_DATA  == FILE_ADD_SUBDIRECTORY
//	FILE_EXECUTE      == FILE_TRAVERSE
//
// which is why the narrowing below needs no separate directory branch: R_OK on
// a directory is exactly "may list it" and X_OK on a directory is exactly "may
// traverse it".
const (
	accFileReadData        uint32 = 0x00000001
	accFileWriteData       uint32 = 0x00000002
	accFileAppendData      uint32 = 0x00000004
	accFileReadEA          uint32 = 0x00000008
	accFileWriteEA         uint32 = 0x00000010
	accFileExecute         uint32 = 0x00000020
	accFileDeleteChild     uint32 = 0x00000040
	accFileReadAttributes  uint32 = 0x00000080
	accFileWriteAttributes uint32 = 0x00000100
	accDelete              uint32 = 0x00010000
	accReadControl         uint32 = 0x00020000
	accWriteDAC            uint32 = 0x00040000
	accWriteOwner          uint32 = 0x00080000
	accSynchronize         uint32 = 0x00100000
)

// Share-wide ceilings. These are the masks the server used to report verbatim
// for every object on the share; they are now only the upper bound that the
// object's real POSIX permissions are subtracted from.
const (
	// accessFileAllAccess is FILE_ALL_ACCESS — the ceiling on a read-write share.
	accessFileAllAccess uint32 = 0x001F01FF
	// accessReadOnlyShare is FILE_GENERIC_READ|FILE_GENERIC_EXECUTE — the
	// ceiling on a read-only share. It carries no write bit at all, so a
	// read-only share can never report write access however permissive the
	// file's mode is.
	accessReadOnlyShare uint32 = 0x001200A9
)

// accessWriteBits are every right that implies mutating the object or its
// metadata. They are cleared as a group when the object is not writable.
//
// DELETE is included even though POSIX unlink(2) is governed by the PARENT
// directory's write bit rather than the file's: macOS gates KAUTH_VNODE_DELETE
// on SMB2_DELETE in the maximal-access mask, and reporting "deletable" for a
// file the user cannot modify is the over-reporting this change exists to stop.
// WRITE_DAC/WRITE_OWNER need ownership, which write permission is the closest
// cheap proxy for.
const accessWriteBits = accFileWriteData | accFileAppendData | accFileWriteEA |
	accFileWriteAttributes | accFileDeleteChild | accDelete |
	accWriteDAC | accWriteOwner

// shareAccessCeiling returns the widest access mask a share may ever report.
func shareAccessCeiling(readOnly bool) uint32 {
	if readOnly {
		return accessReadOnlyShare
	}
	return accessFileAllAccess
}

// narrowAccessMask subtracts from a share ceiling the rights the object's own
// POSIX permissions do not grant. It is pure so the bit arithmetic can be
// tested without touching a filesystem.
//
// READ_CONTROL, SYNCHRONIZE and FILE_READ_ATTRIBUTES are deliberately never
// cleared: stat-ing a handle and waiting on it do not need any POSIX
// permission on the object itself.
func narrowAccessMask(ceiling uint32, readable, writable, executable bool) uint32 {
	granted := ceiling
	if !writable {
		granted &^= accessWriteBits
	}
	if !executable {
		// On a file this is FILE_EXECUTE; on a directory it is FILE_TRAVERSE.
		granted &^= accFileExecute
	}
	if !readable {
		// On a directory this also drops FILE_LIST_DIRECTORY, which macOS
		// requires to enumerate — but a directory that fails R_OK cannot be
		// enumerated by the server either, so the report is accurate. A
		// readable directory keeps the bit and lists as before.
		granted &^= accFileReadData | accFileReadEA
	}
	return granted
}

// maximalAccess reports the access mask for path: the share ceiling narrowed to
// the POSIX permissions the object really grants.
//
// The identity tested is the one this PROCESS runs as, which is the identity
// every filesystem operation on this connection will actually use:
//
//   - with the per-user privilege-drop worker enabled, the worker re-execs and
//     permanently drops (real == effective == saved) to the authenticated
//     user's uid/gid before serving any request, so the process identity IS the
//     SMB user;
//   - without it (not root, or the feature off) every user's I/O runs as the
//     single server identity anyway.
//
// Either way "will a READ/WRITE this handle actually succeed?" is exactly
// "does the current process have that permission?", which is what
// faccessat(AT_EACCESS) answers — including ACLs, read-only mounts (EROFS) and
// immutable flags, none of which a hand-rolled st_mode/uid/gid comparison would
// see. Real and effective ids are always equal here (the drop sets all three),
// so AT_EACCESS and the plain real-id check agree.
//
// The one place this is permissive is a server still running as root: root
// passes W_OK on a mode 0444 file, and the mask says so. That is the truth —
// root's write really does succeed — and it is not the reported bug, which is a
// non-root server claiming write access it does not have.
func maximalAccess(path string, shareReadOnly bool) uint32 {
	ceiling := shareAccessCeiling(shareReadOnly)
	// Skip the W_OK probe entirely on a read-only share: the ceiling has no
	// write bit to clear, and the answer could only ever be discarded.
	writable := ceiling&accessWriteBits != 0 && pathPermits(path, unix.W_OK)
	return narrowAccessMask(ceiling,
		pathPermits(path, unix.R_OK),
		writable,
		pathPermits(path, unix.X_OK))
}

// pathPermits reports whether the current process may access path in the given
// mode (unix.R_OK / W_OK / X_OK).
//
// Only a definite "no" from the kernel clears a right. Any other failure
// (ENOENT from a racing unlink, ENOSYS/ENOTSUP on an exotic filesystem) is not
// a permission answer, so the right is left in place and behaviour falls back
// to the old share-wide mask rather than locking the client out.
func pathPermits(path string, mode uint32) bool {
	err := unix.Faccessat(unix.AT_FDCWD, path, mode, unix.AT_EACCESS)
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS) {
		return false
	}
	return true
}
