// Package smb2 implements the SMB2/3 wire protocol. It is a pure-byte layer:
// no I/O, no goroutines, no logging.
package smb2

// Status is an NTSTATUS code as carried in the SMB2 header Status field.
type Status uint32

const (
	StatusSuccess             Status = 0x00000000
	StatusPending             Status = 0x00000103
	StatusInvalidParameter    Status = 0xC000000D
	StatusAccessDenied        Status = 0xC0000022
	StatusObjectNameNotFound  Status = 0xC0000034
	StatusObjectNameCollision Status = 0xC0000035
	StatusFileIsADirectory    Status = 0xC00000BA
	StatusNotADirectory       Status = 0xC0000103
	StatusNotSupported        Status = 0xC00000BB
	StatusInternalError       Status = 0xC00000E5
	StatusUserSessionDeleted  Status = 0xC0000203
	StatusLogonFailure        Status = 0xC000006D
	StatusMoreProcessingReq   Status = 0xC0000016
	StatusNoSuchFile          Status = 0xC000000F
	StatusNoMoreFiles         Status = 0x80000006
	StatusPipeNotAvailable    Status = 0xC00000AC
	StatusBadNetworkName      Status = 0xC00000CC
	StatusEndOfFile           Status = 0xC0000011
	StatusPipeBroken          Status = 0xC000014B
	StatusCancelled           Status = 0xC0000120
	StatusNotifyEnumDir       Status = 0x0000010C
	StatusNotifyCleanup       Status = 0x0000010B
	StatusFsDriverRequired    Status = 0xC000019C
	StatusNetworkNameDeleted  Status = 0xC00000C9
	StatusBufferOverflow      Status = 0x80000005
	StatusLockNotGranted      Status = 0xC0000055
	StatusFileLockConflict    Status = 0xC0000054
	// StatusSharingViolation is the mandated answer when a CREATE's
	// DesiredAccess/ShareAccess pair cannot coexist with an existing open of
	// the same file (MS-SMB2 §3.3.5.9). It is the ONLY signal a client gets
	// that a deny mode was refused: macOS maps it to EBUSY, which is what
	// O_EXLOCK/O_SHLOCK callers test for.
	StatusSharingViolation Status = 0xC0000043
	StatusDiskFull         Status = 0xC000007F
	// StatusInsufficientResources is what a server returns when it refuses to
	// allocate more per-session state (handles, trees) for a client.
	StatusInsufficientResources Status = 0xC000009A

	// The block below exists so statusFromErr can report the *actual* POSIX
	// failure instead of collapsing everything to STATUS_INTERNAL_ERROR.
	// Clients branch on these: a full disk must not look like a server bug or
	// the client retries forever, and rclone/Finder surface the text verbatim.
	// The errno→NTSTATUS choices follow Samba's unix_dos_nt_errmap
	// (source3/lib/errmap_unix.c), the de-facto reference for a POSIX-backed
	// SMB server.
	StatusObjectPathNotFound Status = 0xC000003A // ELOOP
	StatusObjectNameInvalid  Status = 0xC0000033 // ENAMETOOLONG
	StatusDirectoryNotEmpty  Status = 0xC0000101 // ENOTEMPTY
	StatusTooManyOpenedFiles Status = 0xC000011F // EMFILE / ENFILE
	StatusNotSameDevice      Status = 0xC00000D4 // EXDEV
	StatusIODeviceError      Status = 0xC0000185 // EIO
	StatusInvalidHandle      Status = 0xC0000008 // EBADF
	StatusTooManyLinks       Status = 0xC0000265 // EMLINK

	// StatusInvalidInfoClass is the mandated reply for an information class the
	// server does not implement (MS-SMB2 §3.3.5.18 / MS-FSCC §2.4). Emitting a
	// differently-shaped record instead makes the client parse garbage.
	StatusInvalidInfoClass Status = 0xC0000003
	// StatusInfoLengthMismatch is the mandated reply when the client's
	// OutputBufferLength cannot hold even a single directory entry
	// (MS-SMB2 §3.3.5.18). Answering STATUS_NO_MORE_FILES instead silently
	// truncates the listing.
	StatusInfoLengthMismatch Status = 0xC0000004

	// StatusInvalidOplockProtocol is one of the three statuses MS-SMB2
	// §3.3.5.22 lists for an SMB2 OPLOCK_BREAK the server cannot honour
	// (alongside STATUS_INVALID_PARAMETER and STATUS_FILE_CLOSED). It is the
	// right answer for a break acknowledgement that matches no oplock or lease
	// the server ever granted. STATUS_NOT_SUPPORTED is not in that list, and
	// Windows/Samba clients branch on the listed codes.
	StatusInvalidOplockProtocol Status = 0xC00000E3

	// StatusInvalidViewSize is what MS-SMB2 §3.3.5.15.6 mandates for a
	// server-side copy whose chunk names a source range running past the end of
	// the source file. It is deliberately not STATUS_INVALID_PARAMETER: that
	// status carries the "here are my chunk limits, retry smaller" meaning, and a
	// client that reads an out-of-range refusal as a limit hint retries forever.
	StatusInvalidViewSize Status = 0xC000001F
)
