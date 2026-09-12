//go:build linux

package parent

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// copyFileRange asks the kernel to move bytes straight from one descriptor to
// another. On a filesystem that can reflink (btrfs, XFS with reflinks, NFSv4.2
// server-side copy) this costs no data movement at all; everywhere else it
// still saves two copies through userspace. Both offsets are passed explicitly,
// so neither file's position moves.
//
// The kernel refuses the fast path for plenty of ordinary reasons — a kernel
// older than 4.5, the two files on different filesystems (before 5.3), an
// overlayfs or FUSE mount that does not implement it. All of those come back as
// errCopyRangeUnsupported so the caller quietly finishes with the portable
// read/write loop; only a genuine I/O failure is reported as one.
func copyFileRange(dst, src *os.File, srcOff, dstOff, length int64) (int64, error) {
	if length <= 0 {
		return 0, nil
	}
	// copy_file_range takes an int length; cap rather than truncate-and-wrap on
	// a 32-bit build. The caller loops, so a capped call is not a short copy.
	const maxInt = int64(^uint(0) >> 1)
	if length > maxInt {
		length = maxInt
	}
	so, to := srcOff, dstOff
	n, err := unix.CopyFileRange(int(src.Fd()), &so, int(dst.Fd()), &to, int(length), 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS), // kernel < 4.5
			errors.Is(err, unix.EXDEV),      // cross-filesystem, kernel < 5.3
			errors.Is(err, unix.EINVAL),     // overlapping ranges in one file, or a refused combination
			errors.Is(err, unix.EOPNOTSUPP), // filesystem has no ->copy_file_range
			errors.Is(err, unix.EPERM),      // append-only or immutable target
			errors.Is(err, unix.ETXTBSY),    // one side is a running binary
			errors.Is(err, unix.EBADF),      // a descriptor without the needed mode
			errors.Is(err, unix.EINTR):
			return 0, errCopyRangeUnsupported
		}
		return 0, err
	}
	return int64(n), nil
}
