//go:build !linux

package parent

import "os"

// copyFileRange has no equivalent outside linux. darwin has copyfile(3) and
// fclonefileat(2), but both operate on whole files by path — neither can copy
// one byte range of an open descriptor into another at a chosen offset, which
// is exactly what an SRV_COPYCHUNK chunk is. So every platform but linux takes
// the portable pread/pwrite loop in copyRange, which is still a server-side
// copy: the bytes never leave the machine.
func copyFileRange(dst, src *os.File, srcOff, dstOff, length int64) (int64, error) {
	return 0, errCopyRangeUnsupported
}
