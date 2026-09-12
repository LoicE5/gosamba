package smb2

import (
	"encoding/binary"
	"fmt"
)

type ReadRequest struct {
	Length       uint32
	Offset       uint64
	FileID       [16]byte
	MinimumCount uint32
}

// DecodeReadRequest parses a READ request body.
//
// Body offset 40 holds RemainingBytes — macOS sets it on every READ to the
// rest of the UBC I/O it is working through, up to 16 MiB (smb_smb_2.c
// ~8783) — and it is deliberately not parsed. The obvious use is to feed it to
// posix_fadvise(POSIX_FADV_WILLNEED) on Linux, or fcntl(F_RDADVISE) on darwin,
// so the kernel prefetches the rest of the transfer. Measured on darwin, that
// extra fcntl costs ~400ns and takes a 4 KiB pread from 345ns to 882ns, while
// the whole 4 KiB READ handler now runs in ~890ns — so the hint would add
// close to half again to every small read. Against a page-cache-resident file
// it bought nothing measurable in return, and the kernel's own sequential
// readahead already covers the case the hint is aimed at. It is left out
// rather than paying a syscall per READ on the strength of a theory.
func DecodeReadRequest(body []byte) (ReadRequest, error) {
	if len(body) < 48 {
		return ReadRequest{}, fmt.Errorf("%w: READ body min 48", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 49 {
		return ReadRequest{}, fmt.Errorf("%w: READ StructureSize %d", ErrBadStructureSize, ss)
	}
	r := ReadRequest{
		Length:       binary.LittleEndian.Uint32(body[4:]),
		Offset:       binary.LittleEndian.Uint64(body[8:]),
		MinimumCount: binary.LittleEndian.Uint32(body[32:]),
	}
	copy(r.FileID[:], body[16:32])
	return r, nil
}

type ReadResponse struct {
	Data []byte
}

// EncodeReadResponse builds the body. DataOffset = 80 (header 64 + body fixed 16).
func EncodeReadResponse(r ReadResponse) []byte {
	const fixed = 16
	out := make([]byte, fixed+len(r.Data))
	binary.LittleEndian.PutUint16(out[0:], 17) // StructureSize
	const headerSize = 64
	out[2] = byte(headerSize + fixed) // DataOffset (1 byte) — abs from header start
	binary.LittleEndian.PutUint32(out[4:], uint32(len(r.Data)))
	copy(out[fixed:], r.Data)
	return out
}
