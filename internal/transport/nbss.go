// Package transport implements the NetBIOS Session Service framing
// (RFC 1002 §4.3.1) used to carry SMB over TCP. Only SESSION_MESSAGE (0x00)
// is supported.
package transport

import (
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize is the maximum SMB payload accepted in a single NBSS frame.
const MaxFrameSize = 16 * 1024 * 1024

const (
	frameTypeSessionMessage = 0x00

	// aeadTagHeadroom is the spare capacity ReadFrame leaves past the end of
	// every payload: exactly one AES-GCM/CCM tag. See ReadFrame.
	aeadTagHeadroom = 16
)

// FrameHeaderSize is the length of the NBSS header that precedes every payload
// on the wire: one type byte and a 24-bit big-endian length.
const FrameHeaderSize = 4

var (
	ErrUnsupportedFrameType = errors.New("nbss: unsupported frame type")
	ErrFrameTooLarge        = errors.New("nbss: frame too large")
)

// ReadFrame reads one NBSS SESSION_MESSAGE frame and returns its payload.
// Frames larger than maxSize return ErrFrameTooLarge before the payload is read.
func ReadFrame(r io.Reader, maxSize uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != frameTypeSessionMessage {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedFrameType, hdr[0])
	}
	length := uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3])
	if length > maxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, length, maxSize)
	}
	if length == 0 {
		return []byte{}, nil
	}
	// Spare capacity, not spare length: the frame is exactly `length` bytes and
	// the framing is unchanged. The 16 extra bytes of capacity exist so that an
	// SMB3 transform frame can have its 16-byte AEAD tag appended after the
	// ciphertext and be decrypted in place, instead of copying the whole body
	// into a new buffer just to make ciphertext||tag contiguous
	// (see smb3.DecryptTransform). Unencrypted frames simply never touch it.
	n := int(length)
	payload := make([]byte, n, n+aeadTagHeadroom)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// WriteFrame writes one NBSS SESSION_MESSAGE frame as a single Write call,
// avoiding two small TCP writes per response (which interact poorly with
// delayed-ACK on some clients).
//
// It copies payload into a freshly framed buffer. A caller that can reserve
// FrameHeaderSize bytes at the front of its own buffer should build the
// response there and use WritePreframed instead, which skips this copy.
func WriteFrame(w io.Writer, payload []byte) error {
	if uint64(len(payload)) > 0xFFFFFF {
		return fmt.Errorf("%w: %d > 16777215", ErrFrameTooLarge, len(payload))
	}
	out := make([]byte, FrameHeaderSize+len(payload))
	copy(out[FrameHeaderSize:], payload)
	return WritePreframed(w, out)
}

// WritePreframed writes buf as one NBSS SESSION_MESSAGE frame, where buf's
// first FrameHeaderSize bytes are reserved room for the header rather than
// payload: the caller built the SMB2 message into buf[FrameHeaderSize:] and
// left the front untouched. The header is filled in place and the whole slice
// goes out in the same single Write that WriteFrame performs.
//
// This exists for the READ response path, which allocates one buffer covering
// NBSS header + SMB2 header + READ body + file data and preads straight into
// the data region. Without it that buffer would be copied a second time here
// just to prepend four bytes — at a 512 KiB payload, a whole extra payload's
// worth of allocation and memmove per response.
//
// The payload length is taken from len(buf), so buf must be exactly the frame:
// slice it to length before calling.
func WritePreframed(w io.Writer, buf []byte) error {
	if err := PutFrameHeader(buf); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

// PutFrameHeader fills buf's first FrameHeaderSize bytes with the NBSS
// SESSION_MESSAGE header describing the payload that follows, leaving buf ready
// to go on the wire in a single write.
//
// It is WritePreframed without the write, for callers that hand the finished
// frame to the connection's writer goroutine instead of writing it inline.
func PutFrameHeader(buf []byte) error {
	if len(buf) < FrameHeaderSize {
		return fmt.Errorf("nbss: pre-framed buffer is %d bytes, need at least %d",
			len(buf), FrameHeaderSize)
	}
	n := len(buf) - FrameHeaderSize
	if uint64(n) > 0xFFFFFF {
		return fmt.Errorf("%w: %d > 16777215", ErrFrameTooLarge, n)
	}
	buf[0] = frameTypeSessionMessage
	buf[1] = byte(n >> 16)
	buf[2] = byte(n >> 8)
	buf[3] = byte(n)
	return nil
}
