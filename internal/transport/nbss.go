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
func WriteFrame(w io.Writer, payload []byte) error {
	if uint64(len(payload)) > 0xFFFFFF {
		return fmt.Errorf("%w: %d > 16777215", ErrFrameTooLarge, len(payload))
	}
	out := make([]byte, 4+len(payload))
	out[0] = frameTypeSessionMessage
	out[1] = byte(len(payload) >> 16)
	out[2] = byte(len(payload) >> 8)
	out[3] = byte(len(payload))
	copy(out[4:], payload)
	_, err := w.Write(out)
	return err
}
