package smb2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderSize is the size of the SMB2 sync header.
const HeaderSize = 64

// NextCommandOffset is where the NextCommand field sits inside the SMB2
// header. Assembling a compounded response rewrites that one field in an
// already-encoded header, so it needs the offset rather than a re-encode.
const NextCommandOffset = 20

const headerStructureSize = 64

// Flags is a bit-set carried in the SMB2 header Flags field.
type Flags uint32

const (
	FlagServerToRedir   Flags = 0x00000001
	FlagAsyncCommand    Flags = 0x00000002
	FlagRelatedOps      Flags = 0x00000004
	FlagSigned          Flags = 0x00000008
	FlagPriorityMask    Flags = 0x00000070
	FlagDFSOperations   Flags = 0x10000000
	FlagReplayOperation Flags = 0x20000000
)

var (
	ErrShortBuffer      = errors.New("smb2: buffer too short")
	ErrBadProtocolID    = errors.New("smb2: bad ProtocolId")
	ErrBadStructureSize = errors.New("smb2: bad header StructureSize")
	ErrInvalidParameter = errors.New("smb2: invalid parameter")
)

var protocolID = [4]byte{0xFE, 'S', 'M', 'B'}

// Header is the decoded SMB2 sync header.
type Header struct {
	CreditCharge   uint16
	Status         uint32
	Command        Command
	CreditResponse uint16
	Flags          Flags
	NextCommand    uint32
	MessageID      uint64
	TreeID         uint32
	SessionID      uint64
	Signature      [16]byte
}

func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("%w: header needs %d bytes, got %d", ErrShortBuffer, HeaderSize, len(b))
	}
	if b[0] != protocolID[0] || b[1] != protocolID[1] || b[2] != protocolID[2] || b[3] != protocolID[3] {
		return Header{}, fmt.Errorf("%w: %02x %02x %02x %02x", ErrBadProtocolID, b[0], b[1], b[2], b[3])
	}
	if ss := binary.LittleEndian.Uint16(b[4:]); ss != headerStructureSize {
		return Header{}, fmt.Errorf("%w: %d", ErrBadStructureSize, ss)
	}
	var h Header
	h.CreditCharge = binary.LittleEndian.Uint16(b[6:])
	h.Status = binary.LittleEndian.Uint32(b[8:])
	h.Command = Command(binary.LittleEndian.Uint16(b[12:]))
	h.CreditResponse = binary.LittleEndian.Uint16(b[14:])
	h.Flags = Flags(binary.LittleEndian.Uint32(b[16:]))
	h.NextCommand = binary.LittleEndian.Uint32(b[20:])
	h.MessageID = binary.LittleEndian.Uint64(b[24:])
	h.TreeID = binary.LittleEndian.Uint32(b[36:])
	h.SessionID = binary.LittleEndian.Uint64(b[40:])
	copy(h.Signature[:], b[48:64])
	return h, nil
}

// EncodeHeader writes h into out (which must be ≥ HeaderSize).
func EncodeHeader(out []byte, h Header) error {
	if len(out) < HeaderSize {
		return fmt.Errorf("%w: need %d, have %d", ErrShortBuffer, HeaderSize, len(out))
	}
	copy(out[:4], protocolID[:])
	binary.LittleEndian.PutUint16(out[4:], headerStructureSize)
	binary.LittleEndian.PutUint16(out[6:], h.CreditCharge)
	binary.LittleEndian.PutUint32(out[8:], h.Status)
	binary.LittleEndian.PutUint16(out[12:], uint16(h.Command))
	binary.LittleEndian.PutUint16(out[14:], h.CreditResponse)
	binary.LittleEndian.PutUint32(out[16:], uint32(h.Flags))
	binary.LittleEndian.PutUint32(out[20:], h.NextCommand)
	binary.LittleEndian.PutUint64(out[24:], h.MessageID)
	binary.LittleEndian.PutUint32(out[32:], 0)
	binary.LittleEndian.PutUint32(out[36:], h.TreeID)
	binary.LittleEndian.PutUint64(out[40:], h.SessionID)
	copy(out[48:64], h.Signature[:])
	return nil
}

// EncodeAsyncHeader writes an SMB2 ASYNC header. AsyncId occupies bytes 32-39
// (replacing Reserved+TreeID). FlagAsyncCommand is forced on.
func EncodeAsyncHeader(out []byte, h Header, asyncID uint64) error {
	if len(out) < HeaderSize {
		return fmt.Errorf("%w: need %d, have %d", ErrShortBuffer, HeaderSize, len(out))
	}
	copy(out[:4], protocolID[:])
	binary.LittleEndian.PutUint16(out[4:], headerStructureSize)
	binary.LittleEndian.PutUint16(out[6:], h.CreditCharge)
	binary.LittleEndian.PutUint32(out[8:], h.Status)
	binary.LittleEndian.PutUint16(out[12:], uint16(h.Command))
	binary.LittleEndian.PutUint16(out[14:], h.CreditResponse)
	binary.LittleEndian.PutUint32(out[16:], uint32(h.Flags|FlagAsyncCommand))
	binary.LittleEndian.PutUint32(out[20:], h.NextCommand)
	binary.LittleEndian.PutUint64(out[24:], h.MessageID)
	binary.LittleEndian.PutUint64(out[32:], asyncID)
	binary.LittleEndian.PutUint64(out[40:], h.SessionID)
	copy(out[48:64], h.Signature[:])
	return nil
}
