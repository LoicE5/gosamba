package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadFrame_Happy(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	payload, err := ReadFrame(buf, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "hello" {
		t.Errorf("payload: %q", payload)
	}
}

func TestReadFrame_Empty(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x00})
	payload, err := ReadFrame(buf, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(payload))
	}
}

func TestReadFrame_BadType(t *testing.T) {
	buf := bytes.NewReader([]byte{0x85, 0x00, 0x00, 0x00})
	_, err := ReadFrame(buf, MaxFrameSize)
	if !errors.Is(err, ErrUnsupportedFrameType) {
		t.Errorf("expected ErrUnsupportedFrameType, got %v", err)
	}
}

func TestReadFrame_TooLarge(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x10, 0x00, 0x00})
	_, err := ReadFrame(buf, 1024)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrame_TruncatedHeader(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00})
	_, err := ReadFrame(buf, MaxFrameSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF/ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x05, 'h', 'i'})
	_, err := ReadFrame(buf, MaxFrameSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestWriteFrame_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("smb2 message goes here")
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestWriteFrame_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	huge := make([]byte, 1<<25)
	if err := WriteFrame(&buf, huge); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

// TestReadFrame_TagHeadroom pins the spare capacity smb3.DecryptTransform
// relies on to append an AEAD tag after the ciphertext and decrypt in place.
// The frame's *length* must still be exactly the advertised payload size —
// spare capacity must never leak into the bytes callers parse.
func TestReadFrame_TagHeadroom(t *testing.T) {
	for _, n := range []int{1, 5, 64, 4096, 70000} {
		hdr := []byte{0x00, byte(n >> 16), byte(n >> 8), byte(n)}
		raw := append(hdr, bytes.Repeat([]byte{0xAB}, n)...)
		payload, err := ReadFrame(bytes.NewReader(raw), MaxFrameSize)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(payload) != n {
			t.Errorf("n=%d: length %d", n, len(payload))
		}
		if cap(payload) < n+aeadTagHeadroom {
			t.Errorf("n=%d: capacity %d, want at least %d", n, cap(payload), n+aeadTagHeadroom)
		}
		if !bytes.Equal(payload, bytes.Repeat([]byte{0xAB}, n)) {
			t.Errorf("n=%d: payload corrupted", n)
		}
	}
}

// TestReadFrame_HeadroomUnchangedFraming is a guard on the one thing that must
// not have changed: a stream of back-to-back frames still decodes identically,
// so the extra capacity did not shift any read boundary.
func TestReadFrame_HeadroomUnchangedFraming(t *testing.T) {
	var buf bytes.Buffer
	want := [][]byte{[]byte("alpha"), {}, []byte("gamma frame"), bytes.Repeat([]byte{0x7F}, 9000)}
	for _, p := range want {
		if err := WriteFrame(&buf, p); err != nil {
			t.Fatal(err)
		}
	}
	for i, p := range want {
		got, err := ReadFrame(&buf, MaxFrameSize)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, p) {
			t.Errorf("frame %d mismatch", i)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes left unconsumed", buf.Len())
	}
}
