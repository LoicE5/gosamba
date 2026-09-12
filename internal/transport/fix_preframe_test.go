package transport

import (
	"bytes"
	"errors"
	"testing"
)

// TestWritePreframed_MatchesWriteFrame is the guarantee the READ fast path
// rests on: a buffer whose first FrameHeaderSize bytes are reserved produces
// exactly the frame WriteFrame would have produced for the same payload.
func TestWritePreframed_MatchesWriteFrame(t *testing.T) {
	for _, n := range []int{0, 1, 4, 63, 64, 1024, 70000, 1 << 20} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i*31 + 7)
		}

		var want bytes.Buffer
		if err := WriteFrame(&want, payload); err != nil {
			t.Fatalf("WriteFrame(%d): %v", n, err)
		}

		buf := make([]byte, FrameHeaderSize+n)
		copy(buf[FrameHeaderSize:], payload)
		var got bytes.Buffer
		if err := WritePreframed(&got, buf); err != nil {
			t.Fatalf("WritePreframed(%d): %v", n, err)
		}

		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("payload %d: WritePreframed frame differs from WriteFrame", n)
		}
	}
}

// TestWritePreframed_SingleWrite pins the one-Write property WriteFrame exists
// for (two small writes per response interact badly with delayed ACK).
func TestWritePreframed_SingleWrite(t *testing.T) {
	var w countingWriter
	buf := make([]byte, FrameHeaderSize+100)
	if err := WritePreframed(&w, buf); err != nil {
		t.Fatal(err)
	}
	if w.calls != 1 {
		t.Errorf("WritePreframed made %d Write calls, want 1", w.calls)
	}
	if w.bytes != FrameHeaderSize+100 {
		t.Errorf("wrote %d bytes, want %d", w.bytes, FrameHeaderSize+100)
	}
}

// TestWritePreframed_RoundTrip proves ReadFrame reads back what was written.
func TestWritePreframed_RoundTrip(t *testing.T) {
	payload := []byte("hello pre-framed world")
	buf := make([]byte, FrameHeaderSize+len(payload))
	copy(buf[FrameHeaderSize:], payload)

	var wire bytes.Buffer
	if err := WritePreframed(&wire, buf); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&wire, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip = %q, want %q", got, payload)
	}
}

// TestWritePreframed_ShortBuffer: a buffer with no room for the header is an
// error, not a slice panic.
func TestWritePreframed_ShortBuffer(t *testing.T) {
	for _, n := range []int{0, 1, FrameHeaderSize - 1} {
		var w bytes.Buffer
		if err := WritePreframed(&w, make([]byte, n)); err == nil {
			t.Errorf("WritePreframed with %d-byte buffer returned nil error", n)
		}
		if w.Len() != 0 {
			t.Errorf("WritePreframed with %d-byte buffer still wrote %d bytes", n, w.Len())
		}
	}
}

// TestWritePreframed_TooLarge: payloads past the 24-bit NBSS length are
// refused the same way WriteFrame refuses them.
func TestWritePreframed_TooLarge(t *testing.T) {
	var w bytes.Buffer
	buf := make([]byte, FrameHeaderSize+0x1000000)
	if err := WritePreframed(&w, buf); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("err = %v, want ErrFrameTooLarge", err)
	}
	if w.Len() != 0 {
		t.Errorf("oversized frame still wrote %d bytes", w.Len())
	}
}

type countingWriter struct {
	calls int
	bytes int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.calls++
	c.bytes += len(p)
	return len(p), nil
}
