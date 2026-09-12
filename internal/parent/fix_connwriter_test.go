package parent

import (
	"bytes"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// stalledWriter models a peer that has stopped reading: the first Write blocks
// until the test releases it, exactly as a socket does under TCP backpressure.
type stalledWriter struct {
	entered chan struct{} // signalled once, when a Write is in progress
	release chan struct{}

	mu      sync.Mutex
	frames  [][]byte
	once    sync.Once
	errOnce atomic.Bool
}

func newStalledWriter() *stalledWriter {
	return &stalledWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *stalledWriter) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	if s.errOnce.Load() {
		return 0, io.ErrClosedPipe
	}
	s.mu.Lock()
	s.frames = append(s.frames, append([]byte(nil), p...))
	s.mu.Unlock()
	return len(p), nil
}

func (s *stalledWriter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.frames)
}

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// waitGoroutines waits for the goroutine count to come back down to at most
// want, so a leak check does not race a goroutine that is on its way out.
func waitGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.Gosched()
		got := runtime.NumGoroutine()
		if got <= want {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutine count settled at %d, want at most %d", got, want)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestConnWriter_StalledSocketDoesNotBlockProducers is the regression test for
// the defect itself: a response stuck on a socket that is not being drained
// must not hold up any other response.
//
// The old writeFrame took a connection-wide mutex and held it across the
// blocking socket write, so one CHANGE_NOTIFY completion meeting backpressure
// froze the entire dispatch loop for up to the two-minute write deadline —
// however many credits the client was holding.
func TestConnWriter_StalledSocketDoesNotBlockProducers(t *testing.T) {
	sw := newStalledWriter()
	cw := newConnWriter(sw, testLog(), nil)
	defer func() { close(sw.release); cw.Close() }()

	// Get one frame wedged inside the socket write.
	if err := cw.send(mkFrame(16)); err != nil {
		t.Fatalf("first send: %v", err)
	}
	select {
	case <-sw.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer goroutine never reached the socket write")
	}

	// Every other producer must get through while that write is wedged.
	const others = 64
	done := make(chan error, 1)
	go func() {
		for i := 0; i < others; i++ {
			if err := cw.send(mkFrame(16)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("producer blocked behind the stalled socket: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("producers are still blocked behind the stalled socket write")
	}
}

// TestConnWriter_SlowPeerDropsConnection proves the queue is bounded: a peer
// that stops reading eventually loses its connection instead of growing the
// server's memory without limit.
func TestConnWriter_SlowPeerDropsConnection(t *testing.T) {
	sw := newStalledWriter()
	var killed atomic.Bool
	cw := newConnWriter(sw, testLog(), func() { killed.Store(true) })
	defer func() { close(sw.release); cw.Close() }()

	// Frames big enough that the byte budget is what bites, and few enough
	// that the test does not allocate a gigabyte.
	const frameSize = 4 << 20
	var sent int
	var lastErr error
	for i := 0; i < writeQueueDepth+2; i++ {
		if err := cw.send(mkFrame(frameSize)); err != nil {
			lastErr = err
			break
		}
		sent++
	}
	if lastErr == nil {
		t.Fatalf("queue accepted %d x %d bytes without ever refusing", sent, frameSize)
	}
	if lastErr != errWriteQueueFull {
		t.Errorf("send returned %v, want errWriteQueueFull", lastErr)
	}
	if int64(sent)*frameSize > writeQueueBytes+frameSize {
		t.Errorf("queue grew to %d bytes, over the %d-byte budget", int64(sent)*frameSize, writeQueueBytes)
	}
	if !killed.Load() {
		t.Error("a peer that stopped reading did not have its connection dropped")
	}
	// And the writer refuses everything afterwards rather than panicking.
	if err := cw.send(mkFrame(16)); err == nil {
		t.Error("send succeeded after the connection was dropped")
	}
}

// TestConnWriter_SendRacingCloseNeverPanics hammers send from many goroutines
// while the writer shuts down. The queue channel is never closed — shutdown
// closes a separate channel that send selects on — so a send that loses the
// race must return an error, not panic on a closed channel.
func TestConnWriter_SendRacingCloseNeverPanics(t *testing.T) {
	for round := 0; round < 20; round++ {
		cw := newConnWriter(io.Discard, testLog(), nil)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 32; j++ {
					// Either outcome is fine; a panic is not.
					_ = cw.send(mkFrame(32))
				}
			}()
		}
		go cw.Close()
		wg.Wait()
		cw.Close() // idempotent
	}
}

// TestConnWriter_TeardownFlushesQueuedFrames proves that shutting the writer
// down delivers what is already queued rather than dropping it. The response
// that decides to end a connection is the last thing in that queue, and the
// client is owed it.
func TestConnWriter_TeardownFlushesQueuedFrames(t *testing.T) {
	var out bytes.Buffer
	cw := newConnWriter(&out, testLog(), nil)
	const n = 200
	for i := 0; i < n; i++ {
		if err := cw.send(mkFrame(24)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	cw.Close()

	got := 0
	r := bytes.NewReader(out.Bytes())
	for {
		if _, err := transport.ReadFrame(r, transport.MaxFrameSize); err != nil {
			break
		}
		got++
	}
	if got != n {
		t.Errorf("teardown delivered %d of %d queued frames", got, n)
	}
}

// TestConnWriter_TeardownWithQueuedFramesLeaksNothing tears writers down over
// and over with work still in flight and checks the goroutine count comes back.
func TestConnWriter_TeardownWithQueuedFramesLeaksNothing(t *testing.T) {
	base := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		cw := newConnWriter(io.Discard, testLog(), nil)
		for j := 0; j < 40; j++ {
			_ = cw.send(mkFrame(64))
		}
		cw.Close()
	}
	waitGoroutines(t, base+1)
}

// TestConnWriter_WriteErrorStopsWriter proves a broken socket stops the writer
// and drops the connection instead of spinning on a dead descriptor.
func TestConnWriter_WriteErrorStopsWriter(t *testing.T) {
	sw := newStalledWriter()
	sw.errOnce.Store(true)
	var killed atomic.Bool
	cw := newConnWriter(sw, testLog(), func() { killed.Store(true) })

	if err := cw.send(mkFrame(16)); err != nil {
		t.Fatalf("send: %v", err)
	}
	close(sw.release)

	deadline := time.Now().Add(2 * time.Second)
	for !killed.Load() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if !killed.Load() {
		t.Fatal("a failed write did not drop the connection")
	}
	cw.Close()
	if sw.count() != 0 {
		t.Errorf("writer kept going after a write error")
	}
}

// TestDispatcher_AsyncCompletionDoesNotBlockTheChain is the defect stated in
// its own terms: a CHANGE_NOTIFY-style completion wedged on the socket must not
// stop the dispatcher answering anything else.
func TestDispatcher_AsyncCompletionDoesNotBlockTheChain(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newChainDispatcher(t, dir)
	sw := newStalledWriter()
	cw := newConnWriter(sw, testLog(), nil)
	d.out = cw
	defer func() { close(sw.release); cw.Close() }()

	// An async completion goes out immediately and wedges in the socket.
	d.sendAsync(io.Discard, smb2.Header{Command: smb2.CommandChangeNotify, SessionID: sess.ID},
		sess, 1, smb2.StatusSuccess, []byte{0x09, 0, 0, 0, 0, 0, 0, 0, 0})
	select {
	case <-sw.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the async completion never reached the socket")
	}

	// Meanwhile an ordinary chain must still be answered.
	done := make(chan struct{})
	go func() {
		defer close(done)
		fd := d.forFrame(false)
		fd.Dispatch(discardRW{}, smb2.Header{Command: smb2.CommandTreeConnect, SessionID: sess.ID, TreeID: tree.ID},
			buildTreeConnectBody(`\\srv\share`), nil)
		fd.flush(io.Discard)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the dispatch path is still stalled behind a wedged async completion")
	}
}

// mkFrame builds a throwaway NBSS frame of n payload bytes.
func mkFrame(n int) []byte {
	buf := make([]byte, transport.FrameHeaderSize+n)
	if err := transport.PutFrameHeader(buf); err != nil {
		panic(err)
	}
	return buf
}
