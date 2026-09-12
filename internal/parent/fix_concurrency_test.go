package parent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// TestConcurrency_ChainsDoNotCorruptEachOther is the test the whole per-frame
// chain context exists for.
//
// The "previous handle" FileID, the previous member's status and the chain's
// encryption flag used to live on the one shared Dispatcher. Running two
// chains at once on that layout meant chain A's CREATE could hand its FileID to
// chain B's WRITE, and B's payload would land in A's file. Each chain here
// creates its own file, writes its own payload through the previous-handle
// sentinel and closes it; every file must end up with exactly its own bytes.
//
// Run under -race this also covers the session table, the open table and the
// per-handle lock.
func TestConcurrency_ChainsDoNotCorruptEachOther(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newChainDispatcher(t, dir)

	const chains = 32
	replies := make([][]byte, chains)
	var wg sync.WaitGroup
	for i := 0; i < chains; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("f%02d.txt", i)
			payload := []byte(fmt.Sprintf("payload-for-chain-%02d", i))

			fd := d.forFrame(false)
			var buf bytes.Buffer
			base := uint64(i) * 10
			fd.Dispatch(&buf, smb2.Header{Command: smb2.CommandCreate, SessionID: sess.ID,
				TreeID: tree.ID, MessageID: base},
				buildCreateBody(name, smb2.CreateDispositionCreate, 0,
					smb2.AccessGenericRead|smb2.AccessGenericWrite, nil), nil)
			fd.Dispatch(&buf, smb2.Header{Command: smb2.CommandWrite, SessionID: sess.ID,
				TreeID: tree.ID, MessageID: base + 1, Flags: smb2.FlagRelatedOps},
				buildWriteBody(previousHandleFileID, 0, payload), nil)
			fd.Dispatch(&buf, smb2.Header{Command: smb2.CommandClose, SessionID: sess.ID,
				TreeID: tree.ID, MessageID: base + 2, Flags: smb2.FlagRelatedOps},
				buildCloseBody(previousHandleFileID), nil)
			fd.flush(&buf)
			replies[i] = buf.Bytes()
		}(i)
	}
	wg.Wait()

	// Each chain must have been answered with exactly its own three members,
	// in the order they were sent.
	for i := 0; i < chains; i++ {
		base := uint64(i) * 10
		members := splitCompound(t, replies[i])
		if len(members) != 3 {
			t.Errorf("chain %d got %d members, want 3", i, len(members))
			continue
		}
		for j, want := range []smb2.Command{
			smb2.CommandCreate, smb2.CommandWrite, smb2.CommandClose,
		} {
			if members[j].hdr.Command != want {
				t.Errorf("chain %d member %d is %v, want %v — chain order was not preserved",
					i, j, members[j].hdr.Command, want)
			}
			if got := members[j].hdr.MessageID; got != base+uint64(j) {
				t.Errorf("chain %d member %d MessageId = %d, want %d",
					i, j, got, base+uint64(j))
			}
		}
	}

	for i := 0; i < chains; i++ {
		name := fmt.Sprintf("f%02d.txt", i)
		want := fmt.Sprintf("payload-for-chain-%02d", i)
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s holds %q, want %q — one chain's handle leaked into another",
				name, got, want)
		}
	}
}

// TestConnPool_RunsFramesConcurrently proves the pool really overlaps frames
// rather than running them one after another. Every task parks until all of
// them have started, which can only complete if the pool runs them at once.
func TestConnPool_RunsFramesConcurrently(t *testing.T) {
	n := connWorkers()
	if n < 2 {
		t.Skip("pool is not configured for concurrency on this machine")
	}
	p := newConnPool(n)
	var started sync.WaitGroup
	started.Add(n)
	release := make(chan struct{})
	for i := 0; i < n; i++ {
		p.submit(func() {
			started.Done()
			<-release
		})
	}

	all := make(chan struct{})
	go func() { started.Wait(); close(all) }()
	select {
	case <-all:
	case <-time.After(3 * time.Second):
		close(release)
		p.drain()
		t.Fatal("the pool did not run frames concurrently")
	}
	close(release)
	p.drain()
}

// TestConnPool_BoundIsRespected proves concurrency is bounded: with more frames
// than workers, the number running at once never exceeds the pool size.
func TestConnPool_BoundIsRespected(t *testing.T) {
	const size = 4
	p := newConnPool(size)
	var live, peak atomic.Int64
	for i := 0; i < size*20; i++ {
		p.submit(func() {
			cur := live.Add(1)
			for {
				old := peak.Load()
				if cur <= old || peak.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			live.Add(-1)
		})
	}
	p.drain()
	if got := peak.Load(); got > size {
		t.Errorf("%d frames ran at once, pool size is %d", got, size)
	}
	if got := peak.Load(); got < 2 {
		t.Errorf("peak concurrency was %d; the pool never overlapped anything", got)
	}
}

// TestFrameNeedsSerialExecution pins which frames are kept off the pool. Being
// wrong towards "serial" costs concurrency; being wrong the other way would let
// a SESSION_SETUP — a multi-leg state machine whose success drops the process's
// privileges — run beside a file operation.
func TestFrameNeedsSerialExecution(t *testing.T) {
	msg := func(cmd smb2.Command, next uint32, extra int) []byte {
		b := make([]byte, smb2.HeaderSize+extra)
		_ = smb2.EncodeHeader(b[:smb2.HeaderSize], smb2.Header{Command: cmd, NextCommand: next})
		return b
	}
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"lone read", msg(smb2.CommandRead, 0, 48), false},
		{"lone session setup", msg(smb2.CommandSessionSetup, 0, 24), true},
		{"chain of reads", append(msg(smb2.CommandCreate, smb2.HeaderSize+8, 8),
			msg(smb2.CommandRead, 0, 48)...), false},
		{"session setup not first", append(msg(smb2.CommandTreeConnect, smb2.HeaderSize+8, 8),
			msg(smb2.CommandSessionSetup, 0, 24)...), true},
		{"empty", nil, true},
		{"truncated header", make([]byte, 8), true},
		{"NextCommand below header size", msg(smb2.CommandRead, 8, 48), true},
		{"NextCommand past the frame", msg(smb2.CommandRead, 4096, 48), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := frameNeedsSerialExecution(tc.frame); got != tc.want {
				t.Errorf("frameNeedsSerialExecution = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAsyncTable_CancelBeforeRegister covers the ordering that only became
// possible once frames ran concurrently: an SMB2_CANCEL can overtake the
// CHANGE_NOTIFY or blocking LOCK it names. Dropping it there would leave the
// client waiting on a request it has already abandoned.
func TestAsyncTable_CancelBeforeRegister(t *testing.T) {
	d := &Dispatcher{async: &asyncTable{}}

	if d.cancelNotify(7, smb2.StatusCancelled) {
		t.Error("cancelNotify reported it completed a request that had not registered")
	}
	reg := &notifyReg{cancel: make(chan struct{}), status: smb2.StatusNotifyCleanup}
	d.registerNotify(7, reg)

	select {
	case <-reg.cancel:
	default:
		t.Fatal("a request that registered after its cancel was not completed")
	}
	if reg.status != smb2.StatusCancelled {
		t.Errorf("completion status = 0x%08X, want STATUS_CANCELLED", reg.status)
	}
	// The remembered cancel is consumed, not left to bite the next request
	// that happens to reuse the id.
	reg2 := &notifyReg{cancel: make(chan struct{})}
	d.registerNotify(7, reg2)
	select {
	case <-reg2.cancel:
		t.Error("the remembered cancel fired a second time")
	default:
	}
}

// TestAsyncTable_PreCancelBounded proves a client cannot grow the remembered-
// cancel set without limit by cancelling ids it never used.
func TestAsyncTable_PreCancelBounded(t *testing.T) {
	d := &Dispatcher{async: &asyncTable{}}
	for i := 0; i < maxPreCancelled*4; i++ {
		d.cancelNotify(uint64(i), smb2.StatusCancelled)
	}
	d.async.mu.Lock()
	n := len(d.async.preCancelled)
	d.async.mu.Unlock()
	if n > maxPreCancelled {
		t.Errorf("remembered %d cancels, cap is %d", n, maxPreCancelled)
	}
}

// TestServeConn_AbortStillDeliversFinalResponse drives a real connection to the
// point where the dispatcher decides to drop it, and proves the response that
// made that decision still reaches the client.
//
// It is the shutdown protocol end to end: the handler queues its error, asks
// the read loop to stop (without slamming the socket), and teardown flushes the
// writer before the socket closes.
func TestServeConn_AbortStillDeliversFinalResponse(t *testing.T) {
	base := runtime.NumGoroutine()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ServeConn(ctx, c, slog.New(slog.NewTextHandler(io.Discard, nil)),
			transport.MaxFrameSize, ConnOptions{})
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := transport.WriteFrame(conn, buildClientNegotiate311()); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ReadFrame(conn, transport.MaxFrameSize); err != nil {
		t.Fatalf("negotiate: %v", err)
	}

	// A command naming a session that does not exist: the dispatcher answers
	// STATUS_USER_SESSION_DELETED and drops the connection.
	hdr := make([]byte, smb2.HeaderSize)
	if err := smb2.EncodeHeader(hdr, smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandTreeConnect,
		MessageID:    1,
		SessionID:    0xDEADBEEFCAFE,
	}); err != nil {
		t.Fatal(err)
	}
	if err := transport.WriteFrame(conn, append(hdr, buildTreeConnectBody(`\\srv\share`)...)); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, err := transport.ReadFrame(conn, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("the response that dropped the connection never arrived: %v", err)
	}
	resp, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if smb2.Status(resp.Status) != smb2.StatusUserSessionDeleted {
		t.Errorf("final status = 0x%08X, want USER_SESSION_DELETED", resp.Status)
	}
	if _, err := transport.ReadFrame(conn, transport.MaxFrameSize); err == nil {
		t.Error("connection stayed open after the dispatcher asked for it to be dropped")
	}

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return")
	}
	conn.Close()
	waitGoroutines(t, base+2)
}

// --- benchmark ---

// BenchmarkConnReadThroughput compares serving a connection's frames one at a
// time — what this server did — against serving them on the bounded
// per-connection worker pool. Each iteration serves one batch of concurrent
// READs of different files, which is the shape the macOS client's pipeline
// produces: it sizes that pipeline for eight concurrent 512 KiB transfers.
//
// The "signed" variants are the ones that matter most. The client switches its
// own engine to multi-threaded when signing or sealing is on precisely because
// it expects a parallel server, and a per-response MAC is exactly the CPU work
// a single-threaded connection cannot overlap.
func BenchmarkConnReadThroughput(b *testing.B) {
	const (
		files    = 8
		readSize = 512 << 10
	)
	dir := b.TempDir()
	blob := bytes.Repeat([]byte{0xAB}, 4<<20)
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.bin", i)), blob, 0644); err != nil {
			b.Fatal(err)
		}
	}

	setup := func(b *testing.B, signed bool) (*Dispatcher, *Session, []*Open) {
		b.Helper()
		d, sess, tree := newChainDispatcher(b, dir)
		d.Conn.MaxIOSize = 8 << 20
		if signed {
			sess.SigningKey = bytes.Repeat([]byte{0x5A}, 16)
			d.Conn.Selection.SigningAlgo = smb2.SigningAlgo(smb3.SignAlgoAESCMAC)
		}
		// Share everything: the share-mode table is process-global, so the
		// sub-benchmarks would otherwise deny each other the same files.
		const shareAll = shareAccessRead | shareAccessWrite | shareAccessDelete
		opens := make([]*Open, files)
		for i := 0; i < files; i++ {
			var buf bytes.Buffer
			fd := d.forFrame(false)
			fd.Dispatch(&buf, smb2.Header{Command: smb2.CommandCreate, SessionID: sess.ID, TreeID: tree.ID},
				buildCreateBodyShare(fmt.Sprintf("f%d.bin", i), smb2.CreateDispositionOpen, 0,
					smb2.AccessGenericRead, shareAll, nil), nil)
			fd.flush(&buf)
			opens[i] = sess.GetOpen(fd.LastCreatedFileID)
			if opens[i] == nil {
				hdr, _ := smb2.DecodeHeader(buf.Bytes()[4 : 4+smb2.HeaderSize])
				b.Fatalf("open %d failed: status 0x%08X", i, hdr.Status)
			}
		}
		b.Cleanup(func() { d.releaseOpens(sess.TakeAllOpens()) })
		return d, sess, opens
	}

	for _, mode := range []struct {
		name   string
		signed bool
	}{{"plain", false}, {"signed", true}} {
		b.Run(mode.name+"/sequential", func(b *testing.B) {
			d, sess, opens := setup(b, mode.signed)
			b.SetBytes(int64(files * readSize))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < files; j++ {
					serveRead(d, sess, opens[j], uint64((i%8)*readSize), readSize)
				}
			}
		})

		b.Run(mode.name+"/pool", func(b *testing.B) {
			d, sess, opens := setup(b, mode.signed)
			p := newConnPool(connWorkers())
			b.SetBytes(int64(files * readSize))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < files; j++ {
					o, off := opens[j], uint64((i%8)*readSize)
					p.submit(func() { serveRead(d, sess, o, off, readSize) })
				}
				p.drain()
			}
		})
	}
}

// serveRead runs one READ frame end to end — dispatch, response build, sign,
// flush — against a discard writer.
func serveRead(d *Dispatcher, sess *Session, o *Open, off uint64, length uint32) {
	fd := d.forFrame(false)
	fd.Dispatch(discardRW{}, smb2.Header{Command: smb2.CommandRead, SessionID: sess.ID},
		buildReadBody(o.FileID, off, length), nil)
	fd.flush(discardRW{})
}
