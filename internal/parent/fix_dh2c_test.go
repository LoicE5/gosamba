package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- Defect: a durable reconnect echoed the wrong create context ---
//
// handleDurableReconnect used to answer a DH2C (durable handle reconnect v2)
// with a DH2Q durable-handle response context. MS-SMB2 §3.3.5.9.12's Response
// Construction phase enumerates only the lease response contexts and never
// constructs a durable-handle response; step 2.14 makes a DH2Q arriving
// alongside a DH2C an error outright, so the echo answered a request context
// the client could not legally have sent.
//
// Apple's SMBClient shows the cost on a real client: it clears
// SMB2_DURABLE_HANDLE_RECONNECT only in its RqLs arm, while its DH2Q arm clears
// SMB2_DURABLE_HANDLE_REQUEST — a flag a reconnect never sets. So after a
// reconnect the server had in fact granted, the client still believed the
// reconnect was pending, and flagged SMB2_DURABLE_HANDLE_FAIL for the
// request/response version mismatch as well.
//
// DHnC (v1) is governed by §3.3.5.9.7, a different section with a different
// construction phase, and is deliberately left echoing DHnQ.

// contextTags returns the create-context names present in a response blob, in
// wire order, so a test can assert on both what is there and what is not.
func contextTags(raw []byte) []string {
	var tags []string
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		tags = append(tags, string(c.Name))
		return true
	})
	return tags
}

// durableReconnectFixture stands up a durable open over a real file, then drops
// the connection so the entry is reclaimable. It returns everything a reconnect
// CREATE needs: the dispatcher, a fresh session+tree standing in for the new
// connection, and the reclaimed-handle FileID to assert against.
type durableReconnectFixture struct {
	d        *Dispatcher
	sess2    *Session
	tree2    *Tree
	fileID   [16]byte
	shareDir string
	path     string
}

// setupDurableReconnect performs a durable CREATE (v2 DH2Q when v2 is true,
// v1 DHnQ otherwise) and detaches it, exactly as a dropped connection would.
func setupDurableReconnect(t *testing.T, v2 bool) *durableReconnectFixture {
	t.Helper()
	shareDir := t.TempDir()
	path := filepath.Join(shareDir, "dur.txt")
	if err := os.WriteFile(path, []byte("payload"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree, tbl := newDurableDispatcher(t, shareDir)

	var reqCtx smb2.CreateContext
	var createGuid [16]byte
	if v2 {
		var dh2q [32]byte
		binary.LittleEndian.PutUint32(dh2q[0:], 30000)
		createGuid[0] = 0x9E
		copy(dh2q[16:32], createGuid[:])
		reqCtx = smb2.CreateContext{Name: tagDH2Q, Data: dh2q[:]}
	} else {
		// DHnQ carries 16 reserved bytes and no CreateGuid; the table keys the
		// entry by the FileID instead, which we learn from the response.
		reqCtx = smb2.CreateContext{Name: tagDHnQ, Data: make([]byte, 16)}
	}
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{reqCtx})
	body := buildCreateBody("dur.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	if !d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID}, body, sess) {
		t.Fatalf("durable CREATE returned false")
	}
	hdr, resp, rctxs := readCreateResponse(t, &buf)
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("durable CREATE status=0x%08X, want SUCCESS", hdr.Status)
	}
	wantEcho := tagDHnQ
	if v2 {
		wantEcho = tagDH2Q
	}
	if !hasContext(rctxs, wantEcho) {
		t.Fatalf("fresh durable CREATE did not echo %s: got %v", wantEcho, contextTags(rctxs))
	}
	if tbl.len() != 1 {
		t.Fatalf("durable table len=%d, want 1", tbl.len())
	}
	if !v2 {
		createGuid = resp.FileID
	}

	// The connection drops: the open leaves the session and the durable entry
	// detaches, which is what makes it reclaimable.
	sess.RemoveOpen(resp.FileID)
	tbl.Detach(d.Conn.ClientGuid, createGuid)

	sess2 := &Session{}
	tree2 := sess2.AddTree(d.Shares[0])
	return &durableReconnectFixture{
		d: d, sess2: sess2, tree2: tree2,
		fileID: resp.FileID, shareDir: shareDir, path: path,
	}
}

// reconnect issues the reconnect CREATE carrying ctxs and returns the parsed
// response.
func (f *durableReconnectFixture) reconnect(t *testing.T, ctxs []smb2.CreateContext) (smb2.Header, smb2.CreateResponse, []byte) {
	t.Helper()
	body := buildCreateBody("dur.txt", smb2.CreateDispositionOpen, 0,
		smb2.AccessGenericRead, smb2.EncodeCreateContexts(ctxs))
	var buf bytes.Buffer
	if !f.d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: f.tree2.ID}, body, f.sess2) {
		t.Fatalf("reconnect CREATE returned false")
	}
	return readCreateResponse(t, &buf)
}

// assertReclaimed proves the reconnect did the actual work behind the response
// contexts: the original FileID came back and the Open is live on the new
// session, pointing at the same backing file.
func (f *durableReconnectFixture) assertReclaimed(t *testing.T, resp smb2.CreateResponse) {
	t.Helper()
	if resp.FileID != f.fileID {
		t.Fatalf("reclaimed FileID=%x, want %x (same handle)", resp.FileID, f.fileID)
	}
	open := f.sess2.GetOpen(f.fileID)
	if open == nil {
		t.Fatalf("reclaimed open not restored on the new session")
	}
	if open.Path != f.path {
		t.Fatalf("reclaimed open path=%q, want %q", open.Path, f.path)
	}
	if !open.IsDurable {
		t.Errorf("reclaimed open is not marked durable, so it cannot be reclaimed again")
	}
}

// buildDH2C returns a DH2C reconnect context for the given handle.
func buildDH2C(fileID [16]byte) smb2.CreateContext {
	var data [36]byte
	copy(data[0:16], fileID[:])
	var createGuid [16]byte
	createGuid[0] = 0x9E // must match setupDurableReconnect's DH2Q CreateGuid
	copy(data[16:32], createGuid[:])
	return smb2.CreateContext{Name: tagDH2C, Data: data[:]}
}

// TestFix_DH2CReconnectAnsweredWithLeaseContext is the core regression test: a
// v2 reconnect carrying an RqLs must come back with an RqLs response — same
// lease key, LEASE_NONE, and the matching v1/v2 payload size — and with no
// DH2Q context at all.
func TestFix_DH2CReconnectAnsweredWithLeaseContext(t *testing.T) {
	for _, tc := range []struct {
		name     string
		leaseLen int
	}{
		{"lease v1 request", rqLsV1Size},
		{"lease v2 request", rqLsV2Size},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupDurableReconnect(t, true)

			var key [16]byte
			key[0] = 0x7E
			key[15] = 0xF1
			lease := make([]byte, tc.leaseLen)
			copy(lease[0:16], key[:])
			// Ask for everything; the server must still grant nothing.
			binary.LittleEndian.PutUint32(lease[16:],
				leaseReadCaching|leaseHandleCaching|leaseWriteCaching)

			before := sharedShareModes.len()
			hdr, resp, rctxs := f.reconnect(t, []smb2.CreateContext{
				buildDH2C(f.fileID),
				{Name: tagRqLs, Data: lease},
			})
			if smb2.Status(hdr.Status) != smb2.StatusSuccess {
				t.Fatalf("DH2C reconnect status=0x%08X, want SUCCESS", hdr.Status)
			}
			f.assertReclaimed(t, resp)

			// The reclaim transfers the share-mode reservation onto the
			// replacement Open rather than adding a second one; the response
			// context change must not have disturbed that.
			if got := sharedShareModes.len(); got != before {
				t.Errorf("share-mode reservations went %d -> %d across the reclaim, want unchanged",
					before, got)
			}

			// MS-SMB2 §3.3.5.9.12 constructs no durable-handle response, and
			// §3.3.5.9.12 step 2.14 makes DH2Q+DH2C an error, so a DH2Q reply
			// answers a context the client could not have sent.
			if hasContext(rctxs, tagDH2Q) {
				t.Errorf("DH2C reconnect still echoed a DH2Q context: %v", contextTags(rctxs))
			}
			if hasContext(rctxs, tagDHnQ) {
				t.Errorf("DH2C reconnect echoed a DHnQ context: %v", contextTags(rctxs))
			}

			data := rqLsResponseData(t, rctxs)
			if len(data) != tc.leaseLen {
				t.Fatalf("RqLs response len=%d, want %d (must match the request form)",
					len(data), tc.leaseLen)
			}
			if !bytes.Equal(data[0:16], key[:]) {
				t.Errorf("lease key not echoed: got %x, want %x", data[0:16], key)
			}
			if got := binary.LittleEndian.Uint32(data[16:]); got != leaseNone {
				t.Errorf("granted LeaseState=0x%08X, want LEASE_NONE: we implement no lease-break machinery",
					got)
			}
			// Exactly one context, so the client cannot latch onto anything else.
			if tags := contextTags(rctxs); len(tags) != 1 || tags[0] != "RqLs" {
				t.Errorf("reconnect response contexts = %v, want exactly [RqLs]", tags)
			}
		})
	}
}

// TestFix_DHnCReconnectStillEchoesDHnQ pins the v1 path as deliberately
// unchanged. DHnC is handled by MS-SMB2 §3.3.5.9.7, not §3.3.5.9.12, and Apple
// observes "a RqLs and DHnQ reply" there (smb_smb_2.c), so the DHnQ echo stays.
func TestFix_DHnCReconnectStillEchoesDHnQ(t *testing.T) {
	f := setupDurableReconnect(t, false)

	var dhnc [16]byte
	copy(dhnc[:], f.fileID[:])
	hdr, resp, rctxs := f.reconnect(t, []smb2.CreateContext{
		{Name: tagDHnC, Data: dhnc[:]},
	})
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("DHnC reconnect status=0x%08X, want SUCCESS", hdr.Status)
	}
	f.assertReclaimed(t, resp)

	if !hasContext(rctxs, tagDHnQ) {
		t.Fatalf("DHnC reconnect no longer echoes DHnQ: got %v — §3.3.5.9.7 governs v1, not §3.3.5.9.12",
			contextTags(rctxs))
	}
	if hasContext(rctxs, tagDH2Q) {
		t.Errorf("DHnC reconnect echoed a v2 DH2Q context: %v", contextTags(rctxs))
	}
}

// TestFix_DH2CWithoutLeaseContextGetsNoContexts records the decision for a v2
// reconnect that carries no RqLs.
//
// We answer with NO create contexts. Both response contexts §3.3.5.9.12 can
// construct are gated on Open.Lease being non-NULL, and a request with no RqLs
// establishes no lease, so the section constructs nothing; SUCCESS plus the
// reclaimed FileID is the whole answer. Falling back to the DH2Q echo would put
// back precisely the context that section refuses to construct — and any client
// that parsed it would hit the same "reconnect still pending" bug. In practice
// this case does not arise on a real client: Apple's SMBClient requires a lease
// request alongside a durable reconnect, and Windows sends RqLs with DH2C
// whenever the handle had a lease.
func TestFix_DH2CWithoutLeaseContextGetsNoContexts(t *testing.T) {
	f := setupDurableReconnect(t, true)

	hdr, resp, rctxs := f.reconnect(t, []smb2.CreateContext{buildDH2C(f.fileID)})
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("DH2C reconnect status=0x%08X, want SUCCESS", hdr.Status)
	}
	// The reclaim itself must still happen — the decision is only about what
	// the response advertises.
	f.assertReclaimed(t, resp)

	if tags := contextTags(rctxs); len(tags) != 0 {
		t.Fatalf("DH2C without RqLs answered with contexts %v, want none", tags)
	}
}
