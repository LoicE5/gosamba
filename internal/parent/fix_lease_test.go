package parent

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- Defect 1: lease state constants must carry their MS-SMB2 values ---

// TestFix_LeaseStateConstantsMatchSpec pins the LeaseState bits from MS-SMB2
// §2.2.13.2.8 (and Apple's SMBClient smb_2.h, which agrees): READ 0x01,
// HANDLE 0x02, WRITE 0x04. HANDLE and WRITE used to be swapped, which meant a
// grant the author wrote as read+handle (0x01|0x04) would have put
// WRITE_CACHING on the wire and let macOS enable write-behind caching.
func TestFix_LeaseStateConstantsMatchSpec(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"SMB2_LEASE_NONE", leaseNone, 0x00},
		{"SMB2_LEASE_READ_CACHING", leaseReadCaching, 0x01},
		{"SMB2_LEASE_HANDLE_CACHING", leaseHandleCaching, 0x02},
		{"SMB2_LEASE_WRITE_CACHING", leaseWriteCaching, 0x04},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = 0x%02X, want 0x%02X", tc.name, tc.got, tc.want)
		}
	}
	// The three caching bits must also be distinct single bits.
	if leaseReadCaching|leaseHandleCaching|leaseWriteCaching != 0x07 {
		t.Errorf("lease caching bits overlap: 0x%02X",
			leaseReadCaching|leaseHandleCaching|leaseWriteCaching)
	}
}

// --- Defect 2: the RqLs response must match the request's version ---

// buildRqLs returns an RqLs create-context blob of the given payload size
// (32 = lease v1, 52 = lease v2) carrying key and state.
func buildRqLs(size int, key [16]byte, state uint32) []byte {
	data := make([]byte, size)
	copy(data[0:16], key[:])
	binary.LittleEndian.PutUint32(data[16:], state)
	return smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagRqLs, Data: data}})
}

// rqLsResponseData returns the payload of the RqLs context in a response blob.
func rqLsResponseData(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out []byte
	found := false
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		if eqTag(c.Name, tagRqLs) {
			out = append([]byte(nil), c.Data...)
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Fatalf("no RqLs context in response blob")
	}
	return out
}

// TestFix_ParseRqLsRecordsVersion proves the parser records which RqLs form
// arrived. Both versions share the context name "RqLs", so the 32- vs 52-byte
// request length is the only discriminator.
func TestFix_ParseRqLsRecordsVersion(t *testing.T) {
	var key [16]byte
	key[0] = 0x5A

	_, _, v1 := parseDurableContexts(buildRqLs(rqLsV1Size, key, leaseReadCaching))
	if !v1.present {
		t.Fatalf("32-byte RqLs not parsed")
	}
	if v1.v2 {
		t.Errorf("32-byte RqLs parsed as v2, want v1")
	}
	if v1.key != key {
		t.Errorf("v1 lease key mismatch: %x", v1.key)
	}

	_, _, v2 := parseDurableContexts(buildRqLs(rqLsV2Size, key, leaseReadCaching))
	if !v2.present {
		t.Fatalf("52-byte RqLs not parsed")
	}
	if !v2.v2 {
		t.Errorf("52-byte RqLs parsed as v1, want v2")
	}
	if v2.key != key {
		t.Errorf("v2 lease key mismatch: %x", v2.key)
	}
}

// TestFix_EncodeRqLsResponseSizes proves the encoder emits exactly the 32-byte
// v1 form or the 52-byte v2 form, with the lease key and granted state in the
// same place either way and a zeroed v2 tail (no parent lease key, epoch 0).
func TestFix_EncodeRqLsResponseSizes(t *testing.T) {
	var key [16]byte
	key[0] = 0xA5
	key[15] = 0x3C

	v1 := encodeRqLsResponse(key, leaseNone, false)
	if len(v1) != 32 {
		t.Fatalf("v1 response len=%d, want 32", len(v1))
	}
	v2 := encodeRqLsResponse(key, leaseNone, true)
	if len(v2) != 52 {
		t.Fatalf("v2 response len=%d, want 52", len(v2))
	}
	for _, b := range [][]byte{v1, v2} {
		if !bytes.Equal(b[0:16], key[:]) {
			t.Errorf("lease key not echoed: %x", b[0:16])
		}
		if got := binary.LittleEndian.Uint32(b[16:]); got != leaseNone {
			t.Errorf("LeaseState=0x%08X, want LEASE_NONE", got)
		}
		if got := binary.LittleEndian.Uint32(b[20:]); got != 0 {
			t.Errorf("LeaseFlags=0x%08X, want 0 (no PARENT_LEASE_KEY_SET)", got)
		}
		if got := binary.LittleEndian.Uint64(b[24:]); got != 0 {
			t.Errorf("LeaseDuration=%d, want 0", got)
		}
	}
	// v2 tail: ParentLeaseKey(16) Epoch(2) Reserved(2), all zero because we
	// never establish a lease.
	if !bytes.Equal(v2[32:52], make([]byte, 20)) {
		t.Errorf("v2 tail not zeroed: %x", v2[32:52])
	}
}

// TestFix_RqLsResponseVersionMatchesRequest drives the real CREATE response
// path: a 52-byte (v2) lease request must be answered with a 52-byte context
// and a 32-byte (v1) request with a 32-byte one. Answering a v2 request with
// the v1 form makes Apple's client flag SMB2_LEASE_FAIL, and directory leases
// are always v2.
func TestFix_RqLsResponseVersionMatchesRequest(t *testing.T) {
	d, _, tree, _ := newDurableDispatcher(t, t.TempDir())
	var key [16]byte
	key[0] = 0x11

	for _, tc := range []struct {
		name    string
		reqSize int
		want    int
	}{
		{"lease v1 request", rqLsV1Size, 32},
		{"lease v2 request", rqLsV2Size, 52},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, lr := parseDurableContexts(buildRqLs(tc.reqSize, key, leaseReadCaching|leaseHandleCaching))
			if !lr.present {
				t.Fatalf("lease request not parsed")
			}
			open := &Open{Path: "/tmp/leasetest", Tree: tree}
			blob := d.applyDurableAndLease(open, durableRequest{}, lr, nil, "alice")
			data := rqLsResponseData(t, blob)
			if len(data) != tc.want {
				t.Fatalf("RqLs response len=%d, want %d", len(data), tc.want)
			}
			if !bytes.Equal(data[0:16], key[:]) {
				t.Errorf("lease key not echoed: %x", data[0:16])
			}
			// We never grant caching: the response must say LEASE_NONE even
			// though the request asked for read+handle.
			if got := binary.LittleEndian.Uint32(data[16:]); got != leaseNone {
				t.Errorf("granted LeaseState=0x%08X, want LEASE_NONE", got)
			}
		})
	}
}

// --- Defect 3: OPLOCK_BREAK must not be answered STATUS_NOT_SUPPORTED ---

// TestFix_OplockBreakStatus proves an SMB2 OPLOCK_BREAK the server cannot match
// is answered STATUS_INVALID_OPLOCK_PROTOCOL. MS-SMB2 §3.3.5.22 lists only
// STATUS_INVALID_OPLOCK_PROTOCOL, STATUS_INVALID_PARAMETER and
// STATUS_FILE_CLOSED for this case; STATUS_NOT_SUPPORTED is not among them.
func TestFix_OplockBreakStatus(t *testing.T) {
	if smb2.StatusInvalidOplockProtocol != 0xC00000E3 {
		t.Fatalf("StatusInvalidOplockProtocol = 0x%08X, want 0xC00000E3",
			uint32(smb2.StatusInvalidOplockProtocol))
	}

	tbl := NewSessionTable()
	sess := tbl.New()
	sess.Authenticated = true
	d := &Dispatcher{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions: tbl,
		Conn:     &Connection{},
	}
	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandOplockBreak, SessionID: sess.ID}
	if !d.Dispatch(&buf, hdr, make([]byte, 24), nil) {
		t.Errorf("Dispatch dropped the connection on OPLOCK_BREAK, want it kept")
	}
	if st := frameStatus(t, &buf); st != smb2.StatusInvalidOplockProtocol {
		t.Errorf("OPLOCK_BREAK status=0x%08X, want STATUS_INVALID_OPLOCK_PROTOCOL (0xC00000E3)", uint32(st))
	}
}
