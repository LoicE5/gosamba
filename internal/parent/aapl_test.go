package parent

import (
	"encoding/binary"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// TestMxAcResponseContext proves the server answers a "query maximal access"
// (MxAc) create context with the granted access mask. iOS Files reads a
// share's writability from this response context (macOS Finder uses the
// TREE_CONNECT MaximalAccess instead) — without it iOS mounts read-only.
func TestMxAcResponseContext(t *testing.T) {
	reqCtxs := smb2.EncodeCreateContexts([]smb2.CreateContext{
		{Name: []byte("MxAc"), Data: nil},
	})

	out := buildCreateResponseContexts(reqCtxs, nil, 0x001F01FF, 0, 0)

	var found bool
	smb2.IterateCreateContexts(out, func(c smb2.CreateContext) bool {
		if string(c.Name) != "MxAc" {
			return true
		}
		found = true
		if len(c.Data) != 8 {
			t.Fatalf("MxAc response data len = %d, want 8", len(c.Data))
		}
		if qs := binary.LittleEndian.Uint32(c.Data[0:]); qs != 0 {
			t.Fatalf("MxAc QueryStatus = %#x, want 0 (STATUS_SUCCESS)", qs)
		}
		if ma := binary.LittleEndian.Uint32(c.Data[4:]); ma != 0x001F01FF {
			t.Fatalf("MxAc MaximalAccess = %#x, want 0x001F01FF", ma)
		}
		return true
	})
	if !found {
		t.Fatal("no MxAc response context emitted")
	}

	// Read-only shares must report the read/execute mask, not full access.
	outRO := buildCreateResponseContexts(reqCtxs, nil, 0x001200A9, 0, 0)
	smb2.IterateCreateContexts(outRO, func(c smb2.CreateContext) bool {
		if string(c.Name) == "MxAc" {
			if ma := binary.LittleEndian.Uint32(c.Data[4:]); ma != 0x001200A9 {
				t.Fatalf("read-only MxAc MaximalAccess = %#x, want 0x001200A9", ma)
			}
		}
		return true
	})
}
