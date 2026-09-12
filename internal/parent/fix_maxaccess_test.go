package parent

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// mxAcReqCtx builds the SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST context macOS
// attaches to its CREATEs: name "MxAc", no data.
func mxAcReqCtx() []byte {
	return smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: []byte("MxAc"), Data: nil}})
}

// createAndReadMxAc drives a real CREATE through the dispatcher and returns the
// MaximalAccess the MxAc response context reports. macOS builds its entire
// smbfs_vnop_access() answer out of this one value — it never asks for
// FileAccessInformation separately — so this is what access(2) on the mount
// sees.
func createAndReadMxAc(t *testing.T, d *Dispatcher, sess *Session, tree *Tree, name string, disposition, options, access uint32) uint32 {
	t.Helper()
	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBody(name, disposition, options, access, mxAcReqCtx()), sess)
	hdr, _, rctxs := readCreateResponse(t, &buf)
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("CREATE %q failed: status %#x", name, hdr.Status)
	}
	data, ok := findContext(rctxs, "MxAc")
	if !ok {
		t.Fatalf("no MxAc response context for %q", name)
	}
	if len(data) != 8 {
		t.Fatalf("MxAc data len = %d, want 8", len(data))
	}
	if qs := binary.LittleEndian.Uint32(data[0:]); qs != 0 {
		t.Fatalf("MxAc QueryStatus = %#x, want STATUS_SUCCESS", qs)
	}
	return binary.LittleEndian.Uint32(data[4:])
}

// newReadOnlyTestDispatcher is newTestDispatcher with the share marked
// read-only, so the share ceiling can be exercised.
func newReadOnlyTestDispatcher(t *testing.T, shareDir string) (*Dispatcher, *Session, *Tree) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir, ReadOnly: true}
	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{share},
	}
	sess := &Session{}
	return d, sess, sess.AddTree(share)
}

// skipIfRoot skips permission-dependent assertions when the test process is
// root: access(2) lets root through almost every mode bit, so a 0444 file
// genuinely IS writable for root and reporting so is correct, not a bug.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: access(2) bypasses POSIX mode bits")
	}
}

// TestNarrowAccessMask is the pure bit arithmetic, independent of any
// filesystem or of the identity the test runs as.
func TestNarrowAccessMask(t *testing.T) {
	rw := accessFileAllAccess
	ro := accessReadOnlyShare

	tests := []struct {
		name                        string
		ceiling                     uint32
		readable, writable, execute bool
		wantSet, wantClear          uint32
	}{
		{
			name:    "rw share, r--: no write, no execute",
			ceiling: rw, readable: true,
			wantSet:   accFileReadData | accFileReadAttributes | accReadControl | accSynchronize,
			wantClear: accessWriteBits | accFileExecute,
		},
		{
			name:    "rw share, rw-: write but no execute",
			ceiling: rw, readable: true, writable: true,
			wantSet:   accFileReadData | accFileWriteData | accFileAppendData | accFileWriteAttributes | accFileWriteEA | accDelete,
			wantClear: accFileExecute,
		},
		{
			name:    "rw share, rwx: everything",
			ceiling: rw, readable: true, writable: true, execute: true,
			wantSet:   rw,
			wantClear: 0,
		},
		{
			name:    "ro share can never report write even when writable",
			ceiling: ro, readable: true, writable: true, execute: true,
			wantSet:   accFileReadData | accFileExecute,
			wantClear: accessWriteBits,
		},
		{
			name:      "unreadable drops read-data and read-ea but keeps read-attributes",
			ceiling:   rw,
			wantSet:   accFileReadAttributes | accReadControl | accSynchronize,
			wantClear: accFileReadData | accFileReadEA | accFileExecute | accessWriteBits,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := narrowAccessMask(tc.ceiling, tc.readable, tc.writable, tc.execute)
			if got&tc.wantSet != tc.wantSet {
				t.Errorf("mask %#08x missing bits %#08x", got, tc.wantSet&^got)
			}
			if got&tc.wantClear != 0 {
				t.Errorf("mask %#08x still carries bits %#08x", got, got&tc.wantClear)
			}
			// Narrowing may only ever subtract from the ceiling.
			if got&^tc.ceiling != 0 {
				t.Errorf("mask %#08x exceeds ceiling %#08x", got, tc.ceiling)
			}
		})
	}
}

// TestMaxAccess_FileModeBitsReachMxAc proves the MxAc mask follows the file's
// real POSIX mode instead of the old share-wide FILE_ALL_ACCESS constant.
//
// Before the fix a mode 0444 file answered access(W_OK)=true and
// access(X_OK)=true on a macOS mount, and the write that followed failed with
// EACCES; every file on the share looked executable because the AAPL reply
// declares the server UNIX-based, so the client trusts the execute bit
// verbatim (smbfs_vnops.c, smbfs_vnop_access).
func TestMaxAccess_FileModeBitsReachMxAc(t *testing.T) {
	skipIfRoot(t)

	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)

	for _, tc := range []struct {
		name         string
		mode         os.FileMode
		wantWrite    bool
		wantExecute  bool
		desiredAcces uint32
	}{
		{name: "ro.txt", mode: 0o444, wantWrite: false, wantExecute: false, desiredAcces: smb2.AccessGenericRead},
		{name: "rw.txt", mode: 0o644, wantWrite: true, wantExecute: false, desiredAcces: smb2.AccessGenericAll},
		{name: "rwx.sh", mode: 0o755, wantWrite: true, wantExecute: true, desiredAcces: smb2.AccessGenericAll},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(shareDir, tc.name)
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}

			got := createAndReadMxAc(t, d, sess, tree, tc.name,
				smb2.CreateDispositionOpen, smb2.CreateOptNonDirFile, tc.desiredAcces)

			// A readable file always keeps FILE_READ_DATA; without it macOS
			// refuses the open outright.
			if got&accFileReadData == 0 {
				t.Errorf("mode %o: MxAc %#08x lacks FILE_READ_DATA", tc.mode, got)
			}
			if hasWrite := got&accessWriteBits != 0; hasWrite != tc.wantWrite {
				t.Errorf("mode %o: MxAc %#08x write bits = %v, want %v (present: %#08x)",
					tc.mode, got, hasWrite, tc.wantWrite, got&accessWriteBits)
			}
			if hasExec := got&accFileExecute != 0; hasExec != tc.wantExecute {
				t.Errorf("mode %o: MxAc %#08x FILE_EXECUTE = %v, want %v",
					tc.mode, got, hasExec, tc.wantExecute)
			}
		})
	}
}

// TestMaxAccess_GrantedAccessMatchesMxAc proves the handle's GrantedAccess —
// what FileAccessInformation / FileAllInformation report — is narrowed the same
// way, so a client that reads both cannot see two different answers.
func TestMaxAccess_GrantedAccessMatchesMxAc(t *testing.T) {
	skipIfRoot(t)

	shareDir := t.TempDir()
	p := filepath.Join(shareDir, "ro.txt")
	if err := os.WriteFile(p, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o444); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	mask := createAndReadMxAc(t, d, sess, tree, "ro.txt",
		smb2.CreateDispositionOpen, smb2.CreateOptNonDirFile, smb2.AccessGenericRead)

	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil {
		t.Fatal("no open registered for the CREATE")
	}
	if open.GrantedAccess != mask {
		t.Fatalf("Open.GrantedAccess = %#08x, MxAc = %#08x: the two reporting paths disagree",
			open.GrantedAccess, mask)
	}
	if open.GrantedAccess&accessWriteBits != 0 {
		t.Errorf("GrantedAccess %#08x reports write on a mode 0444 file", open.GrantedAccess)
	}
}

// TestMaxAccess_ReadOnlyShareNeverReportsWrite proves the share's read-only
// setting stays a hard ceiling: a world-writable file on a read-only share must
// still report no write access at all.
func TestMaxAccess_ReadOnlyShareNeverReportsWrite(t *testing.T) {
	shareDir := t.TempDir()
	p := filepath.Join(shareDir, "open.txt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newReadOnlyTestDispatcher(t, shareDir)

	// A read-only share rejects every disposition but Open and every
	// write-implying DesiredAccess bit, so ask for plain read.
	got := createAndReadMxAc(t, d, sess, tree, "open.txt",
		smb2.CreateDispositionOpen, smb2.CreateOptNonDirFile, smb2.AccessGenericRead)

	if got&accessWriteBits != 0 {
		t.Fatalf("read-only share MxAc = %#08x reports write bits %#08x on a mode 0666 file",
			got, got&accessWriteBits)
	}
	if got&^accessReadOnlyShare != 0 {
		t.Fatalf("read-only share MxAc = %#08x exceeds the ceiling %#08x", got, accessReadOnlyShare)
	}
	if got&accFileReadData == 0 {
		t.Fatalf("read-only share MxAc = %#08x lacks FILE_READ_DATA", got)
	}
}

// TestMaxAccess_DirectoryKeepsListBits proves directory listing cannot break.
//
// FILE_LIST_DIRECTORY is the same bit as FILE_READ_DATA and FILE_TRAVERSE is
// the same bit as FILE_EXECUTE. smbfs_vnop_access() denies KAUTH_VNODE_SEARCH
// unless at least one of the two is present, and macOS refuses to enumerate a
// directory whose mask lacks FILE_LIST_DIRECTORY even when the CREATE itself
// succeeded — so a normal mode 0755 directory must keep both, and the server
// must still be able to read it.
func TestMaxAccess_DirectoryKeepsListBits(t *testing.T) {
	shareDir := t.TempDir()
	sub := filepath.Join(shareDir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "child.txt"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)

	got := createAndReadMxAc(t, d, sess, tree, "sub",
		smb2.CreateDispositionOpen, smb2.CreateOptDirectoryFile, smb2.AccessGenericRead)

	if got&accFileReadData == 0 {
		t.Fatalf("directory MxAc = %#08x lacks FILE_LIST_DIRECTORY; macOS would refuse to list it", got)
	}
	if got&accFileExecute == 0 {
		t.Fatalf("directory MxAc = %#08x lacks FILE_TRAVERSE on a mode 0755 directory", got)
	}
	if got&accFileWriteData == 0 && os.Geteuid() != 0 {
		// The directory is writable by its creator, so FILE_ADD_FILE
		// (== FILE_WRITE_DATA) must survive: without it macOS refuses to create
		// anything inside the directory.
		t.Fatalf("directory MxAc = %#08x lacks FILE_ADD_FILE on a writable directory", got)
	}

	// The reported rights must match what the server can really do.
	if _, err := os.ReadDir(sub); err != nil {
		t.Fatalf("server cannot read the directory it advertised as listable: %v", err)
	}

	// A read-only share must keep the listing bits too.
	dRO, sessRO, treeRO := newReadOnlyTestDispatcher(t, shareDir)
	gotRO := createAndReadMxAc(t, dRO, sessRO, treeRO, "sub",
		smb2.CreateDispositionOpen, smb2.CreateOptDirectoryFile, smb2.AccessGenericRead)
	if gotRO&accFileReadData == 0 {
		t.Fatalf("read-only share directory MxAc = %#08x lacks FILE_LIST_DIRECTORY", gotRO)
	}
	if gotRO&accessWriteBits != 0 {
		t.Fatalf("read-only share directory MxAc = %#08x reports write bits", gotRO)
	}
}

// TestMaxAccess_UnreadableFileDropsReadBits proves a file the server genuinely
// cannot read is reported as unreadable rather than as FILE_ALL_ACCESS.
func TestMaxAccess_UnreadableFileDropsReadBits(t *testing.T) {
	skipIfRoot(t)

	shareDir := t.TempDir()
	p := filepath.Join(shareDir, "secret.txt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })

	got := maximalAccess(p, false)
	if got&accFileReadData != 0 {
		t.Errorf("mode 0000 file mask %#08x still reports FILE_READ_DATA", got)
	}
	if got&accessWriteBits != 0 {
		t.Errorf("mode 0000 file mask %#08x still reports write bits", got)
	}
	if got&accFileExecute != 0 {
		t.Errorf("mode 0000 file mask %#08x still reports FILE_EXECUTE", got)
	}
	// Attribute/handle rights are not POSIX-gated and must survive.
	if got&(accFileReadAttributes|accReadControl|accSynchronize) != (accFileReadAttributes | accReadControl | accSynchronize) {
		t.Errorf("mode 0000 file mask %#08x dropped stat/handle rights", got)
	}
}

// TestMaxAccess_MissingPathFallsBackToCeiling proves a non-permission failure
// from faccessat (here ENOENT) leaves the old share-wide behaviour in place
// rather than locking the client out of the object.
func TestMaxAccess_MissingPathFallsBackToCeiling(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if got := maximalAccess(missing, false); got != accessFileAllAccess {
		t.Fatalf("mask for a vanished path = %#08x, want the ceiling %#08x", got, accessFileAllAccess)
	}
	if got := maximalAccess(missing, true); got != accessReadOnlyShare {
		t.Fatalf("read-only mask for a vanished path = %#08x, want %#08x", got, accessReadOnlyShare)
	}
}
