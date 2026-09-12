package parent

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// TestF10_FsAttributesCaseSensitive pins the FileFsAttributeInformation bits.
//
// FILE_CASE_SENSITIVE_SEARCH (0x1) is NOT pinned here: it now tracks the
// share's backing filesystem, which differs between an ext4 CI runner and a
// default APFS/HFS+ macOS box. The bit's correctness is asserted against a
// probe of the real filesystem in fix_casesens_test.go; what this test still
// pins is that the unconditional bits are unchanged and that the conditional
// one agrees with shareCaseSensitive.
func TestF10_FsAttributesCaseSensitive(t *testing.T) {
	// A real directory: encodeFsInfo now probes the share's filesystem.
	dir := t.TempDir()
	o := &Open{
		Path: dir,
		Tree: &Tree{
			Share: config.ShareConfig{Name: "test", Path: dir},
		},
	}

	buf, ok := encodeFsInfo(smb2.FileFsAttributeInformation, o)
	if !ok {
		t.Fatal("encodeFsInfo FileFsAttributeInformation returned false")
	}
	if len(buf) < 4 {
		t.Fatalf("FileFsAttributeInformation buf too short: %d", len(buf))
	}

	fsAttrs := binary.LittleEndian.Uint32(buf[0:4])

	const (
		fileCasePreservedNames = 0x00000002
		fileUnicodeOnDisk      = 0x00000004
	)

	// Case-sensitive search is reported only when the filesystem really is.
	wantCase := shareCaseSensitive(o.Tree)
	if got := fsAttrs&fileCaseSensitiveSearch != 0; got != wantCase {
		t.Errorf("FILE_CASE_SENSITIVE_SEARCH = %v, want %v (probed); fsAttrs=0x%08X", got, wantCase, fsAttrs)
	}
	// Must also advertise case-preserved names (we never alter case on disk).
	if fsAttrs&fileCasePreservedNames == 0 {
		t.Errorf("FILE_CASE_PRESERVED_NAMES (0x2) should be set; fsAttrs=0x%08X", fsAttrs)
	}
	// Unicode on disk is expected too.
	if fsAttrs&fileUnicodeOnDisk == 0 {
		t.Errorf("FILE_UNICODE_ON_DISK (0x4) should be set; fsAttrs=0x%08X", fsAttrs)
	}
}

// TestF9_BirthTimeFileBasicInfo verifies that FileBasicInformation's
// CreationTime (offset 0) differs from ModTime when the path has a distinct
// btime, OR equals the ModTime fallback when btime is unavailable.
func TestF9_BirthTimeFileBasicInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "btime_basic.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	// Sleep briefly to ensure mtime and btime could differ.
	time.Sleep(10 * time.Millisecond)

	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	open := &Open{Path: path}
	buf, ok := encodeFileInfo(smb2.FileBasicInformation, st, open)
	if !ok {
		t.Fatal("encodeFileInfo FileBasicInformation failed")
	}
	if len(buf) != 40 {
		t.Fatalf("FileBasicInformation length: got %d, want 40", len(buf))
	}

	creationTime := binary.LittleEndian.Uint64(buf[0:8])
	modTime := binary.LittleEndian.Uint64(buf[16:24]) // LastWriteTime

	btime, btimeOK := birthTime(path)
	if !btimeOK {
		// btime unavailable: CreationTime must equal ModTime (fallback).
		if creationTime != modTime {
			t.Errorf("btime unavailable: CreationTime (0x%X) != ModTime (0x%X)", creationTime, modTime)
		}
		t.Log("F9: btime unavailable — fallback to ModTime verified")
		return
	}

	// btime available: CreationTime should be derived from btime.
	expected := filetimeFromTime(btime)
	if creationTime != expected {
		t.Errorf("F9: CreationTime = 0x%X, want btime-derived 0x%X", creationTime, expected)
	}
	t.Logf("F9: CreationTime from btime = %v", btime)
}
