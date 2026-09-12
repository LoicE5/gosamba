package parent

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// The AAPL READ_DIR_ATTR overlay had two defects, both of them a constant where
// a per-entry answer belongs:
//
//  1. the 16 bytes of compressed Finder Info (ShortName[8..23]) were always
//     zero, although the server persists real Finder Info in the AFP_AfpInfo
//     stream. Apple's client sets FA_FINDERINFO_VALID from that field
//     unconditionally (smb_smb_2.c), so smbfs_attrlist.c then never asks for
//     the real thing: it copies the zeros onto the vnode and starts the cache
//     timer, and Finder can write them back. File type and creator, the
//     invisible bit, label colour and date-added all read back empty;
//  2. max_access (EaSize, offset 64) was the share-wide constant the CREATE
//     path had already stopped reporting, so a vnode macOS seeds from an
//     enumeration got a mask wider than the one a CREATE on the same file
//     would return.
//
// The record layout is fixed by MS-FSCC and Apple accumulates a fixed size per
// class, so these two fields had to change without moving a single other byte;
// TestDirEncode_AAPLRforkSizeUnchanged in fix_direncode_test.go is what holds
// the rest of the record to the pre-fix encoder.

// --- helpers -----------------------------------------------------------------

// Offsets within a FILE_ID_BOTH_DIR_INFORMATION record carrying the overlay.
const (
	aaplRecFixed     = 104
	aaplRecNameLen   = 60
	aaplRecMaxAccess = 64
	aaplRecRfork     = 70
	aaplRecFinder    = 78
	aaplRecUnixMode  = 94
)

// finderInfoBlob builds a 32-byte FinderInfo exactly as macOS stores one: the
// head (type+creator for a file, the Finder window rect for a folder), the
// Finder flags, then — in the extended half — the date added and the extended
// Finder flags, each at the offset Apple's "Normal Finder Info and Extended
// Finder Info" layout in smb_2.h puts it. Multi-byte fields are big-endian,
// which is how a Mac writes them to disk.
func finderInfoBlob(head []byte, flags, extFlags uint16, dateAdded uint32) [32]byte {
	var fi [32]byte
	copy(fi[0:8], head)
	binary.BigEndian.PutUint16(fi[8:], flags)
	binary.BigEndian.PutUint32(fi[20:], dateAdded)
	binary.BigEndian.PutUint16(fi[24:], extFlags)
	return fi
}

// afpInfoWith wraps a FinderInfo in a valid 60-byte AFP_AfpInfo blob, the way a
// macOS client writes one to the AFP_AfpInfo stream.
func afpInfoWith(fi [32]byte) []byte {
	blob := synthAFPInfo()
	copy(blob[16:], fi[:])
	return blob
}

// writeFinderInfo stores fi as path's AFP_AfpInfo stream, skipping the test on
// a filesystem that cannot hold xattrs at all.
func writeFinderInfo(t *testing.T, path string, fi [32]byte) {
	t.Helper()
	if !xattrSupported(t, path) {
		t.Skip("filesystem does not support user xattrs")
	}
	if err := writeStreamXattr(path, afpInfoStreamName, afpInfoWith(fi)); err != nil {
		t.Skipf("writeStreamXattr(AFP_AfpInfo): %v", err)
	}
}

// finderListing encodes a whole directory through the real AAPL path and
// returns each entry's record (its fixed part) by name.
func finderListing(t *testing.T, dir string, readOnly bool) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	open := &Open{Path: dir, IsDir: true, dirEntries: entries}
	if readOnly {
		sess := &Session{}
		open.Tree = sess.AddTree(config.ShareConfig{Name: "share", Path: dir, ReadOnly: true})
	}
	buf, consumed, encoded, err := encodeDirEntriesLimited(
		open, 1<<20, smb2.InfoFileIdBothDirectoryInformation, len(entries), true)
	if err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	}
	if encoded != len(entries) || consumed != len(entries) {
		t.Fatalf("(consumed, encoded) = (%d, %d), want (%d, %d)",
			consumed, encoded, len(entries), len(entries))
	}
	starts, names := dirEncWalkChain(t, buf, aaplRecFixed, aaplRecNameLen)
	out := make(map[string][]byte, len(names))
	for i, n := range names {
		out[n] = buf[starts[i] : starts[i]+aaplRecFixed]
	}
	return out
}

// --- defect 1: real Finder Info on the wire ----------------------------------

// TestFinderInfo_FileRecordCarriesStoredFinderInfo proves a file whose
// AFP_AfpInfo stream holds real Finder Info reports it in the record, in the
// order and byte order Apple's parser expects.
//
// smb_smb_2.c parses a FILE's compressed Finder Info as
//
//	type(4) creator(4) finder_flags(2) finder_ext_flags(2) date_added(4)
//
// reading each field little-endian and memcpy-ing the parsed struct straight
// into fa_finder_info, which userland consumes as a native big-endian
// FinderInfo. An le read followed by a native store on a little-endian host
// preserves the bytes, so each field must appear on the wire in exactly the
// byte order it has on disk — which is what this decodes back out.
func TestFinderInfo_FileRecordCarriesStoredFinderInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.txt")
	if err := os.WriteFile(path, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	const (
		flags     = uint16(0x4000) // kIsInvisible
		extFlags  = uint16(0x0010)
		dateAdded = uint32(0x5F0A1B2C)
	)
	writeFinderInfo(t, path, finderInfoBlob([]byte("TEXTttxt"), flags, extFlags, dateAdded))

	rec := finderListing(t, dir, false)["doc.txt"]
	if rec == nil {
		t.Fatal("doc.txt missing from the listing")
	}
	fi := rec[aaplRecFinder : aaplRecFinder+16]

	if got := string(fi[0:4]); got != "TEXT" {
		t.Errorf("finder type = %q, want %q", got, "TEXT")
	}
	if got := string(fi[4:8]); got != "ttxt" {
		t.Errorf("finder creator = %q, want %q", got, "ttxt")
	}
	if got := binary.BigEndian.Uint16(fi[8:]); got != flags {
		t.Errorf("finder flags = %#04x, want %#04x (the invisible bit is lost)", got, flags)
	}
	if got := binary.BigEndian.Uint16(fi[10:]); got != extFlags {
		t.Errorf("extended finder flags = %#04x, want %#04x", got, extFlags)
	}
	if got := binary.BigEndian.Uint32(fi[12:]); got != dateAdded {
		t.Errorf("date added = %#08x, want %#08x", got, dateAdded)
	}

	// Nothing outside the 16-byte field may have moved: the resource fork size
	// that shares ShortName with it is still zero, and so is the pad byte pair
	// before the UNIX mode.
	if size := binary.LittleEndian.Uint64(rec[aaplRecRfork:]); size != 0 {
		t.Errorf("rfork size = %d, want 0 — Finder Info overran ShortName[0..7]", size)
	}
	if mode := binary.LittleEndian.Uint16(rec[aaplRecUnixMode:]); mode&0o777 != 0o644 {
		t.Errorf("unix mode = %#o, want 0644 — Finder Info overran Reserved2", mode&0o777)
	}
}

// TestFinderInfo_FolderRecordCarriesStoredFinderInfo does the same for the
// FOLDER layout, which Apple parses as
//
//	reserved1(8) finder_flags(2) finder_ext_flags(2) date_added(4)
//
// The first eight bytes are a folder's Finder window rect rather than a
// type/creator pair, and are carried through verbatim like every other field.
func TestFinderInfo_FolderRecordCarriesStoredFinderInfo(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "folder")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// A Finder window rect (top, left, bottom, right), big-endian like the
	// rest of the blob.
	var rect [8]byte
	binary.BigEndian.PutUint16(rect[0:], 40)
	binary.BigEndian.PutUint16(rect[2:], 60)
	binary.BigEndian.PutUint16(rect[4:], 400)
	binary.BigEndian.PutUint16(rect[6:], 600)
	const (
		flags     = uint16(0x0100) // kHasBeenInited
		extFlags  = uint16(0x0002)
		dateAdded = uint32(0x600D_F00D)
	)
	writeFinderInfo(t, sub, finderInfoBlob(rect[:], flags, extFlags, dateAdded))

	rec := finderListing(t, dir, false)["folder"]
	if rec == nil {
		t.Fatal("folder missing from the listing")
	}
	fi := rec[aaplRecFinder : aaplRecFinder+16]

	if got := binary.BigEndian.Uint64(fi[0:]); got != binary.BigEndian.Uint64(rect[:]) {
		t.Errorf("folder reserved1 = %#016x, want the stored window rect %#016x",
			got, binary.BigEndian.Uint64(rect[:]))
	}
	if got := binary.BigEndian.Uint16(fi[8:]); got != flags {
		t.Errorf("folder finder flags = %#04x, want %#04x", got, flags)
	}
	if got := binary.BigEndian.Uint16(fi[10:]); got != extFlags {
		t.Errorf("folder extended finder flags = %#04x, want %#04x", got, extFlags)
	}
	if got := binary.BigEndian.Uint32(fi[12:]); got != dateAdded {
		t.Errorf("folder date added = %#08x, want %#08x", got, dateAdded)
	}
	// A directory has no resource fork and the encoder must not probe for one.
	if size := binary.LittleEndian.Uint64(rec[aaplRecRfork:]); size != 0 {
		t.Errorf("folder rfork size = %d, want 0", size)
	}
}

// TestFinderInfo_NoStreamShipsZeros proves an entry with no AFP_AfpInfo stream
// (and one whose stream is too short to hold a FinderInfo) still reports zeros.
// That is the honest answer — the server knows nothing about the entry's Finder
// Info — and it is what the field held before this change.
func TestFinderInfo_NoStreamShipsZeros(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	short := filepath.Join(dir, "short.txt")
	for _, p := range []string{plain, short} {
		if err := os.WriteFile(p, []byte("body"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if xattrSupported(t, short) {
		// A truncated blob carries no FinderInfo: it must read as "none",
		// not as whatever bytes happen to follow.
		if err := writeStreamXattr(short, afpInfoStreamName, synthAFPInfo()[:20]); err != nil {
			t.Skipf("writeStreamXattr: %v", err)
		}
	}

	recs := finderListing(t, dir, false)
	for _, name := range []string{"plain.txt", "short.txt"} {
		rec := recs[name]
		if rec == nil {
			t.Fatalf("%s missing from the listing", name)
		}
		for i, b := range rec[aaplRecFinder : aaplRecFinder+16] {
			if b != 0 {
				t.Fatalf("%s: finder info byte %d = %#02x, want 0 for an entry with no stored blob",
					name, i, b)
			}
		}
	}
}

// TestFinderInfo_OverlongBlobStillReported proves the fast one-syscall read
// falls back correctly when a client has stored an AFP_AfpInfo stream longer
// than the canonical 60 bytes: the Finder Info is still reported rather than
// silently dropped by the ERANGE the fixed-size buffer would take.
func TestFinderInfo_OverlongBlobStillReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "long.txt")
	if err := os.WriteFile(path, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, path) {
		t.Skip("filesystem does not support user xattrs")
	}
	fi := finderInfoBlob([]byte("TEXTttxt"), 0x4000, 0, 0)
	blob := append(afpInfoWith(fi), make([]byte, 40)...) // 100 bytes
	if err := writeStreamXattr(path, afpInfoStreamName, blob); err != nil {
		t.Skipf("writeStreamXattr: %v", err)
	}

	rec := finderListing(t, dir, false)["long.txt"]
	if rec == nil {
		t.Fatal("long.txt missing from the listing")
	}
	if got := string(rec[aaplRecFinder : aaplRecFinder+4]); got != "TEXT" {
		t.Fatalf("finder type from a 100-byte AFP_AfpInfo = %q, want %q", got, "TEXT")
	}
}

// --- defect 2: per-entry max_access ------------------------------------------

// TestFinderInfo_MaxAccessIsPerEntry proves each record reports the access mask
// of its OWN file rather than the share-wide constant: a 0444 file carries no
// write bits, a 0755 file carries FILE_EXECUTE and a 0644 file does not.
func TestFinderInfo_MaxAccessIsPerEntry(t *testing.T) {
	skipIfRoot(t)

	dir := t.TempDir()
	for name, mode := range map[string]os.FileMode{
		"ro.txt":   0o444,
		"rw.txt":   0o644,
		"exec.txt": 0o755,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("body"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // defeat umask
			t.Fatal(err)
		}
	}

	recs := finderListing(t, dir, false)
	access := func(name string) uint32 {
		rec := recs[name]
		if rec == nil {
			t.Fatalf("%s missing from the listing", name)
		}
		return binary.LittleEndian.Uint32(rec[aaplRecMaxAccess:])
	}

	if got := access("ro.txt"); got&accessWriteBits != 0 {
		t.Errorf("0444 file max_access = %#08x still reports write bits %#08x",
			got, got&accessWriteBits)
	}
	if got := access("ro.txt"); got&accFileReadData == 0 {
		t.Errorf("0444 file max_access = %#08x lost FILE_READ_DATA", got)
	}
	if got := access("rw.txt"); got&accessWriteBits == 0 {
		t.Errorf("0644 file max_access = %#08x reports no write access", got)
	}
	if got := access("rw.txt"); got&accFileExecute != 0 {
		t.Errorf("0644 file max_access = %#08x reports FILE_EXECUTE", got)
	}
	if got := access("exec.txt"); got&accFileExecute == 0 {
		t.Errorf("0755 file max_access = %#08x reports no FILE_EXECUTE", got)
	}
	// The whole point: the three entries do not all report the same mask.
	if access("ro.txt") == access("rw.txt") {
		t.Errorf("0444 and 0644 report the same mask %#08x — still a constant", access("ro.txt"))
	}
	for name := range recs {
		if got := access(name); got == 0 {
			t.Errorf("%s reports max_access 0", name)
		}
	}
}

// TestFinderInfo_ReadOnlyShareNeverReportsWrite proves the share ceiling still
// bounds the per-entry mask: a 0777 file on a read-only share reports no write
// right at all, and still reports something non-zero.
func TestFinderInfo_ReadOnlyShareNeverReportsWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wide.txt")
	if err := os.WriteFile(p, []byte("body"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir")
	if err := os.Mkdir(sub, 0o777); err != nil {
		t.Fatal(err)
	}

	for name, rec := range finderListing(t, dir, true) {
		got := binary.LittleEndian.Uint32(rec[aaplRecMaxAccess:])
		if got&accessWriteBits != 0 {
			t.Errorf("%s on a read-only share reports write bits: %#08x", name, got)
		}
		if got == 0 {
			t.Errorf("%s on a read-only share reports max_access 0", name)
		}
		if got&^accessReadOnlyShare != 0 {
			t.Errorf("%s reports %#08x, outside the read-only ceiling %#08x",
				name, got, accessReadOnlyShare)
		}
	}
}

// TestFinderInfo_MaxAccessNeverZero pins the one value the field may never
// take. Apple reads a zero EaSize in this overlay as "this server thinks we are
// Windows" (smbfs_smb_2.c) and it is the documented cause of every folder
// showing as access denied, so a probe that somehow answers zero must fall back
// to the share ceiling instead of being reported.
func TestFinderInfo_MaxAccessNeverZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file the server genuinely cannot touch at all must still not report 0.
	deny := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(deny, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(deny, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(deny, 0o600) })

	for _, readOnly := range []bool{false, true} {
		for name, rec := range finderListing(t, dir, readOnly) {
			if got := binary.LittleEndian.Uint32(rec[aaplRecMaxAccess:]); got == 0 {
				t.Fatalf("%s (readOnly=%v) reports max_access 0", name, readOnly)
			}
		}
	}

	// And when the probe itself answers zero — it cannot today, but the field
	// must not depend on that — the share ceiling is what goes on the wire.
	orig := entryAccessMask
	entryAccessMask = func(os.FileInfo, posixIdentity, bool) uint32 { return 0 }
	t.Cleanup(func() { entryAccessMask = orig })
	for _, tc := range []struct {
		readOnly bool
		want     uint32
	}{{false, accessFileAllAccess}, {true, accessReadOnlyShare}} {
		for name, rec := range finderListing(t, dir, tc.readOnly) {
			got := binary.LittleEndian.Uint32(rec[aaplRecMaxAccess:])
			if got != tc.want {
				t.Fatalf("%s (readOnly=%v): a zero probe reported %#08x, want the ceiling %#08x",
					name, tc.readOnly, got, tc.want)
			}
		}
	}
}

// --- the fit check must still come first -------------------------------------

// countingProbes replaces the three pieces of per-entry work with counting
// stubs and returns the counters. Two of them are syscalls this fix added to
// the per-entry path, so "does an entry that will not fit pay for them?" is the
// question the ordering has to keep answering with no.
func countingProbes(t testing.TB, access, rfork, finder *int) {
	t.Helper()
	origAccess, origRfork, origFinder := entryAccessMask, entryRforkSize, entryFinderInfo
	entryAccessMask = func(os.FileInfo, posixIdentity, bool) uint32 {
		*access++
		return accessFileAllAccess
	}
	entryRforkSize = func(string, string) (int, error) { *rfork++; return 0, nil }
	entryFinderInfo = func(string) ([finderInfoSize]byte, bool) {
		*finder++
		return [finderInfoSize]byte{}, false
	}
	t.Cleanup(func() {
		entryAccessMask, entryRforkSize, entryFinderInfo = origAccess, origRfork, origFinder
	})
}

// TestFinderInfo_EntryThatDoesNotFitCostsNoProbe proves the per-entry syscalls
// this fix added sit AFTER the fit check: an entry left for the next
// QUERY_DIRECTORY costs no faccessat, no Finder Info read and no resource-fork
// sizing, because it would be probed twice and reported once.
func TestFinderInfo_EntryThatDoesNotFitCostsNoProbe(t *testing.T) {
	var access, rfork, finder int
	countingProbes(t, &access, &rfork, &finder)

	// dirEncEntries uses four-character names, so with the 104-byte fixed part
	// every record is exactly 112 bytes.
	const recLen = aaplRecFixed + 8
	stats := 0
	entries := dirEncEntries(10, &stats)
	for _, fit := range []int{1, 2, 7} {
		access, rfork, finder, stats = 0, 0, 0, 0
		open := dirEncOpen(entries, 0)
		_, consumed, encoded, err := encodeDirEntriesLimited(
			open, fit*recLen, smb2.InfoFileIdBothDirectoryInformation, len(entries), true)
		if err != nil {
			t.Fatalf("encodeDirEntriesLimited: %v", err)
		}
		if encoded != fit || consumed != fit {
			t.Fatalf("buffer for %d records encoded %d, consumed %d", fit, encoded, consumed)
		}
		if access != fit || rfork != fit || finder != fit {
			t.Fatalf("buffer for %d records: %d access checks, %d rfork probes, %d finder reads — want %d each",
				fit, access, rfork, finder, fit)
		}
		if stats != fit {
			t.Fatalf("buffer for %d records performed %d stats, want %d", fit, stats, fit)
		}
	}

	// One byte short of the first record: not a single probe, and nothing
	// encoded.
	access, rfork, finder, stats = 0, 0, 0, 0
	_, consumed, encoded, err := encodeDirEntriesLimited(
		dirEncOpen(entries, 0), recLen-1, smb2.InfoFileIdBothDirectoryInformation, len(entries), true)
	if err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	}
	if encoded != 0 || consumed != 0 {
		t.Fatalf("(consumed, encoded) = (%d, %d), want (0, 0)", consumed, encoded)
	}
	if access+rfork+finder+stats != 0 {
		t.Fatalf("an entry that does not fit cost %d access checks, %d rfork probes, %d finder reads, %d stats",
			access, rfork, finder, stats)
	}
}

// TestFinderInfo_NonAAPLListingProbesNothing proves the probes are confined to
// the overlay: a plain (non-AAPL) listing makes none of them, so no Windows or
// Linux client pays for Apple's fields.
func TestFinderInfo_NonAAPLListingProbesNothing(t *testing.T) {
	var access, rfork, finder int
	countingProbes(t, &access, &rfork, &finder)
	for _, c := range dirEncAllClasses {
		access, rfork, finder = 0, 0, 0
		if _, _, _, err := encodeDirEntriesLimited(
			dirEncOpen(dirEncEntries(50, nil), 0), 1<<20, c.class, 50, false); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if access+rfork+finder != 0 {
			t.Fatalf("%s without AAPL: %d access checks, %d rfork probes, %d finder reads",
				c.name, access, rfork, finder)
		}
	}
}

// --- the listing must not ask the kernel about permissions --------------------

// TestFinderInfo_MaskComesFromTheStatNotTheFilesystem is the mechanical proof
// that the listing path performs no faccessat (or any other permission
// syscall): the entries carry the REAL stat of real files, but open.Path points
// at a directory that does not exist, so every path built from it is a dangling
// one.
//
// Any implementation that asked the kernel would get ENOENT for all three
// entries. ENOENT is not a permission answer, so maximalAccess-style code falls
// back to the share ceiling and all three masks come out identical — which is
// exactly what this test fails on. Masks that still differ by mode can only
// have come from the stat the encoder already had.
func TestFinderInfo_MaskComesFromTheStatNotTheFilesystem(t *testing.T) {
	skipIfRoot(t)

	dir := t.TempDir()
	modes := map[string]os.FileMode{"ro.txt": 0o444, "rw.txt": 0o644, "exec.txt": 0o755}
	entries := make([]os.DirEntry, 0, len(modes))
	for name, mode := range modes {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("body"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, dirEncEntry{name: name, info: info})
	}

	// Nothing under this path exists.
	open := &Open{Path: filepath.Join(dir, "no-such-directory"), IsDir: true, dirEntries: entries}
	buf, _, encoded, err := encodeDirEntriesLimited(
		open, 1<<20, smb2.InfoFileIdBothDirectoryInformation, len(entries), true)
	if err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	}
	if encoded != len(entries) {
		t.Fatalf("encoded %d of %d entries", encoded, len(entries))
	}
	starts, names := dirEncWalkChain(t, buf, aaplRecFixed, aaplRecNameLen)
	masks := make(map[string]uint32, len(names))
	for i, n := range names {
		masks[n] = binary.LittleEndian.Uint32(buf[starts[i]+aaplRecMaxAccess:])
	}

	if masks["ro.txt"]&accessWriteBits != 0 {
		t.Errorf("0444 entry = %#08x reports write bits — the mask came from the filesystem, not the stat",
			masks["ro.txt"])
	}
	if masks["rw.txt"]&accessWriteBits == 0 {
		t.Errorf("0644 entry = %#08x reports no write access", masks["rw.txt"])
	}
	if masks["rw.txt"]&accFileExecute != 0 {
		t.Errorf("0644 entry = %#08x reports FILE_EXECUTE", masks["rw.txt"])
	}
	if masks["exec.txt"]&accFileExecute == 0 {
		t.Errorf("0755 entry = %#08x reports no FILE_EXECUTE", masks["exec.txt"])
	}
	// The tell-tale of a permission syscall on a dangling path: ENOENT is not a
	// permission answer, so the probe falls back to the ceiling and all three
	// masks come back identical. A 0755 file legitimately IS the ceiling, so
	// the check is that the three differ and that the two narrowed ones really
	// were narrowed.
	if masks["ro.txt"] == masks["rw.txt"] || masks["rw.txt"] == masks["exec.txt"] {
		t.Errorf("masks are indistinguishable (0444=%#08x, 0644=%#08x, 0755=%#08x): the filesystem answered, not the stat",
			masks["ro.txt"], masks["rw.txt"], masks["exec.txt"])
	}
	for _, n := range []string{"ro.txt", "rw.txt"} {
		if masks[n] == accessFileAllAccess {
			t.Errorf("%s = %#08x is the untouched share ceiling: a permission syscall answered this",
				n, masks[n])
		}
	}
}

// TestFinderInfo_AccessMaskFollowsThePosixTriads pins the rule the derivation
// implements, against identities the test process does not run as: the OWNER
// triad when the uid matches, the GROUP triad when the file's group is one of
// ours (primary or supplementary), the OTHER triad otherwise — exactly one of
// them, never the union. A test that only ever stats its own files cannot reach
// the last two cases, so the identity is stood in here.
func TestFinderInfo_AccessMaskFollowsThePosixTriads(t *testing.T) {
	const (
		fileUID = uint32(4242)
		fileGID = uint32(777)
	)
	// 0641: owner rw-, group r--, other --x. Every triad differs, so the wrong
	// one cannot look right by accident.
	info := newStatFileInfo(0o641, fileUID, fileGID)

	for _, tc := range []struct {
		name                 string
		id                   posixIdentity
		read, write, execute bool
	}{
		{"owner", posixIdentity{uid: fileUID, gid: 1}, true, true, false},
		{"primary-group", posixIdentity{uid: 1, gid: fileGID}, true, false, false},
		{"supplementary-group", posixIdentity{uid: 1, gid: 2, groups: []uint32{9, fileGID}}, true, false, false},
		{"other", posixIdentity{uid: 1, gid: 2, groups: []uint32{9}}, false, false, true},
		{"root", posixIdentity{uid: 0, gid: 0, root: true}, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dirEntryAccessMask(info, tc.id, false)
			if (got&accFileReadData != 0) != tc.read {
				t.Errorf("mask %#08x: FILE_READ_DATA = %v, want %v", got, got&accFileReadData != 0, tc.read)
			}
			if (got&accessWriteBits != 0) != tc.write {
				t.Errorf("mask %#08x: write bits = %v, want %v", got, got&accessWriteBits != 0, tc.write)
			}
			if (got&accFileExecute != 0) != tc.execute {
				t.Errorf("mask %#08x: FILE_EXECUTE = %v, want %v", got, got&accFileExecute != 0, tc.execute)
			}
			if got == 0 {
				t.Errorf("%s identity produced a zero mask", tc.name)
			}
			// The share ceiling still caps everything.
			if ro := dirEntryAccessMask(info, tc.id, true); ro&accessWriteBits != 0 || ro&^accessReadOnlyShare != 0 {
				t.Errorf("read-only share mask %#08x escapes the ceiling %#08x", ro, accessReadOnlyShare)
			}
		})
	}

	// A FileInfo with no stat behind it has nothing to narrow with: the ceiling
	// is the answer, and it is never zero.
	if got := dirEntryAccessMask(dirEncFileInfo{name: "x"}, posixIdentity{uid: 1}, false); got != accessFileAllAccess {
		t.Errorf("statless FileInfo mask = %#08x, want the ceiling %#08x", got, accessFileAllAccess)
	}
	if got := dirEntryAccessMask(nil, posixIdentity{uid: 1}, true); got != accessReadOnlyShare {
		t.Errorf("nil FileInfo mask = %#08x, want the read-only ceiling %#08x", got, accessReadOnlyShare)
	}
}

// TestFinderInfo_IdentityIsReadOncePerResponse proves the credential lookup is
// amortised over the whole response rather than paid per entry — and that a
// listing without the Apple overlay does not pay it at all. The privilege drop
// happens in-process, which is why the identity is re-read per response instead
// of being cached in a package variable.
func TestFinderInfo_IdentityIsReadOncePerResponse(t *testing.T) {
	calls := 0
	orig := currentPosixIdentity
	currentPosixIdentity = func() posixIdentity {
		calls++
		return orig()
	}
	t.Cleanup(func() { currentPosixIdentity = orig })

	entries := dirEncEntries(200, nil)
	if _, _, encoded, err := encodeDirEntriesLimited(
		dirEncOpen(entries, 0), 1<<20, smb2.InfoFileIdBothDirectoryInformation, len(entries), true); err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	} else if encoded != len(entries) {
		t.Fatalf("encoded %d of %d entries", encoded, len(entries))
	}
	if calls != 1 {
		t.Fatalf("identity read %d times for one response of %d records, want 1", calls, len(entries))
	}

	calls = 0
	if _, _, _, err := encodeDirEntriesLimited(
		dirEncOpen(entries, 0), 1<<20, smb2.InfoFileIdBothDirectoryInformation, len(entries), false); err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	}
	if calls != 0 {
		t.Fatalf("a non-AAPL listing read the identity %d times, want 0", calls)
	}
}

// statFileInfo is an os.FileInfo carrying a syscall.Stat_t, so the derivation
// can be driven with owners the test process could not create files for. The
// stat is built once and handed out by pointer, exactly as os.Lstat's FileInfo
// does — a double that allocated per Sys() call would put an allocation into
// the benchmark that production never makes.
type statFileInfo struct {
	mode os.FileMode
	st   *syscall.Stat_t
}

func newStatFileInfo(mode os.FileMode, uid, gid uint32) statFileInfo {
	return statFileInfo{mode: mode, st: &syscall.Stat_t{Uid: uid, Gid: gid}}
}

func (f statFileInfo) Name() string       { return "x" }
func (f statFileInfo) Size() int64        { return 0 }
func (f statFileInfo) Mode() os.FileMode  { return f.mode }
func (f statFileInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (f statFileInfo) IsDir() bool        { return false }
func (f statFileInfo) Sys() any           { return f.st }

// --- benchmarks ---------------------------------------------------------------

// aaplBenchVariant selects how much of this fix the benchmark runs, so the
// remaining per-entry cost is attributable field by field.
type aaplBenchVariant int

const (
	// aaplBefore is the overlay as it stood before this fix: a share-wide
	// max_access constant and no Finder Info at all.
	aaplBefore aaplBenchVariant = iota
	// aaplFinderOnly adds only the AFP_AfpInfo read, so its distance from
	// aaplBefore is the isolated cost of actually having Finder Info.
	aaplFinderOnly
	// aaplFull is what the server does now: Finder Info plus the per-file
	// access mask derived from the stat the encoder already holds.
	aaplFull
)

// benchAAPLListing measures one full AAPL response out of a real directory —
// real files, real xattrs, so every per-entry syscall is actually paid.
// Everything except the selected variant is identical across the three, the
// resource-fork sizing included, so the differences are this change and nothing
// else.
//
//	go test ./internal/parent/ -run '^$' -bench BenchmarkAAPLDirListing
func benchAAPLListing(b *testing.B, maxBytes int, variant aaplBenchVariant) {
	b.Helper()
	dir := b.TempDir()
	// 2000 entries is more than fills a 64 KiB response (512 records) and
	// enough to make a 1 MiB one realistic.
	const entryCount = 2000
	for i := 0; i < entryCount; i++ {
		p := filepath.Join(dir, fmt.Sprintf("file%04d.txt", i))
		if err := os.WriteFile(p, []byte("body"), 0o644); err != nil {
			b.Fatal(err)
		}
		// Half the entries carry Finder Info, as a real Mac-served share does.
		if i%2 == 0 {
			fi := finderInfoBlob([]byte("TEXTttxt"), 0x4000, 0, uint32(i))
			if err := writeStreamXattr(p, afpInfoStreamName, afpInfoWith(fi)); err != nil {
				b.Skipf("filesystem cannot store the AFP_AfpInfo stream: %v", err)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		b.Fatal(err)
	}

	if variant != aaplFull {
		origAccess := entryAccessMask
		entryAccessMask = func(os.FileInfo, posixIdentity, bool) uint32 { return accessFileAllAccess }
		defer func() { entryAccessMask = origAccess }()
	}
	if variant == aaplBefore {
		origFinder := entryFinderInfo
		entryFinderInfo = func(string) ([finderInfoSize]byte, bool) { return [finderInfoSize]byte{}, false }
		defer func() { entryFinderInfo = origFinder }()
	}

	const class = smb2.InfoFileIdBothDirectoryInformation
	_, _, records, err := encodeDirEntriesLimited(
		&Open{Path: dir, IsDir: true, dirEntries: entries}, maxBytes, class, len(entries), true)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := encodeDirEntriesLimited(
			&Open{Path: dir, IsDir: true, dirEntries: entries}, maxBytes, class, len(entries), true); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(records), "records/response")
}

// BenchmarkDirEntryAccessMask prices the per-file access mask on its own. The
// whole-listing benchmarks cannot resolve it — it sits below their noise floor,
// which is the point — so this is where its real cost is attributable:
// nanoseconds of arithmetic on a stat the encoder already holds, against the
// ~6 us a faccessat trio costs.
func BenchmarkDirEntryAccessMask(b *testing.B) {
	// Hoist the interface conversion: in the encoder info is ALREADY an
	// os.FileInfo, so boxing it here would charge the benchmark an allocation
	// the server never makes.
	var info os.FileInfo = newStatFileInfo(0o644, 4242, 777)
	id := posixIdentity{uid: 1, gid: 2, groups: []uint32{9, 777}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if dirEntryAccessMask(info, id, false) == 0 {
			b.Fatal("zero mask")
		}
	}
}

// 64 KiB is what macOS pins OutputBufferLength to — the size that matters here.
func BenchmarkAAPLDirListing_64KiB(b *testing.B)        { benchAAPLListing(b, 64<<10, aaplFull) }
func BenchmarkAAPLDirListing_64KiB_Finder(b *testing.B) { benchAAPLListing(b, 64<<10, aaplFinderOnly) }
func BenchmarkAAPLDirListing_64KiB_Before(b *testing.B) { benchAAPLListing(b, 64<<10, aaplBefore) }

func BenchmarkAAPLDirListing_1MiB(b *testing.B)        { benchAAPLListing(b, 1<<20, aaplFull) }
func BenchmarkAAPLDirListing_1MiB_Finder(b *testing.B) { benchAAPLListing(b, 1<<20, aaplFinderOnly) }
func BenchmarkAAPLDirListing_1MiB_Before(b *testing.B) { benchAAPLListing(b, 1<<20, aaplBefore) }
