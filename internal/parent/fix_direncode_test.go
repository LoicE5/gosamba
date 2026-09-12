package parent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"golang.org/x/sys/unix"
)

// The directory encoder had four defects that all cost CPU or syscalls per
// entry, none of which may change a single byte on the wire:
//
//  1. the NextEntryOffset chain was re-walked from the head of the buffer for
//     every record appended, making record linking quadratic in the number of
//     records in ONE response — ~2.8G list steps at the 8 MiB this server
//     advertises as MaxTransactSize;
//  2. the AAPL resource-fork probe read the entire fork into memory to call
//     len() on it;
//  3. the entry that straddles the end of the buffer was stat'ed, xattr-probed
//     and fully encoded before being discarded, then redone on the next call;
//  4. FILE_NAMES_INFORMATION stat'ed every entry although it encodes nothing
//     but the name.
//
// Record layout is fixed by MS-FSCC and Apple's parser accumulates a fixed size
// per class, so a one-byte drift is a silent corruption rather than an error.
// dirEncReferenceEncode below is the encoder exactly as it stood before the
// fix, and TestDirEncode_BytesMatchReferenceEncoder holds the new one to
// byte-for-byte equality with it.

// --- test doubles ------------------------------------------------------------

// dirEncFileInfo is an in-memory os.FileInfo so the encoder can be exercised
// (and benchmarked) without touching a filesystem.
type dirEncFileInfo struct {
	name string
	size int64
	mode os.FileMode
	mod  time.Time
}

func (f dirEncFileInfo) Name() string       { return f.name }
func (f dirEncFileInfo) Size() int64        { return f.size }
func (f dirEncFileInfo) Mode() os.FileMode  { return f.mode }
func (f dirEncFileInfo) ModTime() time.Time { return f.mod }
func (f dirEncFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f dirEncFileInfo) Sys() any           { return nil }

// dirEncEntry is an os.DirEntry whose Info() is counted, so a test can assert
// how many stats an encode actually performed. err != nil stands in for an
// entry unlinked between os.ReadDir and the encode.
type dirEncEntry struct {
	name  string
	info  os.FileInfo
	err   error
	stats *int
}

func (e dirEncEntry) Name() string { return e.name }
func (e dirEncEntry) IsDir() bool  { return e.info != nil && e.info.IsDir() }
func (e dirEncEntry) Type() os.FileMode {
	if e.info == nil {
		return 0
	}
	return e.info.Mode().Type()
}

func (e dirEncEntry) Info() (os.FileInfo, error) {
	if e.stats != nil {
		*e.stats++
	}
	if e.err != nil {
		return nil, e.err
	}
	return e.info, nil
}

// dirEncEntries builds n countable entries with fixed-width names, so every
// record for a given class is the same size and the arithmetic in the tests
// stays obvious. stats may be nil.
func dirEncEntries(n int, stats *int) []os.DirEntry {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	out := make([]os.DirEntry, n)
	base := time.Unix(1600000000, 0)
	for i := range out {
		// Four base-36 digits: 1.6M distinct fixed-width names. With the
		// 104-byte FILE_ID_BOTH fixed part that is a 112-byte record.
		name := string([]byte{
			digits[(i/46656)%36], digits[(i/1296)%36], digits[(i/36)%36], digits[i%36],
		})
		out[i] = dirEncEntry{
			name:  name,
			info:  dirEncFileInfo{name: name, size: int64(i), mod: base.Add(time.Duration(i) * time.Second)},
			stats: stats,
		}
	}
	return out
}

// dirEncAllClasses is every class encodeDirRecord can emit, with its fixed part
// and the offset of FileNameLength, for decoding records back out.
var dirEncAllClasses = []struct {
	name       string
	class      uint8
	fixed      int
	nameLenOff int
}{
	{"FileDirectoryInformation", smb2.InfoFileDirectoryInformation, 64, 60},
	{"FileFullDirectoryInformation", smb2.InfoFileFullDirectoryInformation, 68, 60},
	{"FileNamesInformation", smb2.InfoFileNamesInformation, 12, 8},
	{"FileBothDirectoryInformation", smb2.InfoFileBothDirectoryInformation, 94, 60},
	{"FileIdFullDirectoryInformation", smb2.InfoFileIdFullDirectoryInformation, 80, 60},
	{"FileIdBothDirectoryInformation", smb2.InfoFileIdBothDirectoryInformation, 104, 60},
}

// --- the pre-fix encoder, kept verbatim as a reference ------------------------

// dirEncReferenceEncode is encodeDirEntriesLimited exactly as it stood before
// the performance fix: it re-derives the previous record's start by walking the
// NextEntryOffset chain, reads the whole resource fork to take its length,
// stats every entry regardless of class, and fully encodes the entry that does
// not fit before throwing it away. It is here only so the new encoder can be
// held to byte-for-byte equality with it, and to give the benchmark a "before"
// number.
func dirEncReferenceEncode(open *Open, maxBytes int, infoClass uint8, limit int, useAAPL bool) (out []byte, consumed, encoded int, err error) {
	initial := maxBytes
	if initial > 64<<10 {
		initial = 64 << 10
	}
	if initial < 0 {
		initial = 0
	}
	out = make([]byte, 0, initial)
	maxAccess := uint32(0x001F01FF)
	if open.Tree != nil && open.Tree.Share.ReadOnly {
		maxAccess = 0x001200A9
	}
	for i := open.dirSent; i < len(open.dirEntries) && encoded < limit; i++ {
		ent := open.dirEntries[i]
		info, ierr := ent.Info()
		if ierr != nil || info == nil {
			consumed = i + 1 - open.dirSent
			continue
		}
		var rforkSize uint64
		if useAAPL && !info.IsDir() {
			if data, xerr := readStreamXattr(filepath.Join(open.Path, ent.Name()), rforkStreamName); xerr == nil {
				rforkSize = uint64(len(data))
			}
		}
		rec := encodeDirRecord(ent.Name(), info, infoClass, useAAPL, maxAccess, rforkSize)
		if rec == nil {
			return nil, 0, 0, errUnsupportedDirInfoClass
		}
		padded := rec
		if len(rec)%8 != 0 {
			padded = append(append([]byte{}, rec...), make([]byte, 8-len(rec)%8)...)
		}
		if len(out)+len(padded) > maxBytes {
			break
		}
		if encoded > 0 {
			prevStart := dirEncReferenceLastRecordStart(out)
			binary.LittleEndian.PutUint32(out[prevStart:], uint32(len(out)-prevStart))
		}
		out = append(out, padded...)
		encoded++
		consumed = i + 1 - open.dirSent
	}
	return out, consumed, encoded, nil
}

// dirEncReferenceLastRecordStart is the deleted lastRecordStart: the quadratic
// chain walk itself.
func dirEncReferenceLastRecordStart(buf []byte) int {
	off := 0
	for {
		next := binary.LittleEndian.Uint32(buf[off:])
		if next == 0 {
			return off
		}
		off += int(next)
	}
}

// --- chain walking ------------------------------------------------------------

// dirEncWalkChain follows the NextEntryOffset chain and returns each record's
// start offset and name. It fails the test on any malformed link, which is what
// a client's parser would see as a corrupt listing.
func dirEncWalkChain(t *testing.T, buf []byte, fixed, nameLenOff int) (starts []int, names []string) {
	t.Helper()
	if len(buf) == 0 {
		return nil, nil
	}
	off := 0
	for {
		if off < 0 || off+fixed > len(buf) {
			t.Fatalf("record start %d is outside the %d-byte buffer", off, len(buf))
		}
		if off%8 != 0 {
			t.Fatalf("record start %d is not 8-byte aligned", off)
		}
		nameLen := int(binary.LittleEndian.Uint32(buf[off+nameLenOff:]))
		if off+fixed+nameLen > len(buf) {
			t.Fatalf("record at %d claims a %d-byte name that overruns the buffer", off, nameLen)
		}
		raw := buf[off+fixed : off+fixed+nameLen]
		u16 := make([]uint16, 0, nameLen/2)
		for i := 0; i+1 < len(raw); i += 2 {
			u16 = append(u16, binary.LittleEndian.Uint16(raw[i:]))
		}
		names = append(names, string(utf16Runes(u16)))
		starts = append(starts, off)

		next := int(binary.LittleEndian.Uint32(buf[off:]))
		if next == 0 {
			return starts, names
		}
		if next <= 0 {
			t.Fatalf("record at %d has a non-advancing NextEntryOffset %d", off, next)
		}
		off += next
	}
}

// utf16Runes decodes UTF-16 code units without pulling in unicode/utf16, so the
// test does not share a decoder with anything in the package under test.
func utf16Runes(u []uint16) []rune {
	out := make([]rune, 0, len(u))
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000 {
			out = append(out, 0x10000+(rune(c)-0xD800)<<10+(rune(u[i+1])-0xDC00))
			i++
			continue
		}
		out = append(out, rune(c))
	}
	return out
}

func dirEncOpen(entries []os.DirEntry, sent int) *Open {
	return &Open{Path: "/nonexistent", IsDir: true, dirEntries: entries, dirSent: sent}
}

// --- defect 1: record linking must be correct and constant-time ---------------

// TestDirEncode_ChainIsCorrectlyLinked walks the emitted NextEntryOffset chain
// for every class and every buffer size and proves it visits exactly the
// records that were encoded, in order, with a zero terminator on the last one.
// Linking is now done from a local carried across iterations instead of by
// re-walking the chain, so this is the property that change must preserve.
func TestDirEncode_ChainIsCorrectlyLinked(t *testing.T) {
	for _, c := range dirEncAllClasses {
		for _, n := range []int{1, 2, 3, 17, 500} {
			for _, maxBytes := range []int{1 << 12, 64 << 10, 1 << 20} {
				t.Run(fmt.Sprintf("%s/n=%d/buf=%d", c.name, n, maxBytes), func(t *testing.T) {
					open := dirEncOpen(dirEncEntries(n, nil), 0)
					buf, _, encoded, err := encodeDirEntriesLimited(open, maxBytes, c.class, n, false)
					if err != nil {
						t.Fatalf("encodeDirEntriesLimited: %v", err)
					}
					if encoded == 0 {
						t.Fatalf("encoded 0 of %d entries into %d bytes", n, maxBytes)
					}
					starts, names := dirEncWalkChain(t, buf, c.fixed, c.nameLenOff)
					if len(starts) != encoded {
						t.Fatalf("chain visits %d records, encoder reported %d", len(starts), encoded)
					}
					// The last record must terminate the chain.
					last := starts[len(starts)-1]
					if next := binary.LittleEndian.Uint32(buf[last:]); next != 0 {
						t.Fatalf("last record NextEntryOffset = %d, want 0", next)
					}
					// Every other link must be that record's padded length.
					for i := 0; i+1 < len(starts); i++ {
						gotNext := int(binary.LittleEndian.Uint32(buf[starts[i]:]))
						wantNext := starts[i+1] - starts[i]
						if gotNext != wantNext {
							t.Fatalf("record %d NextEntryOffset = %d, want %d", i, gotNext, wantNext)
						}
						if wantNext%8 != 0 {
							t.Fatalf("record %d length %d is not 8-byte aligned", i, wantNext)
						}
					}
					// And the names must be the first `encoded` entries, in order.
					for i, name := range names {
						if want := open.dirEntries[i].Name(); name != want {
							t.Fatalf("record %d name = %q, want %q", i, name, want)
						}
					}
					if len(buf) > maxBytes {
						t.Fatalf("emitted %d bytes into a %d-byte buffer", len(buf), maxBytes)
					}
				})
			}
		}
	}
}

// --- the strongest guard: the bytes themselves may not move ------------------

// TestDirEncode_BytesMatchReferenceEncoder holds the rewritten encoder to
// byte-for-byte equality with the pre-fix implementation across every class,
// every entry count and a spread of buffer sizes chosen to land mid-record. The
// two counts it returns must match too: `consumed` drives the enumeration
// cursor, and a drift there shows up at the client as duplicated or missing
// files.
func TestDirEncode_BytesMatchReferenceEncoder(t *testing.T) {
	for _, c := range dirEncAllClasses {
		for _, n := range []int{0, 1, 2, 5, 64, 1000} {
			for _, maxBytes := range []int{0, 7, 64, 111, 112, 113, 1 << 10, 4001, 64 << 10, 1 << 20} {
				for _, limit := range []int{1, 3, n, n + 5} {
					if limit <= 0 {
						continue
					}
					name := fmt.Sprintf("%s/n=%d/buf=%d/limit=%d", c.name, n, maxBytes, limit)
					t.Run(name, func(t *testing.T) {
						got, gotConsumed, gotEncoded, gerr := encodeDirEntriesLimited(
							dirEncOpen(dirEncEntries(n, nil), 0), maxBytes, c.class, limit, false)
						want, wantConsumed, wantEncoded, werr := dirEncReferenceEncode(
							dirEncOpen(dirEncEntries(n, nil), 0), maxBytes, c.class, limit, false)
						if (gerr == nil) != (werr == nil) {
							t.Fatalf("err = %v, reference err = %v", gerr, werr)
						}
						if !bytes.Equal(got, want) {
							t.Fatalf("encoded %d bytes, reference encoded %d; first difference at %d",
								len(got), len(want), dirEncFirstDiff(got, want))
						}
						if gotConsumed != wantConsumed || gotEncoded != wantEncoded {
							t.Fatalf("(consumed, encoded) = (%d, %d), reference = (%d, %d)",
								gotConsumed, gotEncoded, wantConsumed, wantEncoded)
						}
					})
				}
			}
		}
	}
}

// TestDirEncode_BytesMatchReferenceMidEnumeration does the same from a non-zero
// dirSent, which is where every QUERY_DIRECTORY after the first one starts.
func TestDirEncode_BytesMatchReferenceMidEnumeration(t *testing.T) {
	entries := dirEncEntries(300, nil)
	for _, c := range dirEncAllClasses {
		for _, sent := range []int{1, 7, 299, 300} {
			for _, maxBytes := range []int{500, 64 << 10} {
				t.Run(fmt.Sprintf("%s/sent=%d/buf=%d", c.name, sent, maxBytes), func(t *testing.T) {
					got, gc, ge, _ := encodeDirEntriesLimited(
						dirEncOpen(entries, sent), maxBytes, c.class, len(entries)-sent, false)
					want, wc, we, _ := dirEncReferenceEncode(
						dirEncOpen(entries, sent), maxBytes, c.class, len(entries)-sent, false)
					if !bytes.Equal(got, want) {
						t.Fatalf("bytes differ at %d (len %d vs %d)", dirEncFirstDiff(got, want), len(got), len(want))
					}
					if gc != wc || ge != we {
						t.Fatalf("(consumed, encoded) = (%d, %d), reference = (%d, %d)", gc, ge, wc, we)
					}
				})
			}
		}
	}
}

func dirEncFirstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return min(len(a), len(b))
	}
	return -1
}

// TestDirEncode_FixedSizesMatchEncoder pins dirRecordFixedSize to what
// encodeDirRecord actually emits. The enumerator prices a record from these
// numbers before doing any I/O for it, so a drift here would either overrun
// OutputBufferLength or drop entries that would have fit.
func TestDirEncode_FixedSizesMatchEncoder(t *testing.T) {
	info := dirEncFileInfo{name: "x", mod: time.Unix(1, 0)}
	for _, c := range dirEncAllClasses {
		t.Run(c.name, func(t *testing.T) {
			got, ok := dirRecordFixedSize(c.class)
			if !ok {
				t.Fatalf("dirRecordFixedSize(%#x) reports unsupported", c.class)
			}
			if got != c.fixed {
				t.Fatalf("dirRecordFixedSize = %d, want %d (MS-FSCC)", got, c.fixed)
			}
			for _, name := range []string{"", "a", "hello.txt", "ünïcödé", "𝔘𝔫𝔦"} {
				rec := encodeDirRecord(name, info, c.class, false, 0x001F01FF, 0)
				if rec == nil {
					t.Fatalf("encodeDirRecord(%q) returned nil", name)
				}
				if want := got + utf16leLen(name); len(rec) != want {
					t.Fatalf("record for %q is %d bytes, fixed(%d)+name(%d) = %d",
						name, len(rec), got, utf16leLen(name), want)
				}
			}
		})
	}
	// Unsupported classes must be reported as such, in lockstep with
	// supportedDirInfoClass and with encodeDirRecord returning nil.
	for c := 0; c < 256; c++ {
		_, sized := dirRecordFixedSize(uint8(c))
		if sized != supportedDirInfoClass(uint8(c)) {
			t.Fatalf("class %#x: dirRecordFixedSize ok=%v, supportedDirInfoClass=%v",
				c, sized, supportedDirInfoClass(uint8(c)))
		}
		if rec := encodeDirRecord("x", info, uint8(c), false, 0, 0); (rec != nil) != sized {
			t.Fatalf("class %#x: encodeDirRecord non-nil=%v, dirRecordFixedSize ok=%v",
				c, rec != nil, sized)
		}
	}
}

// TestDirEncode_UTF16LenMatchesEncoder proves the name-length estimate the
// enumerator sizes records with is exactly what utf16leName produces, including
// for astral planes (surrogate pairs) and invalid UTF-8 (replacement runes).
func TestDirEncode_UTF16LenMatchesEncoder(t *testing.T) {
	names := []string{
		"", "a", "hello.txt", "ünïcödé", "日本語のファイル名",
		"𝔘𝔫𝔦𝔠𝔬𝔡𝔢", "emoji 🎉🎉", "\xff\xfe invalid utf8 \x80",
		string([]byte{0xed, 0xa0, 0x80}), // lone surrogate in UTF-8 form
	}
	for _, n := range names {
		if got, want := utf16leLen(n), len(utf16leName(n)); got != want {
			t.Fatalf("utf16leLen(%q) = %d, utf16leName produced %d bytes", n, got, want)
		}
	}
}

// TestDirEncode_PadTo8 covers the alignment helper the fit check and the
// padding both rely on.
func TestDirEncode_PadTo8(t *testing.T) {
	for n, want := range map[int]int{0: 0, 1: 8, 7: 8, 8: 8, 9: 16, 104: 104, 111: 112, 112: 112, 113: 120} {
		if got := padTo8(n); got != want {
			t.Fatalf("padTo8(%d) = %d, want %d", n, got, want)
		}
	}
}

// --- defect 3: the entry that does not fit must not be pre-processed ---------

// TestDirEncode_OversizedEntryIsNotPreProcessed proves the entry that straddles
// the end of the buffer is left alone — not stat'ed, not encoded — and is
// re-offered on the next call. The pre-fix encoder did its lstat (and, under
// AAPL, its resource-fork read) and only then discovered it did not fit, so at
// 64 KiB per response a million-entry listing threw away ~1,700 stats.
func TestDirEncode_OversizedEntryIsNotPreProcessed(t *testing.T) {
	const class = smb2.InfoFileIdBothDirectoryInformation
	const recLen = 112 // 104 fixed + 4 UTF-16 code units, already 8-aligned
	const fit = 10

	newStats := 0
	open := dirEncOpen(dirEncEntries(50, &newStats), 0)
	buf, consumed, encoded, err := encodeDirEntriesLimited(open, fit*recLen, class, 50, false)
	if err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	}
	if encoded != fit || consumed != fit {
		t.Fatalf("(consumed, encoded) = (%d, %d), want (%d, %d)", consumed, encoded, fit, fit)
	}
	if len(buf) != fit*recLen {
		t.Fatalf("emitted %d bytes, want exactly %d", len(buf), fit*recLen)
	}
	if newStats != fit {
		t.Fatalf("encoder performed %d stats for %d records — the entry that did not fit was stat'ed anyway", newStats, fit)
	}

	// The pre-fix encoder is the regression witness: it stat'ed one entry more
	// than it emitted, every single response.
	refStats := 0
	_, _, refEncoded, _ := dirEncReferenceEncode(
		dirEncOpen(dirEncEntries(50, &refStats), 0), fit*recLen, class, 50, false)
	if refEncoded != fit {
		t.Fatalf("reference encoded %d records, want %d", refEncoded, fit)
	}
	if refStats != fit+1 {
		t.Fatalf("reference performed %d stats, expected the pre-fix %d (fit+1)", refStats, fit+1)
	}

	// And the entry that did not fit is re-offered, exactly once, next call.
	open.dirSent += consumed
	buf2, consumed2, encoded2, err := encodeDirEntriesLimited(open, fit*recLen, class, 50-open.dirSent, false)
	if err != nil {
		t.Fatalf("second encodeDirEntriesLimited: %v", err)
	}
	if encoded2 != fit || consumed2 != fit {
		t.Fatalf("second call (consumed, encoded) = (%d, %d), want (%d, %d)", consumed2, encoded2, fit, fit)
	}
	_, names := dirEncWalkChain(t, buf2, 104, 60)
	if names[0] != open.dirEntries[fit].Name() {
		t.Fatalf("second call starts at %q, want the entry that did not fit, %q",
			names[0], open.dirEntries[fit].Name())
	}
}

// TestDirEncode_BufferTooSmallForOneEntry proves a buffer that cannot hold even
// one record encodes nothing and consumes nothing, so the caller can answer
// STATUS_INFO_LENGTH_MISMATCH rather than silently truncating the listing.
func TestDirEncode_BufferTooSmallForOneEntry(t *testing.T) {
	for _, c := range dirEncAllClasses {
		t.Run(c.name, func(t *testing.T) {
			stats := 0
			open := dirEncOpen(dirEncEntries(5, &stats), 0)
			buf, consumed, encoded, err := encodeDirEntriesLimited(open, c.fixed-1, c.class, 5, false)
			if err != nil {
				t.Fatalf("encodeDirEntriesLimited: %v", err)
			}
			if len(buf) != 0 || consumed != 0 || encoded != 0 {
				t.Fatalf("got %d bytes, consumed %d, encoded %d; want all zero", len(buf), consumed, encoded)
			}
			if stats != 0 {
				t.Fatalf("stat'ed %d entries for a buffer that fits none", stats)
			}
		})
	}
}

// --- cursor semantics: consumed counts entries walked, not records emitted ---

// TestDirEncode_CursorCountsVanishedEntries proves an entry whose Info() fails
// is still counted as consumed, so open.dirSent keeps pace with the scan and
// the next call does not re-emit files the client already received. This is the
// invariant the whole consumed/encoded split exists for.
func TestDirEncode_CursorCountsVanishedEntries(t *testing.T) {
	// FILE_NAMES_INFORMATION is excluded on purpose: it no longer stats its
	// entries at all, so it has no vanished-entry path to exercise. See
	// TestDirEncode_NamesInformationNeedsNoStat.
	for _, c := range dirEncAllClasses {
		if c.class == smb2.InfoFileNamesInformation {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			entries := dirEncEntries(6, nil)
			// Two entries vanish: one mid-batch, one at the very end.
			entries[2] = dirEncEntry{name: "gho1", err: os.ErrNotExist}
			entries[5] = dirEncEntry{name: "gho2", err: os.ErrNotExist}

			// Whole listing in one go.
			open := dirEncOpen(entries, 0)
			buf, consumed, encoded, err := encodeDirEntriesLimited(open, 64<<10, c.class, len(entries), false)
			if err != nil {
				t.Fatalf("encodeDirEntriesLimited: %v", err)
			}
			if consumed != 6 {
				t.Fatalf("consumed = %d, want 6 (every entry walked, including the vanished ones)", consumed)
			}
			if encoded != 4 {
				t.Fatalf("encoded = %d, want 4", encoded)
			}
			_, names := dirEncWalkChain(t, buf, c.fixed, c.nameLenOff)
			want := []string{entries[0].Name(), entries[1].Name(), entries[3].Name(), entries[4].Name()}
			if fmt.Sprint(names) != fmt.Sprint(want) {
				t.Fatalf("names = %v, want %v", names, want)
			}

			// Byte-identical to the pre-fix encoder, counts included.
			refBuf, refConsumed, refEncoded, _ := dirEncReferenceEncode(
				dirEncOpen(entries, 0), 64<<10, c.class, len(entries), false)
			if !bytes.Equal(buf, refBuf) || consumed != refConsumed || encoded != refEncoded {
				t.Fatalf("diverged from reference: (%d, %d) vs (%d, %d), bytes equal=%v",
					consumed, encoded, refConsumed, refEncoded, bytes.Equal(buf, refBuf))
			}

			// Now drive it one record at a time, the way a client using
			// SMB2_RETURN_SINGLE_ENTRY does, and prove nothing is delivered
			// twice or skipped.
			var got []string
			open = dirEncOpen(entries, 0)
			for i := 0; i < 20 && open.dirSent < len(entries); i++ {
				b, cons, enc, err := encodeDirEntriesLimited(open, 64<<10, c.class, 1, false)
				if err != nil {
					t.Fatalf("iteration %d: %v", i, err)
				}
				if cons == 0 {
					t.Fatalf("iteration %d consumed nothing — the enumeration cannot progress", i)
				}
				open.dirSent += cons
				if enc > 0 {
					_, n := dirEncWalkChain(t, b, c.fixed, c.nameLenOff)
					got = append(got, n...)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("single-entry enumeration returned %v, want %v", got, want)
			}
		})
	}
}

// --- defect 4: FILE_NAMES_INFORMATION must not stat ---------------------------

// TestDirEncode_NamesInformationNeedsNoStat proves the names class encodes
// without calling Info() at all. FILE_NAMES_INFORMATION is NextEntryOffset +
// FileIndex + FileNameLength + the name (MS-FSCC §2.4.26); the stat filled in
// nothing, and cost one lstat per entry per listing.
func TestDirEncode_NamesInformationNeedsNoStat(t *testing.T) {
	stats := 0
	entries := dirEncEntries(200, &stats)
	// Every entry's Info() also fails, so a stat would additionally drop them.
	for i := range entries {
		e := entries[i].(dirEncEntry)
		e.err = os.ErrNotExist
		e.info = nil
		entries[i] = e
	}
	open := dirEncOpen(entries, 0)
	buf, consumed, encoded, err := encodeDirEntriesLimited(open, 1<<20, smb2.InfoFileNamesInformation, len(entries), false)
	if err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	}
	if stats != 0 {
		t.Fatalf("FILE_NAMES_INFORMATION performed %d stats, want 0", stats)
	}
	if encoded != len(entries) || consumed != len(entries) {
		t.Fatalf("(consumed, encoded) = (%d, %d), want (%d, %d)", consumed, encoded, len(entries), len(entries))
	}
	_, names := dirEncWalkChain(t, buf, 12, 8)
	for i, n := range names {
		if want := entries[i].Name(); n != want {
			t.Fatalf("record %d name = %q, want %q", i, n, want)
		}
	}

	// The stat-bearing classes still stat, once per entry.
	stats = 0
	_, _, _, err = encodeDirEntriesLimited(dirEncOpen(dirEncEntries(200, &stats), 0),
		1<<20, smb2.InfoFileIdBothDirectoryInformation, 200, false)
	if err != nil {
		t.Fatalf("encodeDirEntriesLimited: %v", err)
	}
	if stats != 200 {
		t.Fatalf("FILE_ID_BOTH_DIR_INFORMATION performed %d stats for 200 entries, want 200", stats)
	}
}

// --- defect 2: the resource-fork probe must not read the fork ----------------

// TestDirEncode_StreamXattrSizeMatchesRead proves the size-only probe reports
// exactly what the full read would have measured, for an absent stream, an
// empty one and a large one. The encoder only ever wanted len(); reading a
// multi-megabyte resource fork into memory per directory entry to get it was
// the whole defect.
func TestDirEncode_StreamXattrSizeMatchesRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, path) {
		t.Skip("filesystem does not support user xattrs")
	}

	// Absent stream: both report zero, neither reports an error.
	data, rerr := readStreamXattr(path, rforkStreamName)
	n, serr := streamXattrSize(path, rforkStreamName)
	if rerr != nil || serr != nil {
		t.Fatalf("absent stream: read err = %v, size err = %v", rerr, serr)
	}
	if len(data) != 0 || n != 0 {
		t.Fatalf("absent stream: read %d bytes, size reported %d", len(data), n)
	}

	for _, size := range []int{0, 1, 37, 64 << 10} {
		payload := bytes.Repeat([]byte{0xAB}, size)
		if err := writeStreamXattr(path, rforkStreamName, payload); err != nil {
			if errors.Is(err, errXattrUnsupported) || errors.Is(err, unix.E2BIG) || errors.Is(err, unix.ENOSPC) {
				t.Skipf("filesystem will not hold a %d-byte xattr: %v", size, err)
			}
			t.Fatalf("writeStreamXattr(%d bytes): %v", size, err)
		}
		data, rerr := readStreamXattr(path, rforkStreamName)
		if rerr != nil {
			t.Fatalf("readStreamXattr: %v", rerr)
		}
		n, serr := streamXattrSize(path, rforkStreamName)
		if serr != nil {
			t.Fatalf("streamXattrSize: %v", serr)
		}
		if n != len(data) || n != size {
			t.Fatalf("streamXattrSize = %d, readStreamXattr len = %d, wrote %d", n, len(data), size)
		}
	}
}

// TestDirEncode_AAPLRforkSizeUnchanged drives the real AAPL path end to end and
// proves the record the size-only probe produces is byte-identical to the one
// the fork-reading encoder produced, resource-fork size field included.
func TestDirEncode_AAPLRforkSizeUnchanged(t *testing.T) {
	dir := t.TempDir()
	names := []string{"a.txt", "b.txt", "c.txt"}
	for i, n := range names {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("base"), 0644); err != nil {
			t.Fatal(err)
		}
		if i == 0 && !xattrSupported(t, p) {
			t.Skip("filesystem does not support user xattrs")
		}
		// a.txt has no fork, b.txt an empty one, c.txt a real one.
		switch i {
		case 1:
			if err := writeStreamXattr(p, rforkStreamName, nil); err != nil {
				t.Skipf("writeStreamXattr: %v", err)
			}
		case 2:
			if err := writeStreamXattr(p, rforkStreamName, bytes.Repeat([]byte{7}, 4096)); err != nil {
				t.Skipf("writeStreamXattr: %v", err)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	const class = smb2.InfoFileIdBothDirectoryInformation
	open := &Open{Path: dir, IsDir: true, dirEntries: entries}
	got, gc, ge, gerr := encodeDirEntriesLimited(open, 64<<10, class, len(entries), true)
	want, wc, we, werr := dirEncReferenceEncode(
		&Open{Path: dir, IsDir: true, dirEntries: entries}, 64<<10, class, len(entries), true)
	if gerr != nil || werr != nil {
		t.Fatalf("err = %v, reference err = %v", gerr, werr)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AAPL records differ from the reference encoder at byte %d", dirEncFirstDiff(got, want))
	}
	if gc != wc || ge != we {
		t.Fatalf("(consumed, encoded) = (%d, %d), reference = (%d, %d)", gc, ge, wc, we)
	}
	// And the rfork size really is in the record, at ShortName[0..7].
	starts, recNames := dirEncWalkChain(t, got, 104, 60)
	for i, n := range recNames {
		var wantSize uint64
		if n == "c.txt" {
			wantSize = 4096
		}
		if size := binary.LittleEndian.Uint64(got[starts[i]+70:]); size != wantSize {
			t.Fatalf("%s: rfork size = %d, want %d", n, size, wantSize)
		}
	}
}

// --- benchmarks ---------------------------------------------------------------

// benchDirEncode encodes one full response out of a large directory. The
// entries are in memory, so what is measured is the encoder itself: with
// 112-byte records a 64 KiB response holds 585 records and an 8 MiB response
// holds 74,898, and the pre-fix chain walk cost O(records^2) steps per response
// — 170k steps at 64 KiB, 2.8G at 8 MiB.
//
// Run both halves to see the fix:
//
//	go test ./internal/parent/ -run '^$' -bench 'BenchmarkEncodeDirEntries' -benchtime 20x
func benchDirEncode(b *testing.B, maxBytes int, reference bool) {
	b.Helper()
	// Enough entries to fill an 8 MiB response and then some.
	entries := dirEncEntries(80000, nil)
	const class = smb2.InfoFileIdBothDirectoryInformation
	encode := encodeDirEntriesLimited
	if reference {
		encode = dirEncReferenceEncode
	}
	// How many records actually land in one response — the quantity the
	// pre-fix chain walk was quadratic in.
	_, _, records, err := encode(dirEncOpen(entries, 0), maxBytes, class, len(entries), false)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := encode(dirEncOpen(entries, 0), maxBytes, class, len(entries), false); err != nil {
			b.Fatal(err)
		}
	}
	// After the loop: ResetTimer deletes user-reported metrics.
	b.ReportMetric(float64(records), "records/response")
}

// 64 KiB is what macOS pins OutputBufferLength to.
func BenchmarkEncodeDirEntries_64KiB(b *testing.B)        { benchDirEncode(b, 64<<10, false) }
func BenchmarkEncodeDirEntries_64KiB_Before(b *testing.B) { benchDirEncode(b, 64<<10, true) }

// 1 MiB is a common Windows / smbclient choice.
func BenchmarkEncodeDirEntries_1MiB(b *testing.B)        { benchDirEncode(b, 1<<20, false) }
func BenchmarkEncodeDirEntries_1MiB_Before(b *testing.B) { benchDirEncode(b, 1<<20, true) }

// 8 MiB is what this server advertises as MaxTransactSize, so it is what any
// client honouring the advertisement will ask for.
func BenchmarkEncodeDirEntries_8MiB(b *testing.B)        { benchDirEncode(b, 8<<20, false) }
func BenchmarkEncodeDirEntries_8MiB_Before(b *testing.B) { benchDirEncode(b, 8<<20, true) }
