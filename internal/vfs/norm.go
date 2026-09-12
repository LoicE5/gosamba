package vfs

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// readDir is indirected so tests can assert that the constant-time lookup
// paths never fall back to reading the whole parent directory.
var readDir = os.ReadDir

// asciiFolds maps each ASCII character that some non-ASCII code point
// canonically decomposes to, to that code point. Enumerating the entire
// Unicode range shows there are exactly three of them, and that each one
// decomposes to a single ASCII byte (TestASCIIFoldsIsComplete re-verifies
// this against whatever Unicode tables are compiled in):
//
//	U+037E GREEK QUESTION MARK -> ';'
//	U+1FEF GREEK VARIA         -> '`'
//	U+212A KELVIN SIGN         -> 'K'
//
// They are the reason a pure-ASCII request cannot simply skip the
// normalization fallback: a file stored on disk under one of these code
// points is canonically equivalent to an ASCII name containing the character
// it folds to, so it must still be found.
var asciiFolds = map[byte]rune{
	';': ';',
	'`': '`',
	'K': 'K',
}

// maxASCIIFoldPositions caps how many foldable characters we are willing to
// enumerate on-disk variants for; n of them mean 2^n-1 extra Lstat calls.
// Names with more fall back to the directory scan, which is slower but still
// correct. Real filenames essentially never contain more than a couple.
const maxASCIIFoldPositions = 3

// ResolveNorm resolves a leaf name within parentDir to the actual on-disk
// entry using Unicode-normalization-insensitive matching. It is designed for
// the lookup fallback path, including the very hot "name does not exist yet"
// case of a CREATE, so it resolves in a constant number of syscalls whenever
// it can:
//
//  1. exact match (one Lstat);
//  2. the NFC and the NFD form of the requested name (one Lstat each) — this
//     covers the case the feature exists for, an NFD name written by macOS
//     being looked up in NFC form by a Windows/Linux client, and vice versa;
//  3. for a pure-ASCII request, the remaining members of its canonical
//     equivalence class, which are fully enumerable from asciiFolds (at most
//     2^maxASCIIFoldPositions-1 further Lstat calls, and none at all for the
//     overwhelming majority of names, which contain no foldable character).
//
// Only a non-ASCII name that is on disk in neither its NFC nor its NFD form
// (i.e. a partially composed name) still needs the O(dir) scan; that is the
// rare tail, not the common path. Crucially, a missing name no longer costs a
// full directory read.
//
// # foldCase
//
// foldCase says whether the SERVER has to fold letter case on the backing
// filesystem's behalf. It is not "is the share case-insensitive" — it is
// narrower than that on purpose, and the caller (parent.shareFoldsCase) is
// where the distinction is drawn:
//
//   - On a case-SENSITIVE filesystem, `Foo` and `foo` are different files and
//     the server must say so. foldCase is false and every step above is
//     byte-exact, so a name that is not there still costs no directory read.
//
//   - On a filesystem that folds case ITSELF (APFS, HFS+, a casefold-enabled
//     ext4/f2fs directory, vfat), step 1 has already resolved every spelling
//     before this function sees the name — and, just as importantly, a miss
//     there is conclusive. foldCase is false again, and the new-file CREATE
//     path keeps costing exactly one Lstat.
//
//   - foldCase is true only where the share is reported case-insensitive but
//     nothing underneath is folding: an unprobeable share. Then, and only
//     then, this function folds case itself, and that costs one directory
//     read for a name it cannot find any other way. That is the deliberate
//     price of not telling the client a file exists and then refusing to open
//     it.
//
// The fold is one pass, not a cross product: case and normalization are
// collapsed into a single canonical key per entry (see foldKeyAppend), so
// combining the two does not multiply the candidate set.
//
// Returns the resolved leaf name (usable as a path component under parentDir)
// and true on success, or ("", false) when no matching entry is found.
//
// The caller is responsible for path containment checks (ResolveSecure) on
// the full path after combining parentDir with the returned leaf.
func ResolveNorm(parentDir, requestedLeaf string, foldCase bool) (string, bool) {
	// Fast path: exact match.
	if leafExists(parentDir, requestedLeaf) {
		return requestedLeaf, true
	}

	// Constant-time fallback: probe the normalized forms directly instead of
	// reading the directory.
	nfcRequested := norm.NFC.String(requestedLeaf)
	nfdRequested := norm.NFD.String(requestedLeaf)
	if nfcRequested != requestedLeaf && leafExists(parentDir, nfcRequested) {
		return nfcRequested, true
	}
	if nfdRequested != requestedLeaf && nfdRequested != nfcRequested &&
		leafExists(parentDir, nfdRequested) {
		return nfdRequested, true
	}

	// Still constant time: for a pure-ASCII request the equivalence class is
	// small and known, so probing it finishes the search without a scan.
	variants, exhaustive := asciiFoldVariants(requestedLeaf)
	for _, v := range variants {
		if leafExists(parentDir, v) {
			return v, true
		}
	}
	if exhaustive && !foldCase {
		// The canonical equivalence class is exhausted and case is not ours to
		// fold, so nothing in the directory can match. This is the new-file
		// CREATE path, and it must not read the directory.
		return "", false
	}

	// The remaining paths read the directory once. Without foldCase that is the
	// rare tail — a non-ASCII name stored in neither of its normal forms. With
	// foldCase it is every miss, which is why foldCase is kept off wherever the
	// filesystem answers the case question itself.
	entries, err := readDir(parentDir)
	if err != nil {
		return "", false
	}
	if foldCase {
		// Ambiguity rule: os.ReadDir returns entries sorted by filename, so the
		// first match is deterministic. With both `Foo` and `foo` on disk a
		// request for `FOO` always yields `Foo` ('F' 0x46 sorts before 'f'
		// 0x66). A request that matches one of them exactly never gets here —
		// the Lstat above already returned it — so an exact spelling always
		// wins over a folded one.
		want := foldKeyAppend(nil, nfcRequested)
		key := make([]byte, 0, len(want)+8)
		for _, e := range entries {
			key = foldKeyAppend(key[:0], e.Name())
			if bytes.Equal(key, want) {
				return e.Name(), true
			}
		}
		return "", false
	}
	for _, e := range entries {
		if norm.NFC.String(e.Name()) == nfcRequested {
			return e.Name(), true
		}
	}
	return "", false
}

// FoldRune returns the canonical representative of r's simple case-folding
// orbit: the smallest rune in it. Two runes are case-equal exactly when their
// representatives are equal.
//
// It is exported because internal/parent's SMB pattern matcher must agree with
// this resolver about what "same letter, different case" means — a matcher that
// says `foo` names the on-disk `Foo` while the resolver cannot open it is the
// defect this parameter exists to close. parent's foldEqual walks a's orbit
// looking for b, which is the same equivalence stated the other way round;
// TestFoldRuneAgreesWithFoldEqual proves the two over the whole rune range.
//
// Simple folding (one rune in, one rune out) is deliberate: it is what Windows
// does with its upcase table, so `straße` and `STRASSE` stay distinct while
// U+212A KELVIN SIGN and `k` do not.
func FoldRune(r rune) rune {
	// A rune whose orbit is a singleton — every caseless rune — never comes
	// back round, because SimpleFold returns it unchanged and the loop below
	// does not execute.
	lo := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < lo {
			lo = f
		}
	}
	return lo
}

// foldKeyAppend appends to dst a key that is equal for two names exactly when
// they are the same name ignoring both letter case and Unicode normalization.
// Reducing each entry to one key is what keeps the fold branch a single O(dir)
// pass: the two equivalences are collapsed together rather than enumerated as
// a cross product of spellings.
//
// NFC is applied first (it is a no-op, and allocation-free, for a name that is
// already normalized — which every ASCII name is), then each rune is replaced
// by its FoldRune representative.
//
// A byte that is not valid UTF-8 is emitted as 0xFF followed by the byte
// itself. POSIX filenames are byte strings and two different invalid bytes must
// not compare equal, and 0xFF never appears in valid UTF-8, so the pair cannot
// collide with any real encoding. This mirrors the negative sentinels the
// pattern matcher uses for the same reason.
func foldKeyAppend(dst []byte, s string) []byte {
	s = norm.NFC.String(s)
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			// ASCII is the whole of almost every filename. FoldRune maps an
			// ASCII letter to its upper-case form (the orbit minimum), so do
			// that directly and skip the decoder and the orbit walk.
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			dst = append(dst, c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, 0xFF, s[i])
			i++
			continue
		}
		dst = utf8.AppendRune(dst, FoldRune(r))
		i += size
	}
	return dst
}

// leafExists reports whether leaf names an existing entry inside parentDir.
func leafExists(parentDir, leaf string) bool {
	_, err := os.Lstat(filepath.Join(parentDir, leaf))
	return err == nil
}

// asciiFoldVariants returns the on-disk names that are canonically equivalent
// to leaf but not byte-equal to it, together with a flag reporting whether
// that list is exhaustive — i.e. whether the caller may conclude "not found"
// without scanning the directory.
//
// It is exhaustive only for pure-ASCII names: such a name is its own NFC and
// NFD form, and the only other strings that normalize to it are those in
// which one or more of the characters in asciiFolds were written using the
// non-ASCII code point that folds to them. Every combination is produced.
// For non-ASCII names (or ASCII names with an implausible number of foldable
// characters) it returns exhaustive=false and the caller must scan.
func asciiFoldVariants(leaf string) (variants []string, exhaustive bool) {
	var pos []int
	for i := 0; i < len(leaf); i++ {
		c := leaf[i]
		if c >= utf8.RuneSelf {
			return nil, false
		}
		if _, ok := asciiFolds[c]; ok {
			pos = append(pos, i)
			if len(pos) > maxASCIIFoldPositions {
				return nil, false
			}
		}
	}
	if len(pos) == 0 {
		// Nothing else on disk can be canonically equivalent to this name.
		return nil, true
	}

	variants = make([]string, 0, (1<<len(pos))-1)
	var b strings.Builder
	for mask := 1; mask < 1<<len(pos); mask++ {
		b.Reset()
		prev := 0
		for i, p := range pos {
			if mask&(1<<i) == 0 {
				continue
			}
			b.WriteString(leaf[prev:p])
			b.WriteRune(asciiFolds[leaf[p]])
			prev = p + 1
		}
		b.WriteString(leaf[prev:])
		variants = append(variants, b.String())
	}
	return variants, true
}
