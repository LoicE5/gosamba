package vfs

import (
	"os"
	"path/filepath"
	"strings"
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
// Returns the resolved leaf name (usable as a path component under parentDir)
// and true on success, or ("", false) when no matching entry is found.
//
// The caller is responsible for path containment checks (ResolveSecure) on
// the full path after combining parentDir with the returned leaf.
func ResolveNorm(parentDir, requestedLeaf string) (string, bool) {
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
	if variants, exhaustive := asciiFoldVariants(requestedLeaf); exhaustive {
		for _, v := range variants {
			if leafExists(parentDir, v) {
				return v, true
			}
		}
		return "", false
	}

	// Rare path: a non-ASCII name that is stored in neither of its normal
	// forms. Scan the directory and compare NFC forms.
	entries, err := readDir(parentDir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if norm.NFC.String(e.Name()) == nfcRequested {
			return e.Name(), true
		}
	}
	return "", false
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
