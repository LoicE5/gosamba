package parent

import (
	"unicode"
	"unicode/utf8"
)

// SMB search patterns are not shell globs.
//
// The grammar a QUERY_DIRECTORY pattern is written in is the DOS/SMB one
// (MS-FSA 2.1.4.4, MS-CIFS 2.2.1.1.3). It has exactly two metacharacters:
//
//	*  matches zero or more characters
//	?  matches exactly one character
//
// Everything else is a literal -- `[`, `]`, `\`, `{`, `}`, `^`, `-` included.
// filepath.Match, which this replaced, implements the *shell* grammar, where
// `[` opens a character class and `\` escapes the next character. Both are
// perfectly legal bytes in a POSIX filename, so the two grammars disagree on
// real files:
//
//	pattern              name on disk         filepath.Match
//	IMG[1].jpg           IMG[1].jpg           false
//	Report [2024].pdf    Report [2024].pdf    false
//	a[b.txt              a[b.txt              false (ErrBadPattern)
//	back\slash.txt       back\slash.txt       false
//
// That is not a cosmetic difference. macOS resolves every individual name
// through a single-entry QUERY_DIRECTORY whose pattern is the exact leaf name
// (SMBClient smbfs_smb.c, and smb2fs_smb_cmpd_query_dir_one in smbfs_smb_2.c),
// so a file whose name contains one of those characters enumerated fine under
// the `*` pattern but every stat and open of it answered STATUS_NO_SUCH_FILE.
// The client maps that to ENOENT and parks it in the negative name cache,
// which only clears once the parent directory's mtime advances: Finder shows
// the file, opening it fails, and it keeps failing.
//
// # Legacy DOS wildcards
//
// MS-FSA also defines three wildcards inherited from the DOS FCB matcher:
// DOS_STAR (`<`), DOS_QM (`>`) and DOS_DOT (`"`). They are deliberately NOT
// implemented here; this matcher treats all three as ordinary literals. The
// reasoning:
//
//   - The backing store is POSIX. `<`, `>` and `"` are legal, unremarkable
//     bytes in a filename ("Q1 <draft>.txt", `say "hi".md`), whereas the Win32
//     name space forbids them precisely because it reserves them as wildcards.
//     Honouring them as metacharacters would therefore reintroduce, for three
//     more characters, exactly the defect this file exists to fix -- and for
//     DOS_DOT it demonstrably would: `"` matches a period or end-of-name, never
//     a literal quote, so a client asking for `say "hi".md` by name would get
//     STATUS_NO_SUCH_FILE and cache it.
//
//   - The client that needs them cannot send them. macOS never emits DOS
//     wildcards at all; Windows only generates them inside its own name-to-
//     expression conversion (a trailing `.` becomes `"`, `*.` becomes `<`),
//     and since it cannot express those characters literally in a path it can
//     never need them matched literally either. So the cost of omitting them
//     is bounded to a legacy 8.3-style search returning a slightly different
//     result set, never to a file becoming unopenable.
//
//   - The failure modes are asymmetric. Treating a metacharacter as a literal
//     returns too few results for an unusual search -- visible, harmless, and
//     the user retries. Treating a literal as a metacharacter hides a file
//     that plainly exists and poisons the client's negative name cache. When
//     in doubt, prefer the literal.
//
// Adding them later is a localised change: DOS_QM and DOS_DOT are deterministic
// (they consume one character, or nothing at end-of-name / before a period) and
// DOS_STAR is `*` bounded by the position of the final period in the name, so
// it slots into the same backtrack point `*` already uses.

// matchSMBPattern reports whether name matches the SMB search pattern. An empty
// pattern, and the pattern `*`, match everything.
//
// # Case
//
// caseSensitive must be the share's real, probed case sensitivity — the same
// value the AAPL volume-capability bit and FILE_CASE_SENSITIVE_SEARCH carry
// (parent.shareCaseSensitive). It is not a preference.
//
// This matcher used to fold case unconditionally while vfs.ResolveNorm resolved
// case-sensitively, and the two disagreed on every case-sensitive backing
// filesystem. macOS resolves a single name through a QUERY_DIRECTORY whose
// pattern is the exact leaf name, so a request for `foo` matched an on-disk
// `Foo` here, the client was told the file existed, and the CREATE that
// followed answered STATUS_NO_SUCH_FILE. SMBClient maps that to ENOENT and
// parks it in the negative name cache, which only clears once the parent
// directory's mtime advances: Finder shows the file, opening it fails, and it
// keeps failing. On a case-insensitive filesystem the resolver's exact-match
// fast path hid the whole thing, so it bit Linux and not APFS.
//
// Folding here is therefore gated on the same probe the resolver's foldCase
// argument comes from. On a case-sensitive share `foo` no longer matches `Foo`
// and the client is told the truth up front.
//
// The matcher is a two-pointer scan with a single backtrack point: on a
// mismatch it rewinds to just past the most recent `*` and lets that `*`
// swallow one more character. That is complete for a `*`/`?` grammar, needs no
// recursion and allocates nothing, so it cannot blow the stack and a hostile
// pattern costs at worst O(len(pattern) x len(name)) steps before terminating.
// It runs once per directory entry per QUERY_DIRECTORY, so the two lowercased
// copies the previous implementation built per call were pure waste.
func matchSMBPattern(pattern, name string, caseSensitive bool) bool {
	if pattern == "" || pattern == "*" {
		return true
	}

	var (
		p, n  int  // byte offsets into pattern and name
		starP = -1 // byte offset just past the most recent `*`; -1 if none
		starN int  // how far into name that `*` has swallowed
	)
	for n < len(name) {
		if p < len(pattern) {
			// Decode one rune of each. ASCII -- every byte of almost every
			// pattern and name -- is handled right here, so the loop touches
			// the UTF-8 decoder and the folding table only when it has to.
			// These are written out rather than factored into a helper
			// because a helper big enough to hold them does not fit the
			// inliner's budget, and this loop runs per directory entry.
			pc, psize := rune(pattern[p]), 1
			if pc >= utf8.RuneSelf {
				pc, psize = decodeRune(pattern[p:])
			}
			if pc == '*' {
				p += psize
				if p == len(pattern) {
					return true // a trailing `*` takes whatever is left
				}
				starP, starN = p, n
				continue
			}
			nc, nsize := rune(name[n]), 1
			if nc >= utf8.RuneSelf {
				nc, nsize = decodeRune(name[n:])
			}
			if pc == '?' || pc == nc || (!caseSensitive && foldEqual(pc, nc)) {
				p += psize
				n += nsize
				continue
			}
		}
		// Mismatch, or the pattern ran out with name left over.
		if starP < 0 {
			return false
		}
		// Backtrack: hand the most recent `*` one more rune of the name.
		// starN <= n < len(name), so there is always one to hand over.
		nsize := 1
		if name[starN] >= utf8.RuneSelf {
			_, nsize = decodeRune(name[starN:])
		}
		starN += nsize
		p, n = starP, starN
	}
	// Name consumed: whatever is left of the pattern must match empty.
	for p < len(pattern) {
		if pattern[p] != '*' {
			return false
		}
		p++
	}
	return true
}

// decodeRune decodes the first rune of s, which must be non-empty and must
// start with a non-ASCII byte -- callers test for ASCII themselves so that the
// common case never reaches a function call.
//
// A byte that is not valid UTF-8 is reported as its own negative sentinel
// rather than as utf8.RuneError, because POSIX filenames are byte strings and
// two different invalid bytes must not compare equal. Negative sentinels are
// inert in foldEqual: they fail its ASCII-letter tests and unicode.SimpleFold
// returns out-of-range runes unchanged, so only an identical byte matches.
func decodeRune(s string) (rune, int) {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size == 1 {
		return -rune(s[0]), 1
	}
	return r, size
}

// foldEqual reports whether a and b are the same character ignoring case. It
// allocates nothing. The match loop calls it only once it has found the two
// runes unequal and only on a case-insensitive share, but it is correct
// standalone.
//
// It states the same equivalence as vfs.FoldRune, which the path resolver uses
// to build its fold keys, from the other end: this walks a's orbit looking for
// b, FoldRune reduces an orbit to its smallest member. They MUST agree, or the
// matcher and the resolver drift apart again —
// TestFoldRuneAgreesWithFoldEqual proves it over the whole rune range.
//
// Non-ASCII goes through unicode.SimpleFold, the same equivalence
// strings.EqualFold uses. That is simple (one rune in, one rune out) case
// folding, which is also what Windows does with its upcase table, so it is a
// closer match to real SMB semantics than strings.ToLower's multi-rune special
// cases -- and it additionally equates pairs a ToLower comparison would miss,
// such as U+212A KELVIN SIGN with `k`.
func foldEqual(a, b rune) bool {
	if a == b {
		// Not reachable from the match loop, but unicode.SimpleFold cannot
		// answer this one: a rune whose folding orbit is a singleton (every
		// caseless rune, and every invalid-byte sentinel) never comes back
		// round to itself in the walk below.
		return true
	}
	if a < utf8.RuneSelf && b < utf8.RuneSelf {
		// Fold ASCII letters only. A blanket |0x20 would also equate `_`
		// (0x5F) with `?` (0x3F) and `@` with backtick.
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		return a == b
	}
	// Walk a's folding orbit. SimpleFold's orbits are short cycles (at most
	// four runes) that always return to their starting point, so this ends.
	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
	}
	return false
}
