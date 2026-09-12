package parent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// SMB search patterns use the DOS wildcard grammar, not shell globbing: `*`
// and `?` are the only metacharacters and every other byte is a literal.
// matchSMBPattern used to delegate to filepath.Match, which treats `[` as a
// character class and `\` as an escape, so files whose names contain those
// characters could be listed under `*` but never resolved by name -- and macOS
// resolves every name with a single-entry QUERY_DIRECTORY whose pattern is the
// exact leaf name, so those files could not be opened at all.

// oldMatchSMBPattern is the shell-globbing implementation this fix replaced.
// It is kept so the tests can demonstrate the regression it caused and the
// benchmarks can show what the replacement costs instead.
func oldMatchSMBPattern(pattern, name string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(name))
	return ok
}

// --- the regression itself ---------------------------------------------------

// TestMatchSMBPatternShellMetacharactersAreLiteral covers the exact rows from
// the bug report: the pattern IS the name the client sent, so it must match.
func TestMatchSMBPatternShellMetacharactersAreLiteral(t *testing.T) {
	for _, name := range []string{
		"IMG[1].jpg",
		"Report [2024].pdf",
		"a[b.txt",
		`back\slash.txt`,
	} {
		if !matchSMBPattern(name, name) {
			t.Errorf("matchSMBPattern(%q, %q) = false, want true", name, name)
		}
		// And prove the old implementation really did fail these, so nobody
		// reintroduces filepath.Match thinking it was fine.
		if oldMatchSMBPattern(name, name) {
			t.Errorf("oldMatchSMBPattern(%q, %q) = true; the regression this test guards is gone, re-check the premise", name, name)
		}
	}
}

// TestMatchSMBPatternLiteralNameAlwaysMatches is the invariant that matters
// most: whatever awkward characters a POSIX filename contains, asking for that
// exact name resolves it.
func TestMatchSMBPatternLiteralNameAlwaysMatches(t *testing.T) {
	names := []string{
		"plain.txt",
		"IMG[1].jpg",
		"Report [2024].pdf",
		"a[b.txt",
		"a]b.txt",
		"[",
		"]",
		`back\slash.txt`,
		`\`,
		`C:\Users\me`,
		"{template}.json",
		"{",
		"}",
		"a{b}c[d]e",
		"spaces everywhere .txt",
		" leading space",
		"trailing space ",
		"...",
		".hidden",
		"no-extension",
		"two..dots..here",
		"dash-_under^caret",
		"100% (final) copy #2!.txt",
		"a+b=c,d;e&f",
		"~tilde@at$dollar",
		"'single' quoted",
		`say "hi".md`,
		"Q1 <draft>.txt",
		"less<than",
		"greater>than",
		"naïve café.txt",
		"Ünïcödé [tëst].pdf",
		"日本語のファイル.txt",
		"Ελληνικά.txt",
		"файл.txt",
		"emoji 🎉 party.png",
		"e\u0301-combining.txt",  // NFD
		"\u00e9-precomposed.txt", // NFC
	}
	for _, name := range names {
		if !matchSMBPattern(name, name) {
			t.Errorf("matchSMBPattern(%q, %q) = false, want true (a literal name must always resolve)", name, name)
		}
	}
}

// TestMatchSMBPatternInvalidUTF8LiteralName covers POSIX names that are not
// valid UTF-8 at all -- latin-1 leftovers are common on real shares.
func TestMatchSMBPatternInvalidUTF8LiteralName(t *testing.T) {
	names := []string{"caf\xe9.txt", "\xff\xfe", "mixed \x80 bytes.bin"}
	for _, name := range names {
		if !matchSMBPattern(name, name) {
			t.Errorf("matchSMBPattern(%q, %q) = false, want true", name, name)
		}
	}
	// Two different invalid bytes must not be conflated (utf8.RuneError would).
	if matchSMBPattern("a\xe9b", "a\xffb") {
		t.Error(`matchSMBPattern("a\xe9b", "a\xffb") = true, want false: distinct invalid bytes must not compare equal`)
	}
}

// --- the wildcard grammar ----------------------------------------------------

func TestMatchSMBPatternWildcards(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		// The fast paths.
		{"", "anything.txt", true},
		{"", "", true},
		{"*", "anything.txt", true},
		{"*", "", true},

		// `?` is exactly one character.
		{"?", "a", true},
		{"?", "", false},
		{"?", "ab", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},
		{"???", "abc", true},
		{"???", "ab", false},
		{"??.txt", "ab.txt", true},
		{"?", "\u00e9", true},     // one rune, two bytes
		{"?", "\U0001F389", true}, // one rune, four bytes
		{"??", "\u00e9", false},

		// Suffix, prefix, infix.
		{"*.txt", "notes.txt", true},
		{"*.txt", ".txt", true},
		{"*.txt", "notes.text", false},
		{"*.txt", "txt", false},
		{"report*", "report", true},
		{"report*", "report-2024.pdf", true},
		{"report*", "repor", false},
		{"*draft*", "draft", true},
		{"*draft*", "my draft copy", true},
		{"*draft*", "drift", false},

		// Several stars, including adjacent and trailing ones.
		{"**", "anything", true},
		{"a**b", "ab", true},
		{"a**b", "axxxb", true},
		{"*a*b*c*", "xxaxxbxxcxx", true},
		{"*a*b*c*", "xxaxxcxxbxx", false},
		{"a*b*c", "abc", true},
		{"a*b*c", "aXbXc", true},
		{"a*b*c", "acb", false},
		{"*.*", "a.b", true},
		{"*.*", "noextension", false},

		// Stars and question marks together.
		{"*?", "a", true},
		{"*?", "", false},
		{"?*", "a", true},
		{"a?*z", "abz", true},
		{"a?*z", "az", false},

		// Backtracking has to find the later occurrence.
		{"*ab", "aab", true},
		{"*ab", "aaab", true},
		{"*ab*ab", "abab", true},
		{"*ab*ab", "ab", false},

		// The empty name.
		{"a", "", false},
		{"*a*", "", false},
		{"***", "", true},
	}
	for _, c := range cases {
		if got := matchSMBPattern(c.pattern, c.name); got != c.want {
			t.Errorf("matchSMBPattern(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestMatchSMBPatternCaseInsensitive(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"README.TXT", "readme.txt", true},
		{"readme.txt", "README.TXT", true},
		{"ReAdMe.TxT", "rEaDmE.tXt", true},
		{"*.TXT", "Notes.txt", true},
		{"NOTES.*", "notes.txt", true},
		{"IMG[1].JPG", "img[1].jpg", true},
		{"ÄÖÜ.txt", "äöü.TXT", true},
		{"straße.txt", "STRASSE.txt", false}, // simple folding, not full folding
		{"ΣΊΣΥΦΟΣ", "σίσυφος", true},
		{"ПРИВЕТ.txt", "привет.txt", true},
		// ASCII folding must not leak into the neighbouring punctuation: a
		// blanket |0x20 would equate `_` (0x5F) with `?` (0x3F).
		{"_", "?", false},
		{"@", "`", false},
		{"[", "{", false},
		{`\`, "|", false},
		{"]", "}", false},
	}
	for _, c := range cases {
		if got := matchSMBPattern(c.pattern, c.name); got != c.want {
			t.Errorf("matchSMBPattern(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// TestMatchSMBPatternLegacyDOSWildcardsAreLiteral pins the deliberate decision
// documented in wildcard.go: DOS_STAR (`<`), DOS_QM (`>`) and DOS_DOT (`"`) are
// treated as ordinary characters, because they are legal in POSIX filenames and
// mis-treating a literal as a metacharacter is the failure mode this whole fix
// exists to remove. Change these expectations only together with that decision.
func TestMatchSMBPatternLegacyDOSWildcardsAreLiteral(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		// Literal self-match, the property being protected.
		{"Q1 <draft>.txt", "Q1 <draft>.txt", true},
		{`say "hi".md`, `say "hi".md`, true},
		{"<", "<", true},
		{">", ">", true},
		{`"`, `"`, true},

		// Not honoured as wildcards.
		{"<", "anything", false}, // DOS_STAR would match
		{">", "a", false},        // DOS_QM would match
		{`a"`, "a.", false},      // DOS_DOT would match the period
		{`a"`, "a", false},       // DOS_DOT would match end-of-name
		{`*"`, "no-extension", false},
	}
	for _, c := range cases {
		if got := matchSMBPattern(c.pattern, c.name); got != c.want {
			t.Errorf("matchSMBPattern(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// --- cross-check against an obviously-correct reference ----------------------

// refMatchSMBPattern is a deliberately naive, exponential, recursive matcher
// for the same grammar. It is far too slow to ship and far too simple to be
// wrong, which makes it the right thing to check the real one against.
func refMatchSMBPattern(pattern, name []rune) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(name); i++ {
			if refMatchSMBPattern(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	case '?':
		if len(name) == 0 {
			return false
		}
		return refMatchSMBPattern(pattern[1:], name[1:])
	default:
		if len(name) == 0 {
			return false
		}
		if !strings.EqualFold(string(pattern[0]), string(name[0])) {
			return false
		}
		return refMatchSMBPattern(pattern[1:], name[1:])
	}
}

// TestMatchSMBPatternAgainstReference walks every pattern over {a, B, *, ?} up
// to four characters against every name over {a, b} up to four characters and
// requires the shipped matcher to agree with the reference on all of them.
// This is what proves the single backtrack point is complete: a matcher that
// commits to the wrong `*` split shows up here immediately.
func TestMatchSMBPatternAgainstReference(t *testing.T) {
	patternAlphabet := []rune{'a', 'B', '*', '?'}
	nameAlphabet := []rune{'a', 'b'}

	var enumerate func(alphabet []rune, maxLen int) [][]rune
	enumerate = func(alphabet []rune, maxLen int) [][]rune {
		out := [][]rune{{}}
		cur := [][]rune{{}}
		for l := 0; l < maxLen; l++ {
			var next [][]rune
			for _, prefix := range cur {
				for _, c := range alphabet {
					word := append(append([]rune{}, prefix...), c)
					next = append(next, word)
				}
			}
			out = append(out, next...)
			cur = next
		}
		return out
	}

	names := enumerate(nameAlphabet, 4)
	checked := 0
	for _, pr := range enumerate(patternAlphabet, 4) {
		if len(pr) == 0 {
			continue // the empty pattern means "match all", by definition
		}
		pattern := string(pr)
		for _, nr := range names {
			name := string(nr)
			want := refMatchSMBPattern(pr, nr)
			if got := matchSMBPattern(pattern, name); got != want {
				t.Fatalf("matchSMBPattern(%q, %q) = %v, reference says %v", pattern, name, got, want)
			}
			checked++
		}
	}
	if checked < 10000 {
		t.Fatalf("only %d pattern/name pairs checked, the enumeration is broken", checked)
	}
}

// --- robustness --------------------------------------------------------------

// TestMatchSMBPatternAdversarialTerminates feeds the matcher the shapes that
// make a naive backtracking matcher run for the age of the universe, or recurse
// until the stack dies, and requires it to answer quickly.
func TestMatchSMBPatternAdversarialTerminates(t *testing.T) {
	cases := []struct {
		what    string
		pattern string
		name    string
	}{
		{"star-a repeated, no match", strings.Repeat("a*", 200) + "b", strings.Repeat("a", 4000)},
		{"star-qm repeated", strings.Repeat("*?", 200), strings.Repeat("a", 4000)},
		{"all stars", strings.Repeat("*", 4000), strings.Repeat("a", 4000)},
		{"star between every char", strings.Repeat("*x", 500), strings.Repeat("x", 5000)},
		{"long literal miss at the end", strings.Repeat("a", 4000) + "b", strings.Repeat("a", 4001)},
		{"pattern far longer than name", strings.Repeat("?", 10000), "a"},
		{"name far longer than pattern", "*z", strings.Repeat("a", 100000)},
		{"nested stars and classes", strings.Repeat("*[a]", 300), strings.Repeat("[a]", 900)},
		{"invalid utf8 with stars", "*\xff*\xfe*", strings.Repeat("\xff\xfe", 2000)},
	}
	for _, c := range cases {
		done := make(chan bool, 1)
		go func() { done <- matchSMBPattern(c.pattern, c.name) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("matchSMBPattern did not terminate for %s (pattern %d bytes, name %d bytes)",
				c.what, len(c.pattern), len(c.name))
		}
	}
}

var globmatchSink bool

// TestMatchSMBPatternDoesNotAllocate is the performance contract: this runs
// once per directory entry per QUERY_DIRECTORY, and the implementation it
// replaced built two lowercased copies of the strings on every call.
func TestMatchSMBPatternDoesNotAllocate(t *testing.T) {
	cases := []struct{ pattern, name string }{
		{"IMG[1].jpg", "IMG[1].jpg"},
		{"*.txt", "a-quite-long-file-name-here.txt"},
		{"*a*b*c*", "xxaxxbxxcxx"},
		{"ÄÖÜ.txt", "äöü.txt"},
		{strings.Repeat("a*", 50) + "b", strings.Repeat("a", 400)},
	}
	for _, c := range cases {
		allocs := testing.AllocsPerRun(200, func() {
			globmatchSink = matchSMBPattern(c.pattern, c.name)
		})
		if allocs != 0 {
			t.Errorf("matchSMBPattern(%q, %q) allocated %v times per call, want 0", c.pattern, c.name, allocs)
		}
	}
}

// FuzzMatchSMBPattern checks that the matcher never panics and that it agrees
// with a plain case-insensitive comparison whenever the pattern has no
// metacharacters -- which is exactly the shape macOS sends for every name
// resolution.
func FuzzMatchSMBPattern(f *testing.F) {
	seeds := [][2]string{
		{"IMG[1].jpg", "IMG[1].jpg"},
		{`back\slash.txt`, `back\slash.txt`},
		{"*.txt", "notes.txt"},
		{"a?c", "abc"},
		{"*a*b*", "ab"},
		{"", ""},
		{"*", "x"},
		{"[a-", "[a-"},
		{`\`, `\`},
		{"naïve", "NAÏVE"},
		{"\xff", "\xff"},
		{strings.Repeat("*a", 20), strings.Repeat("a", 40)},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		// Keep the fuzzer away from inputs whose only interest is size.
		if len(pattern) > 4096 || len(name) > 4096 {
			return
		}
		got := matchSMBPattern(pattern, name)

		// A wildcard-free pattern is just a case-insensitive comparison.
		if pattern != "" && !strings.ContainsAny(pattern, "*?") &&
			utf8.ValidString(pattern) && utf8.ValidString(name) {
			if want := strings.EqualFold(pattern, name); got != want {
				t.Fatalf("matchSMBPattern(%q, %q) = %v, want %v (literal pattern)", pattern, name, got, want)
			}
		}

		// Widening the pattern with a star can never lose a match.
		if got {
			if !matchSMBPattern(pattern+"*", name) {
				t.Fatalf("matchSMBPattern(%q, %q) matched but %q did not", pattern, name, pattern+"*")
			}
			if !matchSMBPattern("*"+pattern, name) {
				t.Fatalf("matchSMBPattern(%q, %q) matched but %q did not", pattern, name, "*"+pattern)
			}
		}

		// Small inputs get cross-checked against the exponential reference.
		if pattern != "" && utf8.ValidString(pattern) && utf8.ValidString(name) &&
			len(pattern) <= 24 && len(name) <= 24 {
			pr, nr := []rune(pattern), []rune(name)
			if want := refMatchSMBPattern(pr, nr); got != want {
				t.Fatalf("matchSMBPattern(%q, %q) = %v, reference says %v", pattern, name, got, want)
			}
		}

		// A pattern of one `?` per rune always matches, and one more never does.
		runes := utf8.RuneCountInString(name)
		if utf8.ValidString(name) && runes < 1024 {
			if !matchSMBPattern(strings.Repeat("?", runes), name) && runes > 0 {
				t.Fatalf("%q (%d runes) did not match %d question marks", name, runes, runes)
			}
			if matchSMBPattern(strings.Repeat("?", runes+1), name) {
				t.Fatalf("%q (%d runes) matched %d question marks", name, runes, runes+1)
			}
		}
	})
}

// --- benchmarks --------------------------------------------------------------

// BenchmarkMatchSMBPattern measures the per-entry cost against the shell-glob
// implementation it replaced. "exact" is the hot one: macOS resolves every
// single name through a one-entry QUERY_DIRECTORY with the leaf name as the
// pattern, and "miss" is what the other 4999 entries of a directory cost.
func BenchmarkMatchSMBPattern(b *testing.B) {
	cases := []struct{ what, pattern, name string }{
		{"exact", "Quarterly Report [2024].pdf", "Quarterly Report [2024].pdf"},
		{"miss", "Quarterly Report [2024].pdf", "IMG_20240817_182233.jpg"},
		{"suffix_star", "*.txt", "a-quite-long-file-name-here.txt"},
		{"prefix_star", "report*", "report-2024-final.pdf"},
		{"infix_stars", "*a*b*c*", "xxaxxbxxcxxddddddddddddddd"},
		{"unicode", "Ünïcödé [tëst].pdf", "ünïcödé [tëst].pdf"},
	}
	for _, c := range cases {
		b.Run(c.what+"/new", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				globmatchSink = matchSMBPattern(c.pattern, c.name)
			}
		})
		b.Run(c.what+"/old", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				globmatchSink = oldMatchSMBPattern(c.pattern, c.name)
			}
		})
	}
}

// BenchmarkQueryDirFilter is the loop handleQueryDirectory actually runs: one
// match per directory entry, for a 5000-entry directory.
func BenchmarkQueryDirFilter(b *testing.B) {
	names := make([]string, 5000)
	for i := range names {
		names[i] = "IMG_2024" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + ".jpg"
	}
	target := names[len(names)-1]

	b.Run("exact_name/new", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			n := 0
			for _, name := range names {
				if matchSMBPattern(target, name) {
					n++
				}
			}
			globmatchSink = n == 1
		}
	})
	b.Run("exact_name/old", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			n := 0
			for _, name := range names {
				if oldMatchSMBPattern(target, name) {
					n++
				}
			}
			globmatchSink = n == 1
		}
	})
	b.Run("suffix/new", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			n := 0
			for _, name := range names {
				if matchSMBPattern("*.jpg", name) {
					n++
				}
			}
			globmatchSink = n == len(names)
		}
	})
	b.Run("suffix/old", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			n := 0
			for _, name := range names {
				if oldMatchSMBPattern("*.jpg", name) {
					n++
				}
			}
			globmatchSink = n == len(names)
		}
	})
}
