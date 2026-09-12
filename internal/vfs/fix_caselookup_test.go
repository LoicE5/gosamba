package vfs

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// The path resolver and internal/parent's SMB pattern matcher used to disagree
// about case: ResolveNorm was normalization-insensitive but case-SENSITIVE,
// while matchSMBPattern folded case unconditionally. macOS resolves a single
// name through a QUERY_DIRECTORY whose pattern is the exact leaf name, so on a
// case-sensitive backing filesystem a request for `foo` matched an on-disk
// `Foo`, the client was told the file existed, and the CREATE that followed
// answered STATUS_NO_SUCH_FILE — which SMBClient caches as a negative name
// entry until the parent directory's mtime advances.
//
// The fix threads the share's probed case sensitivity into both. These tests
// pin the resolver half: what foldCase does, what it deliberately does not do,
// and that turning it off leaves the constant-time missing-name path exactly
// as it was.

// fsFoldsCase reports whether dir's filesystem resolves a name written in one
// case under another. A Linux CI runner (ext4) and a stock macOS box (APFS,
// case-insensitive) legitimately disagree, so nothing below hardcodes an
// answer — every assertion is about self-consistency with this observation.
func fsFoldsCase(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "caselookup-ground-truth")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatalf("ground-truth write: %v", err)
	}
	defer os.Remove(probe)

	_, err := os.Lstat(filepath.Join(dir, "CASELOOKUP-GROUND-TRUTH"))
	switch {
	case err == nil:
		return true
	case os.IsNotExist(err):
		return false
	default:
		t.Fatalf("ground-truth lstat: %v", err)
		return false
	}
}

// sameFile reports whether two paths name the same inode.
func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	ai, err := os.Lstat(a)
	if err != nil {
		t.Fatalf("lstat %s: %v", a, err)
	}
	bi, err := os.Lstat(b)
	if err != nil {
		t.Fatalf("lstat %s: %v", b, err)
	}
	return os.SameFile(ai, bi)
}

// TestResolveNorm_FoldCaseFindsOtherSpelling is the requirement in one test:
// with folding on, `foo` resolves to an on-disk `Foo` — on every filesystem,
// whether or not the kernel would have folded for us.
func TestResolveNorm_FoldCaseFindsOtherSpelling(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Foo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, requested := range []string{"foo", "FOO", "fOo"} {
		got, ok := ResolveNorm(dir, requested, true)
		if !ok {
			t.Fatalf("ResolveNorm(%q, foldCase) missed the on-disk %q", requested, "Foo")
		}
		// Whatever it returns must be openable under parentDir — a resolver
		// that answers "found" with a name that does not open is the defect.
		if !sameFile(t, filepath.Join(dir, got), filepath.Join(dir, "Foo")) {
			t.Errorf("ResolveNorm(%q, foldCase) = %q, which is not the file that was created", requested, got)
		}
	}
}

// TestResolveNorm_NoFoldDefersToFilesystem pins the other half of the contract:
// with folding off the resolver adds nothing of its own, so its answer is
// exactly what the backing filesystem says. That is what makes foldCase=false
// the right setting BOTH for a case-sensitive filesystem (where `foo` must
// miss) and for one that folds in the kernel (where the very first Lstat has
// already resolved every spelling).
func TestResolveNorm_NoFoldDefersToFilesystem(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Foo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	folds := fsFoldsCase(t, dir)

	scans := countDirScans(t)
	got, ok := ResolveNorm(dir, "foo", false)
	if ok != folds {
		t.Errorf("ResolveNorm(%q, foldCase=false) = %q, %v; the filesystem folds case = %v, so the two must agree",
			"foo", got, ok, folds)
	}
	if ok && !sameFile(t, filepath.Join(dir, got), filepath.Join(dir, "Foo")) {
		t.Errorf("ResolveNorm returned %q, which is not the file that was created", got)
	}
	// The point of foldCase=false: it never reads the directory, hit or miss.
	if *scans != 0 {
		t.Errorf("foldCase=false read the directory %d time(s); want 0", *scans)
	}
}

// TestResolveNorm_MissingNameStillDoesNotScanWithoutFold is the regression
// guard for the constant-time missing-name path, restated for the case
// parameter: adding case awareness must not have put a directory read back on
// the new-file CREATE path. A case variant is present on disk precisely so the
// resolver has something it *could* have scanned for.
func TestResolveNorm_MissingNameStillDoesNotScanWithoutFold(t *testing.T) {
	dir := t.TempDir()
	populate(t, dir, 2000)
	for _, name := range []string{"Brand-New-File.txt", "Kelvin-Report.TXT", "Weird;Name.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	folds := fsFoldsCase(t, dir)
	scans := countDirScans(t)
	for _, name := range []string{"brand-new-file.txt", "kelvin-report.txt", "weird;name.txt"} {
		got, ok := ResolveNorm(dir, name, false)
		if ok && !folds {
			t.Errorf("ResolveNorm(%q, foldCase=false) = %q on a case-sensitive filesystem; want miss", name, got)
		}
	}
	if *scans != 0 {
		t.Errorf("missing-name lookups read the directory %d time(s); want 0", *scans)
	}
}

// TestResolveNorm_FoldCaseCostsOneDirectoryRead makes the price explicit rather
// than leaving it to be discovered in production. Folding is the one branch
// that reads the directory, and it reads it exactly once — never once per
// candidate spelling, which is what enumerating case x normalization would
// have cost.
func TestResolveNorm_FoldCaseCostsOneDirectoryRead(t *testing.T) {
	dir := t.TempDir()
	populate(t, dir, 200)

	// A hit that the constant-time ladder can serve must still not scan: an
	// exactly-spelled name is resolved by the very first Lstat.
	if err := os.WriteFile(filepath.Join(dir, "exact.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	scans := countDirScans(t)
	if _, ok := ResolveNorm(dir, "exact.txt", true); !ok {
		t.Fatal("exact spelling should resolve")
	}
	if *scans != 0 {
		t.Errorf("exact hit under foldCase read the directory %d time(s); want 0", *scans)
	}

	// A name no spelling probe can find falls through to one scan, and only one.
	*scans = 0
	if got, ok := ResolveNorm(dir, "no-such-name-at-all.txt", true); ok {
		t.Fatalf("ResolveNorm = %q, true; want miss", got)
	}
	if *scans != 1 {
		t.Errorf("folded miss read the directory %d time(s); want exactly 1", *scans)
	}
}

// TestResolveNorm_FoldAmbiguityIsDeterministic covers the case a case-sensitive
// filesystem permits and a case-insensitive one cannot: `Foo` and `foo` side by
// side, with a folded lookup that has two correct answers.
//
// The rule is "first in os.ReadDir order", which sorts by filename in byte
// order, so `Foo` ('F' 0x46) wins over `foo` ('f' 0x66). An exactly-spelled
// request never reaches the rule at all — the Lstat ladder returns it first —
// so asking for `foo` still gets `foo`.
func TestResolveNorm_FoldAmbiguityIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	if fsFoldsCase(t, dir) {
		t.Skip("filesystem folds case; `Foo` and `foo` cannot coexist to be ambiguous")
	}
	for _, name := range []string{"foo", "Foo", "FOO"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Ambiguous request: none of these is on disk, all three fold to the same
	// name. "FOO" sorts first among {"FOO", "Foo", "foo"}.
	for i := 0; i < 50; i++ {
		got, ok := ResolveNorm(dir, "fOO", true)
		if !ok {
			t.Fatal("folded lookup should resolve")
		}
		if got != "FOO" {
			t.Fatalf("run %d: ResolveNorm(%q, foldCase) = %q, want %q (first in os.ReadDir order)",
				i, "fOO", got, "FOO")
		}
	}

	// An exact spelling is never ambiguous: it is resolved before any scan.
	for _, name := range []string{"foo", "Foo", "FOO"} {
		got, ok := ResolveNorm(dir, name, true)
		if !ok || got != name {
			t.Errorf("ResolveNorm(%q, foldCase) = %q, %v; an exact spelling must win", name, got, ok)
		}
	}
}

// TestResolveNorm_FoldCaseAndNormalizationTogether is the interaction the two
// equivalences create. They are not enumerated as a cross product of spellings;
// both sides are reduced to one canonical key, so combining them costs the same
// single pass that either would alone.
func TestResolveNorm_FoldCaseAndNormalizationTogether(t *testing.T) {
	// On disk: NFD, upper case. Requested: NFC, lower case. Neither the case
	// nor the normalization matches, so only the fold key can find it.
	onDisk := strings.ToUpper(nfdCafe)
	if onDisk == nfcCafe {
		t.Fatal("test premise broken: on-disk and requested spellings coincide")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, onDisk), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := ResolveNorm(dir, nfcCafe, true)
	if !ok {
		t.Fatalf("ResolveNorm(%q, foldCase) missed the on-disk %q", nfcCafe, onDisk)
	}
	if !sameFile(t, filepath.Join(dir, got), filepath.Join(dir, onDisk)) {
		t.Errorf("ResolveNorm returned %q, which is not the file that was created", got)
	}

	// And with folding off it is a miss on a case-sensitive filesystem: the
	// normalization fallback alone must not start folding case.
	if _, ok := ResolveNorm(dir, nfcCafe, false); ok != fsFoldsCase(t, dir) {
		t.Errorf("ResolveNorm(%q, foldCase=false) = %v; want the filesystem's own answer %v",
			nfcCafe, ok, fsFoldsCase(t, dir))
	}
}

// TestResolveSecureNorm_FoldCaseWalksEveryComponent checks that the flag
// reaches each path component, not just the leaf — a mis-cased DIRECTORY in
// the middle of a path is just as unopenable as a mis-cased file.
func TestResolveSecureNorm_FoldCaseWalksEveryComponent(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "Reports", "Q1")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "Summary.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveSecureNorm(root, `reports\q1\summary.txt`, true)
	if err != nil {
		t.Fatalf("ResolveSecureNorm: %v", err)
	}
	if !sameFile(t, got, filepath.Join(sub, "Summary.txt")) {
		t.Errorf("ResolveSecureNorm = %q, which is not the file that was created", got)
	}

	// A brand-new leaf under mis-cased parents must land in the directory that
	// actually exists, under the leaf spelling the client asked for. The leaf
	// itself is not rewritten — there is nothing on disk to rewrite it to — and
	// the parent components keep whatever spelling resolved them: on a
	// filesystem that folds case the requested spelling already opens the right
	// directory, so only the resolved inode is worth asserting on.
	got, err = ResolveSecureNorm(root, `reports\q1\brand-new.txt`, true)
	if err != nil {
		t.Fatalf("ResolveSecureNorm (new leaf): %v", err)
	}
	if base := filepath.Base(got); base != "brand-new.txt" {
		t.Errorf("ResolveSecureNorm (new leaf) = %q, want leaf %q", got, "brand-new.txt")
	}
	if !sameFile(t, filepath.Dir(got), sub) {
		t.Errorf("ResolveSecureNorm (new leaf) = %q; its parent is not %q", got, sub)
	}
}

// TestFoldRuneIsAnOrbitInvariant proves the fold key is well defined: every
// rune in a simple-case-folding orbit must reduce to the same representative,
// or two spellings of one name would key differently and the scan would miss.
func TestFoldRuneIsAnOrbitInvariant(t *testing.T) {
	checked := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF { // surrogates are not valid runes
			continue
		}
		want := FoldRune(r)
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if got := FoldRune(f); got != want {
				t.Fatalf("FoldRune(U+%04X) = U+%04X but FoldRune(U+%04X) = U+%04X; "+
					"they are in one folding orbit and must agree", r, want, f, got)
			}
			checked++
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d orbit members checked; the Unicode tables look wrong", checked)
	}
}

// TestFoldKeyDistinguishesWhatItMust guards the two ways a fold key could
// wrongly collapse names: distinct invalid bytes (POSIX filenames are byte
// strings) and ASCII punctuation that a blanket |0x20 would fold onto letters.
func TestFoldKeyDistinguishesWhatItMust(t *testing.T) {
	equal := func(a, b string) bool {
		return string(foldKeyAppend(nil, a)) == string(foldKeyAppend(nil, b))
	}
	same := [][2]string{
		{"Foo", "foo"}, {"FOO", "fOo"},
		{"Kelvin", "kelvin"},            // U+212A KELVIN SIGN
		{"straſe", "STRASE"[:4] + "se"}, // U+017F LATIN SMALL LETTER LONG S
		{nfcCafe, norm.NFD.String("CAFÉ")},
		{"CAF\xe9.TXT", "caf\xe9.txt"}, // invalid byte preserved, ASCII folded
	}
	for _, c := range same {
		if !equal(c[0], c[1]) {
			t.Errorf("fold keys of %q and %q differ; want equal", c[0], c[1])
		}
	}
	different := [][2]string{
		{"_", "?"}, {"@", "`"}, {"[", "{"}, {"]", "}"}, {`\`, "|"},
		{"straße", "STRASSE"}, // simple folding, not full folding
		{"caf\xe9.txt", "caf\xff.txt"},
		{"caf\xe9", "café"},
		{"a", "ab"},
	}
	for _, c := range different {
		if equal(c[0], c[1]) {
			t.Errorf("fold keys of %q and %q are equal; want different", c[0], c[1])
		}
	}
}

// BenchmarkResolveNormMissingFold is the measured cost of the one branch that
// reads the directory. Compare it with BenchmarkResolveNormMissing, which is
// the same lookup with folding off: that one is flat, this one is not. It is
// the reason foldCase is kept off for every share whose filesystem answers the
// case question itself.
func BenchmarkResolveNormMissingFold(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(strconv.Itoa(n)+"-entries", func(b *testing.B) {
			dir := makeBenchDir(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := ResolveNorm(dir, "brand-new-file.txt", true); ok {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkResolveNormExistingFold measures the hit that the constant-time
// ladder serves even with folding on: an exactly-spelled name never reaches
// the scan, so this must stay flat.
func BenchmarkResolveNormExistingFold(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(strconv.Itoa(n)+"-entries", func(b *testing.B) {
			dir := makeBenchDir(b, n)
			if err := os.WriteFile(filepath.Join(dir, "existing.txt"), nil, 0o644); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := ResolveNorm(dir, "existing.txt", true); !ok {
					b.Fatal("expected hit")
				}
			}
		})
	}
}

// fakeDirEntry is a name and nothing else: the fold scan only ever reads
// Name(), so this is enough to drive the selection rule directly.
type fakeDirEntry struct{ name string }

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return false }
func (f fakeDirEntry) Type() os.FileMode          { return 0 }
func (f fakeDirEntry) Info() (os.FileInfo, error) { return nil, os.ErrNotExist }

// TestResolveNorm_FoldAmbiguityRuleIsFirstSorted states the ambiguity rule
// without needing a filesystem that can hold `Foo` and `foo` at once — the
// machine running the test usually cannot. It feeds the scan the entry list a
// case-sensitive filesystem would have produced and checks which one wins.
//
// os.ReadDir sorts by filename in byte order, so upper case sorts first. The
// rule is "first match in that order", which makes the answer a property of the
// directory's contents rather than of iteration luck.
func TestResolveNorm_FoldAmbiguityRuleIsFirstSorted(t *testing.T) {
	dir := t.TempDir()

	// os.ReadDir's own ordering, applied to the names a case-sensitive
	// filesystem would report.
	entries := []os.DirEntry{
		fakeDirEntry{"FOO"}, fakeDirEntry{"Foo"}, fakeDirEntry{"fOO"}, fakeDirEntry{"foo"},
	}
	orig := readDir
	readDir = func(string) ([]os.DirEntry, error) { return entries, nil }
	t.Cleanup(func() { readDir = orig })

	// `fOo` is not in the list, so every candidate is reached through folding
	// and the rule has to choose. It must choose the same one every time.
	for i := 0; i < 50; i++ {
		got, ok := ResolveNorm(dir, "fOo", true)
		if !ok {
			t.Fatal("folded lookup should resolve")
		}
		if got != "FOO" {
			t.Fatalf("run %d: ResolveNorm(%q, foldCase) = %q, want %q (first in os.ReadDir order)",
				i, "fOo", got, "FOO")
		}
	}

	// Reordering the slice must not change the answer for a caller who sorts,
	// which is what os.ReadDir guarantees — this documents the dependency.
	entries = []os.DirEntry{fakeDirEntry{"foo"}, fakeDirEntry{"FOO"}}
	if got, _ := ResolveNorm(dir, "fOo", true); got != "foo" {
		t.Errorf("the rule is positional: got %q, want the first entry %q", got, "foo")
	}
}
