package vfs

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// nfdName produces an NFD-encoded version of s for use in test filenames.
// We use a simple example: "café" in NFC vs "café" in NFD.
var (
	// nfcCafe is the NFC form of "café" (single composed codepoint U+00E9).
	nfcCafe = norm.NFC.String("café")
	// nfdCafe is the NFD form of "café" (e + combining acute U+0301).
	nfdCafe = norm.NFD.String("café")
)

// TestResolveNorm_NFDthenNFC creates a file on disk with an NFD-encoded name,
// then looks it up via its NFC form and asserts it resolves to the NFD entry.
func TestResolveNorm_NFDthenNFC(t *testing.T) {
	dir := t.TempDir()

	// Create the file with the NFD name on disk.
	nfdPath := filepath.Join(dir, nfdCafe)
	if err := os.WriteFile(nfdPath, []byte("content"), 0644); err != nil {
		t.Fatalf("create NFD file: %v", err)
	}

	// Fast path (exact NFD match) should work.
	got, ok := ResolveNorm(dir, nfdCafe, false)
	if !ok {
		t.Error("ResolveNorm: exact NFD lookup should succeed")
	}
	if got != nfdCafe {
		t.Errorf("ResolveNorm exact: got %q, want %q", got, nfdCafe)
	}

	// Slow path (NFC request → NFD on disk) should also work.
	got2, ok2 := ResolveNorm(dir, nfcCafe, false)
	if !ok2 {
		t.Error("ResolveNorm: NFC lookup for NFD-on-disk should succeed")
	}
	// The returned name should be canonically equivalent to the on-disk NFD
	// name. On Linux the filesystem is byte-transparent so it comes back
	// exactly as NFD; on macOS the filesystem normalizes filenames, so we
	// compare normalization-equivalent forms rather than exact bytes.
	if norm.NFC.String(got2) != norm.NFC.String(nfdCafe) {
		t.Errorf("ResolveNorm NFC→NFD: got %q, want (normalization-equivalent to) %q", got2, nfdCafe)
	}
}

// TestResolveNorm_NFCthenNFD creates a file with an NFC name, then looks it
// up via NFD form.
func TestResolveNorm_NFCthenNFD(t *testing.T) {
	dir := t.TempDir()

	nfcPath := filepath.Join(dir, nfcCafe)
	if err := os.WriteFile(nfcPath, []byte("content"), 0644); err != nil {
		t.Fatalf("create NFC file: %v", err)
	}

	// Lookup via NFD form.
	got, ok := ResolveNorm(dir, nfdCafe, false)
	if !ok {
		t.Error("ResolveNorm: NFD lookup for NFC-on-disk should succeed")
	}
	// Compare normalization-equivalent forms: on macOS the filesystem
	// normalizes filenames, so the returned name may differ byte-for-byte
	// from nfcCafe while still being the same canonical string.
	if norm.NFC.String(got) != norm.NFC.String(nfcCafe) {
		t.Errorf("ResolveNorm NFD→NFC: got %q, want (normalization-equivalent to) %q", got, nfcCafe)
	}
}

// TestResolveNorm_ExactASCII verifies the fast path for a plain ASCII name.
func TestResolveNorm_ExactASCII(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got, ok := ResolveNorm(dir, "hello.txt", false)
	if !ok || got != "hello.txt" {
		t.Errorf("ResolveNorm ascii: ok=%v got=%q", ok, got)
	}
}

// TestResolveNorm_NotFound verifies that a missing entry returns false.
func TestResolveNorm_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, ok := ResolveNorm(dir, "nonexistent.txt", false)
	if ok {
		t.Error("ResolveNorm: missing file should return false")
	}
}

// TestResolveSecureNorm_DotDotWithinRoot verifies that a within-root path
// containing ".." resolves correctly (subdir/../file.txt → file.txt).
func TestResolveSecureNorm_DotDotWithinRoot(t *testing.T) {
	root := t.TempDir()

	// Create subdir and a file at the root level.
	if err := os.Mkdir(filepath.Join(root, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveSecureNorm(root, "subdir/../file.txt", false)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	want := filepath.Join(root, "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestResolveSecureNorm_DotDotEscapeRejected verifies that a ".." path that
// would escape the share root is still rejected with ErrTraversal.
func TestResolveSecureNorm_DotDotEscapeRejected(t *testing.T) {
	root := t.TempDir()

	_, err := ResolveSecureNorm(root, "../escape.txt", false)
	if err != ErrTraversal {
		t.Errorf("expected ErrTraversal, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Constant-time fallback: the lookup must not read the parent directory
// ---------------------------------------------------------------------------

// countDirScans installs a counting wrapper around the directory-scan hook and
// returns a pointer to the number of full directory reads performed since.
func countDirScans(t *testing.T) *int {
	t.Helper()
	n := 0
	orig := readDir
	readDir = func(name string) ([]os.DirEntry, error) {
		n++
		return orig(name)
	}
	t.Cleanup(func() { readDir = orig })
	return &n
}

// populate creates n throwaway entries in dir.
func populate(t *testing.T, dir string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, "entry-"+strconv.Itoa(i)+".dat"), nil, 0o644); err != nil {
			t.Fatalf("populate: %v", err)
		}
	}
}

// TestResolveNorm_MissingNameDoesNotScan is the regression guard for the
// defect this fallback was rewritten for: a name that does not exist (every
// new-file CREATE, every negative lookup) used to read the entire parent
// directory and normalize every entry name. It must now cost a fixed number
// of Lstat calls regardless of how many entries the directory holds.
func TestResolveNorm_MissingNameDoesNotScan(t *testing.T) {
	dir := t.TempDir()
	populate(t, dir, 2000)
	if err := os.WriteFile(filepath.Join(dir, nfdCafe), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	names := []string{
		"brand-new-file.txt",
		// Names holding the ASCII characters that a non-ASCII code point can
		// decompose to; these take the variant-probing path, which must also
		// stay scan-free.
		"Kelvin-Report.txt",
		"weird;name.txt",
		"back`tick.txt",
		"K;`.txt",
	}
	scans := countDirScans(t)
	for _, name := range names {
		if got, ok := ResolveNorm(dir, name, false); ok {
			t.Errorf("ResolveNorm(%q, false) = %q, true; want miss", name, got)
		}
	}
	if *scans != 0 {
		t.Errorf("missing-name lookups read the directory %d time(s); want 0", *scans)
	}
}

// TestResolveNorm_CrossNormalizationDoesNotScan verifies that the case the
// feature exists for — an NFD name on disk found through an NFC request — is
// served by direct Lstat probes rather than a directory scan.
func TestResolveNorm_CrossNormalizationDoesNotScan(t *testing.T) {
	dir := t.TempDir()
	populate(t, dir, 500)
	if err := os.WriteFile(filepath.Join(dir, nfdCafe), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	scans := countDirScans(t)
	got, ok := ResolveNorm(dir, nfcCafe, false)
	if !ok {
		t.Fatal("NFC lookup for NFD-on-disk entry should succeed")
	}
	if norm.NFC.String(got) != norm.NFC.String(nfdCafe) {
		t.Errorf("got %q, want (normalization-equivalent to) %q", got, nfdCafe)
	}
	if *scans != 0 {
		t.Errorf("cross-normalization lookup read the directory %d time(s); want 0", *scans)
	}
}

// TestASCIIFoldsIsComplete re-derives, from the Unicode tables actually
// compiled in, the set of code points whose canonical decomposition is pure
// ASCII, and asserts it matches asciiFolds exactly. The constant-time
// ASCII path is only correct while that table is complete, so this test is
// what makes a Unicode table update fail loudly instead of silently losing
// lookups.
func TestASCIIFoldsIsComplete(t *testing.T) {
	found := map[byte]rune{}
	for c := rune(utf8.RuneSelf); c <= 0x10FFFF; c++ {
		if c >= 0xD800 && c <= 0xDFFF { // surrogates are not valid runes
			continue
		}
		s := string(c)
		for _, folded := range []string{norm.NFC.String(s), norm.NFD.String(s)} {
			if folded == s || !isASCIIString(folded) {
				continue
			}
			if len(folded) != 1 {
				t.Fatalf("U+%04X folds to the multi-byte ASCII string %q; "+
					"asciiFoldVariants assumes single-byte folds", c, folded)
			}
			if prev, dup := found[folded[0]]; dup && prev != c {
				t.Fatalf("both U+%04X and U+%04X fold to %q; asciiFolds cannot "+
					"express that", prev, c, folded)
			}
			found[folded[0]] = c
		}
	}
	if len(found) != len(asciiFolds) {
		t.Fatalf("asciiFolds has %d entries, Unicode tables yield %d: %v",
			len(asciiFolds), len(found), found)
	}
	for b, c := range found {
		if asciiFolds[b] != c {
			t.Errorf("asciiFolds[%q] = U+%04X, want U+%04X", b, asciiFolds[b], c)
		}
	}
}

func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// TestResolveNorm_ASCIIFoldedOnDisk covers the trap in the ASCII fast path: a
// file stored under U+212A KELVIN SIGN (or U+037E, or U+1FEF) has a pure-ASCII
// NFC form, so an ASCII request must still find it even though the request is
// its own NFC and NFD form.
func TestResolveNorm_ASCIIFoldedOnDisk(t *testing.T) {
	cases := []struct {
		name      string
		onDisk    string // as stored on disk
		requested string // pure-ASCII request
	}{
		{"kelvin sign", "K.txt", "K.txt"},
		{"greek question mark", "semi;.txt", "semi;.txt"},
		{"greek varia", "grave`.txt", "grave`.txt"},
		{"two folds", "Kelvin;.txt", "Kelvin;.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.onDisk), []byte("payload"), 0o644); err != nil {
				t.Fatalf("create %q: %v", tc.onDisk, err)
			}
			got, ok := ResolveNorm(dir, tc.requested, false)
			if !ok {
				t.Fatalf("ResolveNorm(%q, false) missed the canonically equivalent entry %q",
					tc.requested, tc.onDisk)
			}
			// The returned leaf must actually open the file.
			data, err := os.ReadFile(filepath.Join(dir, got))
			if err != nil {
				t.Fatalf("resolved leaf %q is not usable: %v", got, err)
			}
			if string(data) != "payload" {
				t.Errorf("resolved leaf %q opened the wrong file", got)
			}
		})
	}
}

// TestResolveNorm_PartiallyComposedOnDisk pins the remaining slow path: a name
// stored in neither its NFC nor its NFD form (combining marks in
// non-canonical order) is still found, via the directory scan.
func TestResolveNorm_PartiallyComposedOnDisk(t *testing.T) {
	// "a" + COMBINING ACUTE + COMBINING CEDILLA: the marks are not in
	// canonical order, so this is neither the NFC nor the NFD form.
	onDisk := "á̧.txt"
	requested := norm.NFC.String(onDisk)
	if requested == onDisk || norm.NFD.String(onDisk) == onDisk {
		t.Skip("Unicode tables no longer make this name partially composed")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, onDisk), []byte("payload"), 0o644); err != nil {
		t.Fatalf("create partially composed name: %v", err)
	}
	got, ok := ResolveNorm(dir, requested, false)
	if !ok {
		t.Fatalf("ResolveNorm(%q, false) missed partially composed entry %q", requested, onDisk)
	}
	if norm.NFC.String(got) != norm.NFC.String(onDisk) {
		t.Errorf("got %q, want (normalization-equivalent to) %q", got, onDisk)
	}
}

// TestAsciiFoldVariants checks the variant enumeration directly.
func TestAsciiFoldVariants(t *testing.T) {
	cases := []struct {
		leaf       string
		want       []string
		exhaustive bool
	}{
		{"plain.txt", nil, true},
		{"K", []string{"K"}, true},
		{"K;", []string{"K;", "K;", "K;"}, true},
		// Non-ASCII: the class is not enumerable this way, caller must scan.
		{nfcCafe, nil, false},
		// Too many foldable characters: fall back to the scan.
		{"KKKK", nil, false},
	}
	for _, tc := range cases {
		got, exhaustive := asciiFoldVariants(tc.leaf)
		if exhaustive != tc.exhaustive {
			t.Errorf("asciiFoldVariants(%q) exhaustive=%v, want %v", tc.leaf, exhaustive, tc.exhaustive)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("asciiFoldVariants(%q) = %q, want %q", tc.leaf, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("asciiFoldVariants(%q)[%d] = %q, want %q", tc.leaf, i, got[i], tc.want[i])
			}
		}
		// Whatever is produced must be canonically equivalent to the request.
		for _, v := range got {
			if norm.NFC.String(v) != norm.NFC.String(tc.leaf) {
				t.Errorf("variant %q of %q is not canonically equivalent", v, tc.leaf)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// benchSizes are the directory sizes used by the scaling benchmarks. Before
// the constant-time fallback was added, a missing-name lookup read the whole
// parent directory, so cost grew linearly with these numbers.
var benchSizes = []int{0, 100, 1000, 10000}

// makeBenchDir creates a directory containing n plain files plus one file
// whose name is stored in NFD form, and returns the directory path.
func makeBenchDir(tb testing.TB, n int) string {
	tb.Helper()
	dir := tb.TempDir()
	for i := 0; i < n; i++ {
		name := filepath.Join(dir, "entry-"+strconv.Itoa(i)+".dat")
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			tb.Fatalf("populate dir: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, nfdCafe), nil, 0o644); err != nil {
		tb.Fatalf("create NFD entry: %v", err)
	}
	return dir
}

// BenchmarkResolveNormMissing measures the cost of resolving a name that does
// not exist — the path taken by every new-file CREATE and every negative
// lookup. It must not scale with the number of directory entries.
func BenchmarkResolveNormMissing(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(strconv.Itoa(n)+"-entries", func(b *testing.B) {
			dir := makeBenchDir(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := ResolveNorm(dir, "brand-new-file.txt", false); ok {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkResolveNormMissingASCIIFold is the same as the above but for a
// missing name containing one of the three ASCII characters that a non-ASCII
// code point can canonically decompose to (here "K", cf. U+212A KELVIN SIGN).
// These names cannot take an "it's ASCII, skip the fallback" shortcut, so this
// benchmark guards the variant-probing path specifically.
func BenchmarkResolveNormMissingASCIIFold(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(strconv.Itoa(n)+"-entries", func(b *testing.B) {
			dir := makeBenchDir(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := ResolveNorm(dir, "Kelvin-Report.txt", false); ok {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkResolveNormExisting measures the exact-match fast path, which was
// already flat and must stay flat.
func BenchmarkResolveNormExisting(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(strconv.Itoa(n)+"-entries", func(b *testing.B) {
			dir := makeBenchDir(b, n)
			if err := os.WriteFile(filepath.Join(dir, "existing.txt"), nil, 0o644); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := ResolveNorm(dir, "existing.txt", false); !ok {
					b.Fatal("expected hit")
				}
			}
		})
	}
}

// BenchmarkResolveNormCrossNormalization measures the case the feature exists
// for: the entry is stored NFD on disk and requested in NFC form. This used to
// require a full directory scan on every call.
func BenchmarkResolveNormCrossNormalization(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(strconv.Itoa(n)+"-entries", func(b *testing.B) {
			dir := makeBenchDir(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := ResolveNorm(dir, nfcCafe, false); !ok {
					b.Fatal("expected hit")
				}
			}
		})
	}
}

// BenchmarkResolveSecureNormMissing measures the full share-relative resolve
// for a new file in a populated directory (the end-to-end CREATE path).
func BenchmarkResolveSecureNormMissing(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(strconv.Itoa(n)+"-entries", func(b *testing.B) {
			root := b.TempDir()
			sub := filepath.Join(root, "sub")
			if err := os.Mkdir(sub, 0o755); err != nil {
				b.Fatal(err)
			}
			for i := 0; i < n; i++ {
				if err := os.WriteFile(filepath.Join(sub, "entry-"+strconv.Itoa(i)+".dat"), nil, 0o644); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := ResolveSecureNorm(root, `sub\brand-new-file.txt`, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
