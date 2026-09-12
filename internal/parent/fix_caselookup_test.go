package parent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/vfs"
)

// The lookup and the open used to disagree about case.
//
// matchSMBPattern folded case unconditionally; vfs.ResolveNorm was
// normalization-insensitive but case-SENSITIVE. macOS resolves a single name
// through a QUERY_DIRECTORY whose pattern is the exact leaf name (SMBClient
// smb2fs_smb_cmpd_query_dir_one), so on a case-sensitive backing filesystem a
// request for `foo` matched an on-disk `Foo` during the lookup, the client was
// told the file existed, and the CREATE that followed resolved case-sensitively
// and answered STATUS_NO_SUCH_FILE. SMBClient maps that to ENOENT and parks it
// in the negative name cache, which only clears once the parent directory's
// mtime advances. On a case-insensitive filesystem the resolver's exact-match
// fast path hid the whole thing, so it bit Linux and not APFS.
//
// Both halves now follow the same per-share probe. These tests pin that they
// cannot drift apart again.

// errProbeUnavailable stands in for a share the probe cannot measure: an empty
// read-only share, an unreadable root. shareCaseSensitive then falls back to
// reporting case-insensitive, and shareFoldsCase turns folding on because
// nothing underneath the share is folding for us.
var errProbeUnavailable = errors.New("test: share not probeable")

// caseState is one of the three states shareFoldsCase distinguishes.
type caseState struct {
	name  string
	probe func(string, bool) (bool, error)
}

var (
	probedSensitive   = caseState{"probed case-sensitive", func(string, bool) (bool, error) { return true, nil }}
	probedInsensitive = caseState{"probed case-insensitive", func(string, bool) (bool, error) { return false, nil }}
	unprobeable       = caseState{"unprobeable", func(string, bool) (bool, error) { return false, errProbeUnavailable }}
)

// forceCaseProbe installs state for the rest of the test and clears the
// per-share cache around it so nothing leaks into the next one.
func forceCaseProbe(t *testing.T, state caseState) {
	t.Helper()
	orig := probeCaseSensitivityFn
	resetCaseProbeCache(t)
	probeCaseSensitivityFn = state.probe
	t.Cleanup(func() {
		probeCaseSensitivityFn = orig
		resetCaseProbeCache(t)
	})
}

// TestShareFoldsCaseDistinguishesThreeStates pins the layering decision: the
// value handed to the resolver is deliberately NOT the complement of the value
// put on the wire, because "the share is case-insensitive" and "the server has
// to fold case itself" are different questions.
func TestShareFoldsCaseDistinguishesThreeStates(t *testing.T) {
	dir := t.TempDir()
	tree := &Tree{Share: config.ShareConfig{Name: "share", Path: dir}}

	for _, c := range []struct {
		state         caseState
		wantSensitive bool
		wantFoldsCase bool
		why           string
	}{
		{probedSensitive, true, false,
			"`Foo` and `foo` are different files; the resolver must not paper over that"},
		{probedInsensitive, false, false,
			"the filesystem folds before we see the name, so the first Lstat has already resolved every spelling and a miss is conclusive"},
		{unprobeable, false, true,
			"reported case-insensitive with nothing underneath folding; the server has to do it"},
	} {
		t.Run(c.state.name, func(t *testing.T) {
			forceCaseProbe(t, c.state)
			if got := shareCaseSensitive(tree); got != c.wantSensitive {
				t.Errorf("shareCaseSensitive = %v, want %v", got, c.wantSensitive)
			}
			if got := shareFoldsCase(tree); got != c.wantFoldsCase {
				t.Errorf("shareFoldsCase = %v, want %v (%s)", got, c.wantFoldsCase, c.why)
			}
		})
	}

	// IPC$ has no backing filesystem: nothing to probe, nothing to fold.
	if shareFoldsCase(&Tree{Share: config.ShareConfig{Name: "IPC$"}}) {
		t.Error("shareFoldsCase(IPC$) = true; there is no filesystem to fold for")
	}
	if shareFoldsCase(nil) {
		t.Error("shareFoldsCase(nil) = true; want false")
	}
}

// TestCaseLookupMatcherFollowsProbe is the first half of the required
// behaviour: with the share probed case-sensitive, `foo` no longer matches an
// on-disk `Foo`, so the one-entry QUERY_DIRECTORY macOS uses to resolve a name
// tells the client the truth up front instead of promising a file the CREATE
// will refuse.
func TestCaseLookupMatcherFollowsProbe(t *testing.T) {
	dir := t.TempDir()
	tree := &Tree{Share: config.ShareConfig{Name: "share", Path: dir}}

	forceCaseProbe(t, probedSensitive)
	if matchSMBPattern("foo", "Foo", shareCaseSensitive(tree)) {
		t.Error("on a case-sensitive share the pattern `foo` must not match the entry `Foo`")
	}
	if !matchSMBPattern("Foo", "Foo", shareCaseSensitive(tree)) {
		t.Error("the exact name must always match")
	}

	forceCaseProbe(t, probedInsensitive)
	if !matchSMBPattern("foo", "Foo", shareCaseSensitive(tree)) {
		t.Error("on a case-insensitive share the pattern `foo` must match the entry `Foo`")
	}
}

// TestCaseLookupAndOpenAgree is the invariant the whole fix exists for, stated
// directly: anything the lookup says exists must actually open.
//
// It runs the real matcher against a real directory and then asks the real
// resolver, with exactly the two values dispatch.go passes — shareCaseSensitive
// for the matcher, shareFoldsCase for the resolver — so a future change that
// moves one without the other fails here.
//
// The state under test is chosen to match the filesystem the test is running
// on, because "probed case-insensitive" on a filesystem that does not fold is
// a self-contradiction, not a configuration: a probe that ran cannot report
// something the filesystem does not do. On a case-folding filesystem (a stock
// macOS, APFS) that is the measured state; on a case-sensitive one (a Linux CI
// runner, ext4) the share is reported case-insensitive only when the probe
// could not run, so that is the state exercised there. Either way the assertion
// is the same and the fold path is exercised on both.
func TestCaseLookupAndOpenAgree(t *testing.T) {
	dir := t.TempDir()
	tree := &Tree{Share: config.ShareConfig{Name: "share", Path: dir}}

	onDisk := []string{"Foo", "README.md", "Mixed Case Name.TXT", "café.txt"}
	for _, name := range onDisk {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fsIsSensitive := observedCaseSensitivity(t, dir)

	reportedInsensitive := probedInsensitive
	if fsIsSensitive {
		reportedInsensitive = unprobeable
	}

	for _, state := range []caseState{probedSensitive, reportedInsensitive} {
		t.Run(state.name, func(t *testing.T) {
			forceCaseProbe(t, state)
			caseSensitive := shareCaseSensitive(tree)
			foldCase := shareFoldsCase(tree)

			requests := []string{}
			for _, name := range onDisk {
				requests = append(requests, name,
					strings.ToLower(name), strings.ToUpper(name))
			}
			requests = append(requests, "no-such-file.txt", "NO-SUCH-FILE.TXT")

			for _, requested := range requests {
				// The lookup: macOS sends the leaf name as the pattern and
				// keeps whatever entry comes back.
				matched := ""
				for _, name := range onDisk {
					if matchSMBPattern(requested, name, caseSensitive) {
						matched = name
						break
					}
				}
				// The open: the CREATE that follows resolves the same name.
				resolved, err := vfs.ResolveSecureNorm(dir, requested, foldCase)
				opens := false
				if err == nil {
					_, statErr := os.Lstat(resolved)
					opens = statErr == nil
				}

				if matched != "" && !opens {
					t.Errorf("QUERY_DIRECTORY(%q) matched the entry %q but the CREATE that follows "+
						"cannot open it (resolved %q): the client caches this as ENOENT",
						requested, matched, resolved)
				}
			}
		})
	}
}

// TestCaseLookupInsensitiveShareOpensOtherSpelling is the second half of the
// required behaviour: on a share reported case-insensitive, `foo` both matches
// and opens an on-disk `Foo`. See TestCaseLookupAndOpenAgree for why the state
// is picked from the filesystem.
func TestCaseLookupInsensitiveShareOpensOtherSpelling(t *testing.T) {
	dir := t.TempDir()
	tree := &Tree{Share: config.ShareConfig{Name: "share", Path: dir}}
	if err := os.WriteFile(filepath.Join(dir, "Foo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := probedInsensitive
	if observedCaseSensitivity(t, dir) {
		state = unprobeable
	}
	forceCaseProbe(t, state)

	if !matchSMBPattern("foo", "Foo", shareCaseSensitive(tree)) {
		t.Fatal("the lookup must match `Foo` for a request of `foo`")
	}
	resolved, err := vfs.ResolveSecureNorm(dir, "foo", shareFoldsCase(tree))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := os.Lstat(resolved)
	if err != nil {
		t.Fatalf("the lookup matched but the open failed: %v", err)
	}
	want, err := os.Lstat(filepath.Join(dir, "Foo"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(got, want) {
		t.Errorf("resolved %q, which is not the file that was created", resolved)
	}
}

// TestFoldRuneAgreesWithFoldEqual is what keeps the two halves from drifting
// apart at the character level. The matcher decides case equality by walking a
// rune's unicode.SimpleFold orbit; the resolver decides it by reducing an orbit
// to its smallest member. They are the same equivalence stated two ways, and
// nothing but this test says so.
//
// The proof is complete rather than sampled: every rune's whole orbit, plus
// every ASCII pair, which is the one place foldEqual takes a different branch.
func TestFoldRuneAgreesWithFoldEqual(t *testing.T) {
	orbits := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF { // surrogates are not valid runes
			continue
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if !foldEqual(r, f) {
				t.Fatalf("foldEqual(U+%04X, U+%04X) = false but they share a folding orbit", r, f)
			}
			if vfs.FoldRune(r) != vfs.FoldRune(f) {
				t.Fatalf("FoldRune(U+%04X) = U+%04X, FoldRune(U+%04X) = U+%04X; "+
					"the resolver would key one orbit two ways", r, vfs.FoldRune(r), f, vfs.FoldRune(f))
			}
			orbits++
		}
	}
	if orbits < 1000 {
		t.Fatalf("only %d orbit members walked; the Unicode tables look wrong", orbits)
	}

	// ASCII is where foldEqual has its own branch (a blanket |0x20 would equate
	// `_` with `?`), so check every pair against the resolver's key.
	for a := rune(0); a < utf8.RuneSelf; a++ {
		for b := rune(0); b < utf8.RuneSelf; b++ {
			if got, want := foldEqual(a, b), vfs.FoldRune(a) == vfs.FoldRune(b); got != want {
				t.Fatalf("foldEqual(%q, %q) = %v but FoldRune agreement says %v", a, b, got, want)
			}
		}
	}

	// And the cross-over the ASCII branch must NOT hide: U+212A KELVIN SIGN is
	// case-equal to `k` for both, which is why an ASCII-only shortcut in either
	// implementation would be wrong.
	if !foldEqual('K', 'k') || vfs.FoldRune('K') != vfs.FoldRune('k') {
		t.Error("U+212A KELVIN SIGN must fold together with `k` in both implementations")
	}
}
