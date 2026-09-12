package parent

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// The server used to claim, unconditionally, that every share is case
// sensitive: the AAPL volume-capability bit in aapl.go and
// FILE_CASE_SENSITIVE_SEARCH in encodeFsInfo were both hard-coded on.
//
// SMBClient acts on the AAPL bit. Once AAPL negotiation marks the peer an OS X
// server, smbfs_check_name (smbfs_node.c) compares cached names with bcmp when
// the volume claims case sensitivity and strncasecmp when it does not, and
// smbfs_vfsops.c maps the same bit onto VOL_CAP_FMT_CASE_SENSITIVE. On a
// case-INSENSITIVE backing filesystem — the APFS and HFS+ default, i.e. the
// normal situation for this server on macOS — that produces two distinct
// vnodes, and therefore two page caches, aliasing one inode: a write through
// one is lost when the other flushes.
//
// These tests pin the fix: both claims are derived from one probe of the real
// filesystem, the probe runs once per share, and it never litters the share.

// resetCaseProbeCache empties the per-share probe cache so a test starts from a
// known state and does not leave fabricated answers behind for the next one.
func resetCaseProbeCache(t *testing.T) {
	t.Helper()
	caseProbeMu.Lock()
	caseProbes = map[string]*caseProbe{}
	caseProbeMu.Unlock()
}

// observedCaseSensitivity determines the truth about dir independently of the
// code under test: write one name, look for the other spelling.
//
// It is deliberately NOT a hardcoded expectation — a Linux CI runner (ext4) and
// a stock macOS box (APFS, case-insensitive) legitimately disagree, so every
// assertion below is about self-consistency with this observation.
func observedCaseSensitivity(t *testing.T, dir string) bool {
	t.Helper()
	lower := filepath.Join(dir, "casesens-ground-truth")
	if err := os.WriteFile(lower, []byte("x"), 0o600); err != nil {
		t.Fatalf("ground-truth write: %v", err)
	}
	defer os.Remove(lower)

	_, err := os.Lstat(filepath.Join(dir, "CASESENS-GROUND-TRUTH"))
	switch {
	case err == nil:
		return false // the flipped spelling resolved: case-insensitive
	case os.IsNotExist(err):
		return true
	default:
		t.Fatalf("ground-truth lstat: %v", err)
		return false
	}
}

func dirEntryNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// TestCaseProbe_MatchesFilesystemReality proves the probe reports what the
// filesystem under the test's temp dir actually does — by both routes, the
// write probe used for a normal share and the read-only probe used for a share
// we may not write to.
func TestCaseProbe_MatchesFilesystemReality(t *testing.T) {
	dir := t.TempDir()
	want := observedCaseSensitivity(t, dir)

	got, err := probeCaseSensitivity(dir, false)
	if err != nil {
		t.Fatalf("write probe failed: %v", err)
	}
	if got != want {
		t.Errorf("write probe = %v, filesystem really is %v", got, want)
	}

	// Give the read-only probe an existing entry with letters in its name.
	if err := os.WriteFile(filepath.Join(dir, "Anchor.txt"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = probeCaseByExistingEntry(dir)
	if err != nil {
		t.Fatalf("existing-entry probe failed: %v", err)
	}
	if got != want {
		t.Errorf("existing-entry probe = %v, filesystem really is %v", got, want)
	}

	// The machine running this test has exactly one kind of filesystem under
	// its temp dir (case-insensitive on a stock macOS, case-sensitive on a
	// Linux CI runner), so the other verdict is exercised by making the flipped
	// name come back ENOENT — which is precisely what a case-sensitive
	// filesystem does with a name that was written in the other case.
	orig := probeLstat
	probeLstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { probeLstat = orig })
	for _, probe := range []struct {
		name string
		fn   func(string) (bool, error)
	}{
		{"write", probeCaseByCreate},
		{"existing-entry", probeCaseByExistingEntry},
	} {
		got, err := probe.fn(dir)
		if err != nil {
			t.Fatalf("%s probe with a missing flipped name: %v", probe.name, err)
		}
		if !got {
			t.Errorf("%s probe reported case-insensitive although the flipped name does not exist", probe.name)
		}
	}
}

// TestCaseProbe_LeavesNoFileBehind proves the write probe cleans up its
// temporary file — on the happy path and when it fails partway, after the file
// exists but before the answer is known.
func TestCaseProbe_LeavesNoFileBehind(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := probeCaseSensitivity(dir, false); err != nil {
			t.Fatalf("probe failed: %v", err)
		}
		if names := dirEntryNames(t, dir); len(names) != 0 {
			t.Fatalf("probe left %v behind", names)
		}
	})

	t.Run("fails after creating the file", func(t *testing.T) {
		dir := t.TempDir()
		// The lookup blows up once the probe file is already on disk. The
		// cleanup is a defer registered right after the create, so it must
		// still run.
		boom := errors.New("synthetic lstat failure")
		orig := probeLstat
		probeLstat = func(string) (os.FileInfo, error) { return nil, boom }
		t.Cleanup(func() { probeLstat = orig })

		if _, err := probeCaseSensitivity(dir, false); err == nil {
			t.Fatal("probe returned success despite a failing lstat")
		}
		for _, n := range dirEntryNames(t, dir) {
			if strings.HasPrefix(n, caseProbePrefix) {
				t.Fatalf("failed probe left stray probe file %q behind", n)
			}
			t.Fatalf("failed probe left %q behind", n)
		}
	})

	t.Run("failure falls back, never fails the share", func(t *testing.T) {
		resetCaseProbeCache(t)
		dir := t.TempDir()
		orig := probeLstat
		probeLstat = func(string) (os.FileInfo, error) { return nil, errors.New("synthetic lstat failure") }
		t.Cleanup(func() {
			probeLstat = orig
			resetCaseProbeCache(t)
		})

		tree := &Tree{Share: config.ShareConfig{Name: "share", Path: dir}}
		if shareCaseSensitive(tree) != caseSensitivityFallback {
			t.Fatalf("unprobeable share reported %v, want the %v fallback",
				!caseSensitivityFallback, caseSensitivityFallback)
		}
		if names := dirEntryNames(t, dir); len(names) != 0 {
			t.Fatalf("failed probe left %v behind", names)
		}
	})
}

// aaplVolumeCapsReqCtx builds the AAPL SERVER_QUERY create context macOS sends,
// asking for volume capabilities only (so the response's volume-caps field sits
// at a fixed offset).
func aaplVolumeCapsReqCtx() []byte {
	var data [24]byte
	binary.LittleEndian.PutUint32(data[0:], aaplCmdServerQuery)
	binary.LittleEndian.PutUint64(data[8:], aaplBitVolumeCaps)
	return smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: []byte("AAPL"), Data: data[:]}})
}

// aaplVolumeCapsFor drives the real create-context builder and returns the
// volume-capability bitmap the client would see.
func aaplVolumeCapsFor(t *testing.T, tree *Tree) uint64 {
	t.Helper()
	out := buildCreateResponseContexts(aaplVolumeCapsReqCtx(), nil, tree, 0x001F01FF, 0, 0)
	data, ok := findContext(out, "AAPL")
	if !ok {
		t.Fatal("no AAPL response context emitted")
	}
	// cmd(4) + reserved(4) + reqBitmap(8) + volumeCaps(8)
	if len(data) < 24 {
		t.Fatalf("AAPL response too short: %d bytes", len(data))
	}
	return binary.LittleEndian.Uint64(data[16:24])
}

// TestCaseSensitivity_AAPLAndFsAttrsAgree proves the two places that claim case
// sensitivity cannot contradict each other. A client that reads the AAPL volume
// capability and one that reads FileFsAttributeInformation must be told the
// same thing about the same share.
func TestCaseSensitivity_AAPLAndFsAttrsAgree(t *testing.T) {
	dir := t.TempDir()
	tree := &Tree{Share: config.ShareConfig{Name: "share", Path: dir}}

	// First against the real filesystem.
	resetCaseProbeCache(t)
	actual := shareCaseSensitive(tree)
	if want := observedCaseSensitivity(t, dir); actual != want {
		t.Fatalf("share reported case_sensitive=%v, filesystem really is %v", actual, want)
	}
	assertClaimsAgree(t, tree, actual)

	// Then with the probe forced both ways, so agreement is proven in both
	// directions regardless of what the host filesystem happens to be.
	orig := probeCaseSensitivityFn
	t.Cleanup(func() {
		probeCaseSensitivityFn = orig
		resetCaseProbeCache(t)
	})
	for _, forced := range []bool{true, false} {
		resetCaseProbeCache(t)
		probeCaseSensitivityFn = func(string, bool) (bool, error) { return forced, nil }
		assertClaimsAgree(t, tree, forced)
	}
}

func assertClaimsAgree(t *testing.T, tree *Tree, want bool) {
	t.Helper()

	aaplCaps := aaplVolumeCapsFor(t, tree)
	aaplSensitive := aaplCaps&aaplVolCaseSensitive != 0

	o := &Open{Path: tree.Share.Path, Tree: tree}
	buf, ok := encodeFsInfo(smb2.FileFsAttributeInformation, o)
	if !ok || len(buf) < 4 {
		t.Fatal("encodeFsInfo FileFsAttributeInformation failed")
	}
	fsAttrs := binary.LittleEndian.Uint32(buf[0:4])
	fsSensitive := fsAttrs&fileCaseSensitiveSearch != 0

	if aaplSensitive != fsSensitive {
		t.Fatalf("contradiction: AAPL volume caps say case_sensitive=%v (caps=%#x) but FileFsAttributeInformation says %v (attrs=%#08x)",
			aaplSensitive, aaplCaps, fsSensitive, fsAttrs)
	}
	if aaplSensitive != want {
		t.Fatalf("claims say case_sensitive=%v, want %v", aaplSensitive, want)
	}
	// FULL_SYNC is unrelated to case and must survive.
	if aaplCaps&aaplVolFullSync == 0 {
		t.Errorf("AAPL volume caps dropped FULL_SYNC: %#x", aaplCaps)
	}
	// The unconditional filesystem-attribute bits must be untouched.
	if fsAttrs&fsAttrsBase != fsAttrsBase {
		t.Errorf("fs attributes lost a base bit: %#08x, want %#08x set", fsAttrs, fsAttrsBase)
	}
}

// TestCaseProbe_ReadOnlyShareFallback documents what a share we may not write
// to reports.
//
// A read-only share is never probed by creating a file. If it holds an entry
// whose name has an ASCII letter, that entry answers the question for free. If
// it does not (an empty share, an unreadable root), we report case-INSENSITIVE:
// understating sensitivity makes SMBClient fall back to strncasecmp and merge
// the two vnodes, whereas overstating it aliases one inode behind two page
// caches and loses writes.
func TestCaseProbe_ReadOnlyShareFallback(t *testing.T) {
	t.Run("empty share falls back to case-insensitive", func(t *testing.T) {
		resetCaseProbeCache(t)
		t.Cleanup(func() { resetCaseProbeCache(t) })
		dir := t.TempDir()
		tree := &Tree{Share: config.ShareConfig{Name: "ro", Path: dir, ReadOnly: true}}

		if got := shareCaseSensitive(tree); got != caseSensitivityFallback {
			t.Errorf("unprobeable read-only share reported %v, want %v", got, caseSensitivityFallback)
		}
		// And it must not have tried to write to the share to find out.
		if names := dirEntryNames(t, dir); len(names) != 0 {
			t.Fatalf("read-only share was written to: %v", names)
		}
		assertClaimsAgree(t, tree, caseSensitivityFallback)
	})

	t.Run("existing entry is used when there is one", func(t *testing.T) {
		resetCaseProbeCache(t)
		t.Cleanup(func() { resetCaseProbeCache(t) })
		dir := t.TempDir()
		want := observedCaseSensitivity(t, dir)
		if err := os.WriteFile(filepath.Join(dir, "Readme.txt"), []byte("z"), 0o600); err != nil {
			t.Fatal(err)
		}
		tree := &Tree{Share: config.ShareConfig{Name: "ro", Path: dir, ReadOnly: true}}

		if got := shareCaseSensitive(tree); got != want {
			t.Errorf("read-only share reported %v, filesystem really is %v", got, want)
		}
		if names := dirEntryNames(t, dir); len(names) != 1 || names[0] != "Readme.txt" {
			t.Fatalf("read-only share contents changed: %v", names)
		}
	})
}

// TestCaseProbe_RunsOncePerShare proves the probe is a startup-ish cost, not a
// per-request one: it touches the filesystem once per share root no matter how
// many CREATEs, QUERY_INFOs, connections or goroutines ask.
func TestCaseProbe_RunsOncePerShare(t *testing.T) {
	resetCaseProbeCache(t)
	var probes int64
	orig := probeCaseSensitivityFn
	probeCaseSensitivityFn = func(root string, readOnly bool) (bool, error) {
		atomic.AddInt64(&probes, 1)
		return orig(root, readOnly)
	}
	t.Cleanup(func() {
		probeCaseSensitivityFn = orig
		resetCaseProbeCache(t)
	})

	dirA, dirB := t.TempDir(), t.TempDir()
	treeA := &Tree{Share: config.ShareConfig{Name: "a", Path: dirA}}
	treeB := &Tree{Share: config.ShareConfig{Name: "b", Path: dirB}}
	// A second tree over the same share — a second TREE_CONNECT — must reuse
	// the first one's answer.
	treeA2 := &Tree{ID: 2, Share: config.ShareConfig{Name: "a", Path: dirA + "/"}}

	openA := &Open{Path: dirA, Tree: treeA}
	for i := 0; i < 20; i++ {
		// Every request path that can claim case sensitivity.
		_ = aaplVolumeCapsFor(t, treeA)
		if _, ok := encodeFsInfo(smb2.FileFsAttributeInformation, openA); !ok {
			t.Fatal("encodeFsInfo failed")
		}
		_ = shareCaseSensitive(treeA2)
	}
	if got := atomic.LoadInt64(&probes); got != 1 {
		t.Fatalf("share A probed %d times, want exactly 1", got)
	}

	// Concurrent first use of a second share still probes it exactly once.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = shareCaseSensitive(treeB)
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt64(&probes); got != 2 {
		t.Fatalf("%d probes after adding share B, want exactly 2", got)
	}

	// A tree with no backing path (IPC$) is never probed at all.
	if shareCaseSensitive(&Tree{Share: config.ShareConfig{Name: "IPC$"}}) != caseSensitivityFallback {
		t.Error("IPC$ tree should report the fallback")
	}
	if shareCaseSensitive(nil) != caseSensitivityFallback {
		t.Error("nil tree should report the fallback")
	}
	if got := atomic.LoadInt64(&probes); got != 2 {
		t.Fatalf("pathless trees triggered a probe: %d probes", got)
	}
}

// TestFlipASCIICase covers the helper the read-only probe leans on: it must
// change something to be a useful probe, and it must leave non-ASCII alone
// (non-ASCII case mapping is locale- and normalization-dependent, so a flip we
// perform differently from the filesystem would fake case sensitivity).
func TestFlipASCIICase(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"Readme.txt", "rEADME.TXT", true},
		{"a", "A", true},
		{"1234", "1234", false},
		{".", ".", false},
		// ASCII letters flip; the accented runes are left exactly as they are.
		{"résumé", "RéSUMé", true},
		// Nothing but non-ASCII: no usable flip, so the probe skips the name
		// rather than inventing a case mapping of its own.
		{"üöä", "üöä", false},
		{"日本語", "日本語", false},
	}

	for _, tc := range tests {
		got, ok := flipASCIICase(tc.in)
		if ok != tc.wantOK {
			t.Errorf("flipASCIICase(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
		}
		if ok && got != tc.want {
			t.Errorf("flipASCIICase(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !ok && got != tc.in {
			t.Errorf("flipASCIICase(%q) returned %q with ok=false, want the input back", tc.in, got)
		}
	}
}
