package vfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ResolveSecure returns the LEXICAL path of a symlink, which is the right
// answer for naming the object but not for opening it: an O_NOFOLLOW open of
// that path fails with ELOOP. ResolveLink is the second half — the target the
// caller should actually open — and it re-proves containment rather than
// trusting the earlier resolve, because the link may have been repointed since.
//
// The other half of these tests is the refusal that stopped being a blanket
// ErrTraversal: a broken link inside the share is not an escape attempt, and
// reporting it as one made an ordinary dangling symlink come back to the client
// as ACCESS_DENIED instead of "not there".

func TestResolveLink_InShareTargetResolves(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink("target.txt", link); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveLink(root, link)
	if err != nil {
		t.Fatalf("ResolveLink: %v", err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("ResolveLink = %q, want %q", got, want)
	}
}

// A chain of links has to be followed to its end; only the final target's
// location decides whether the open is allowed.
func TestResolveLink_ChainInsideShareResolves(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(root, "first")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("first", filepath.Join(root, "second")); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveLink(root, filepath.Join(root, "second"))
	if err != nil {
		t.Fatalf("ResolveLink: %v", err)
	}
	want, _ := filepath.EvalSymlinks(target)
	if got != want {
		t.Errorf("ResolveLink = %q, want %q", got, want)
	}
}

func TestResolveLink_EscapingTargetRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"file outside": secret,
		"dir outside":  outside,
		"parent of the share": filepath.Dir(func() string {
			real, _ := filepath.EvalSymlinks(root)
			return real
		}()),
	}
	for name, target := range cases {
		link := filepath.Join(root, "link-"+filepath.Base(name))
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveLink(root, link)
		if !errors.Is(err, ErrTraversal) {
			t.Errorf("%s: ResolveLink = (%q, %v), want ErrTraversal", name, got, err)
		}
		if got != "" {
			t.Errorf("%s: ResolveLink returned %q with an error", name, got)
		}
	}
}

// A link that escapes must stay refused even when it is repointed AFTER an
// earlier resolve approved it — which is the whole reason containment is
// re-proven here rather than inherited.
func TestResolveLink_RepointedOutsideRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(root, "target.txt")
	if err := os.WriteFile(inside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLink(root, link); err != nil {
		t.Fatalf("ResolveLink before repoint: %v", err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "elsewhere.txt"), link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "elsewhere.txt"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLink(root, link); !errors.Is(err, ErrTraversal) {
		t.Errorf("ResolveLink after repoint: err = %v, want ErrTraversal", err)
	}
}

func TestResolveLink_DanglingReported(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "broken.txt")
	if err := os.Symlink("gone.txt", link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLink(root, link); !errors.Is(err, ErrDanglingLink) {
		t.Errorf("ResolveLink of a dangling link: err = %v, want ErrDanglingLink", err)
	}
}

// ResolveSecure has to make the same distinction one layer up, because that is
// where a CREATE for a broken link is refused.
func TestResolveSecure_DanglingLinkIsNotTraversal(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("gone.txt", filepath.Join(root, "broken.txt")); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveSecure(root, "broken.txt")
	if !errors.Is(err, ErrDanglingLink) {
		t.Fatalf("ResolveSecure = (%q, %v), want ErrDanglingLink", got, err)
	}
	if got != "" {
		t.Errorf("ResolveSecure returned %q alongside the error", got)
	}
	// The two refusals must stay distinguishable in both directions, or the
	// caller cannot pick a status from them.
	if errors.Is(err, ErrTraversal) {
		t.Error("ErrDanglingLink matches ErrTraversal: the statuses would collapse again")
	}
	if errors.Is(ErrTraversal, ErrDanglingLink) {
		t.Error("ErrTraversal matches ErrDanglingLink")
	}
}

// A broken link reached THROUGH an escaping directory symlink is an escape, and
// must be reported as one — the missing target is not the interesting part.
func TestResolveSecure_DanglingBeyondEscapeIsTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink("gone.txt", filepath.Join(outside, "broken.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveSecure(root, "escape/broken.txt"); !errors.Is(err, ErrTraversal) {
		t.Errorf("ResolveSecure through an escaping link: err = %v, want ErrTraversal", err)
	}
}

// A name that simply does not exist yet is not a dangling link: CREATE depends
// on it resolving so the file can be made.
func TestResolveSecure_MissingNameStillResolves(t *testing.T) {
	root := t.TempDir()
	got, err := ResolveSecure(root, "newfile.txt")
	if err != nil {
		t.Fatalf("ResolveSecure of a new name: %v", err)
	}
	if want := filepath.Join(root, "newfile.txt"); got != want {
		t.Errorf("ResolveSecure = %q, want %q", got, want)
	}
}
