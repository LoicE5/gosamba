// Package vfs handles share-relative path resolution and filesystem-info
// helpers for the SMB protocol.
package vfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrTraversal = errors.New("vfs: path escapes share root")

// ErrDanglingLink reports a symlink inside the share whose target does not
// exist. It is a refusal like ErrTraversal — the path cannot be resolved, so no
// caller may operate on it — but it is a DIFFERENT refusal: nothing escaped the
// share, the link simply points at something that is not there.
//
// The distinction exists because the two deserve different NTSTATUS codes. A
// containment failure is ACCESS_DENIED; a link that cannot be followed is
// OBJECT_PATH_NOT_FOUND, which is what statusFromErr already reports for the
// ELOOP the same situation produces one layer down. Collapsing both into
// ErrTraversal made a dangling in-share symlink look like an attempted escape.
//
// It deliberately does NOT wrap ErrTraversal: callers that merely test err !=
// nil (all of them today) keep refusing, and no caller can mistake a missing
// target for a proven escape.
var ErrDanglingLink = errors.New("vfs: symlink target does not exist")

// Resolve takes a share root (absolute, cleaned) and a client-supplied
// share-relative path (which may use either backslashes or forward slashes,
// may begin with a slash, may be empty for the root). Returns an absolute
// OS path that is guaranteed to lie under root, or ErrTraversal.
func Resolve(root, smbPath string) (string, error) {
	root = filepath.Clean(root)
	// Normalize slashes
	p := strings.ReplaceAll(smbPath, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return root, nil
	}
	full := filepath.Join(root, p)
	full = filepath.Clean(full)
	// Verify still under root.
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", ErrTraversal
	}
	return full, nil
}

// ResolveSecure is like Resolve but additionally enforces that no symlink in
// the resolved path escapes the share root. It does this by:
//
//  1. Performing the lexical Resolve check (dot-dot etc.) first.
//  2. Evaluating symlinks on the deepest existing ancestor of the candidate
//     path and confirming the real path still lives under the canonical
//     (EvalSymlinks'd) root.
//
// For paths whose final component does not exist yet (e.g. a CREATE for a new
// file), the parent directory is validated instead — this avoids a TOCTOU
// window on the leaf while still catching any escaping symlink in the parent
// chain.
//
// An in-share symlink whose resolved target remains within root is allowed and
// the lexical (un-resolved) path is returned so callers continue to see the
// expected share-relative location. A caller that needs to OPEN such a path
// must follow it with ResolveLink: the lexical path is the link itself, and an
// O_NOFOLLOW open of a link fails with ELOOP.
//
// Returns ErrTraversal when the path escapes the share root, and
// ErrDanglingLink when the leaf is a symlink inside the share whose target does
// not exist — both refusals, but different ones (see ErrDanglingLink).
func ResolveSecure(root, smbPath string) (string, error) {
	// Step 1: lexical containment (handles dot-dot, etc.).
	lexical, err := Resolve(root, smbPath)
	if err != nil {
		return "", err
	}

	// Step 2: canonicalize the root itself so we have a stable prefix to
	// compare against.
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		// Root doesn't exist — unexpected; fall back to lexical check only.
		return lexical, nil
	}
	canonRoot = filepath.Clean(canonRoot)

	// Step 3: find the deepest ancestor that exists on disk.
	// We walk from lexical toward root looking for the deepest existing path.
	checkPath := lexical
	for {
		_, statErr := os.Lstat(checkPath)
		if statErr == nil {
			// This path exists; evaluate symlinks to get real path.
			break
		}
		if !os.IsNotExist(statErr) {
			// Permission error or other — treat as not escapable; let the
			// subsequent filesystem op return the appropriate error.
			return lexical, nil
		}
		parent := filepath.Dir(checkPath)
		if parent == checkPath {
			// Reached filesystem root without finding any existing ancestor;
			// can't escape via symlink if nothing exists.
			return lexical, nil
		}
		checkPath = parent
	}

	// Step 4: evaluate all symlinks on the existing ancestor.
	real, err := filepath.EvalSymlinks(checkPath)
	if err != nil {
		// A missing target on a path that Lstat says exists means the leaf is a
		// dangling symlink. That is not a containment failure, and reporting it
		// as one made an ordinary broken link inside the share come back as
		// ACCESS_DENIED. Classify it separately — but only once the chain ABOVE
		// the link is proven contained, so a broken link reached THROUGH an
		// escaping directory symlink is still reported as the escape it is.
		if errors.Is(err, os.ErrNotExist) {
			// The parent has to be canonicalized before it can be compared:
			// canonRoot is symlink-free, and on a machine where the share sits
			// under one (macOS /var → /private/var) the lexical parent never
			// matches it.
			if parent, perr := filepath.EvalSymlinks(filepath.Dir(checkPath)); perr == nil &&
				contained(canonRoot, filepath.Clean(parent)) {
				return "", ErrDanglingLink
			}
		}
		// Unable to resolve — deny to be safe.
		return "", ErrTraversal
	}
	real = filepath.Clean(real)

	// Step 5: check that the real path is still under canonRoot.
	if !contained(canonRoot, real) {
		return "", ErrTraversal
	}

	return lexical, nil
}

// contained reports whether p is canonRoot itself or lies beneath it. Both must
// already be cleaned and free of symlinks, which is what EvalSymlinks gives.
func contained(canonRoot, p string) bool {
	return p == canonRoot || strings.HasPrefix(p, canonRoot+string(filepath.Separator))
}

// ResolveLink follows a symlink that lives inside the share and returns the
// real path of its target, which is guaranteed to lie under root.
//
// ResolveSecure deliberately returns the LEXICAL path of a symlink so callers
// keep seeing the share-relative location the client asked for. That is the
// right answer for naming the object (rename and unlink act on the link, as
// they do in POSIX), but not for opening it: opening the link path with
// O_NOFOLLOW fails with ELOOP, which is why an in-share symlink was unopenable
// over SMB even though the share is perfectly willing to serve its target.
//
// Callers use this to obtain the path they should actually open. Containment is
// re-proven here rather than assumed: ResolveSecure ran against the state of
// the filesystem at the time, and re-resolving now is what keeps a link that
// has since been repointed outside the share from being opened.
//
// Returns ErrDanglingLink when the target does not exist and ErrTraversal when
// it exists but lies outside root.
func ResolveLink(root, path string) (string, error) {
	canonRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		// Without a canonical root there is nothing to prove containment
		// against, so the only safe answer is to refuse.
		return "", ErrTraversal
	}
	canonRoot = filepath.Clean(canonRoot)

	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrDanglingLink
		}
		return "", ErrTraversal
	}
	target = filepath.Clean(target)
	if !contained(canonRoot, target) {
		return "", ErrTraversal
	}
	return target, nil
}

// ResolveSecureNorm is like ResolveSecure but applies a Unicode-normalization-
// insensitive fallback when looking up each path component. This allows a file
// created with an NFD-encoded name (typical on macOS) to be found by an NFC
// lookup (typical on Windows/Linux), and vice-versa.
//
// The fallback is applied component-by-component on the LOOKUP path only —
// directory listings and on-disk names are never rewritten. The resolved OS
// path uses the actual on-disk names, which are then validated by ResolveSecure
// to ensure containment within the share root.
//
// Fast path: if the lexical path resolves without any normalization miss, it
// delegates directly to ResolveSecure (no directory scanning overhead).
func ResolveSecureNorm(root, smbPath string) (string, error) {
	root = filepath.Clean(root)

	// Normalize slashes and split into components.
	p := strings.ReplaceAll(smbPath, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ResolveSecure(root, smbPath)
	}

	// Fast path: try lexical resolution first. If the path exists, no need to
	// walk component-by-component.
	lexical, err := Resolve(root, smbPath)
	if err != nil {
		return "", err
	}
	if _, statErr := os.Lstat(lexical); statErr == nil {
		// Exists as-is; delegate to the full symlink check.
		return ResolveSecure(root, smbPath)
	}

	// Slow path: resolve each component with normalization fallback.
	components := strings.Split(p, "/")
	current := root
	for _, comp := range components {
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			current = filepath.Dir(current)
			continue
		}
		resolved, ok := ResolveNorm(current, comp)
		if !ok {
			// Component not found even after normalization — keep the
			// requested name (e.g. for new-file CREATE paths).
			resolved = comp
		}
		current = filepath.Join(current, resolved)
	}

	// Validate the resolved path via ResolveSecure (symlink containment check).
	// We pass the resolved OS path as an already-absolute path. To convert it
	// to a share-relative form for ResolveSecure, compute the relative suffix.
	rel, err := filepath.Rel(root, current)
	if err != nil {
		return "", ErrTraversal
	}
	return ResolveSecure(root, rel)
}
