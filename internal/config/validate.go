package config

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// parseNumericSystemUser interprets a system_user spec as numeric ids so the
// uid/gid can be resolved without reading /etc/passwd.
//
//   - "1000"       -> uid=1000, gid=1000, ok=true
//   - "1000/1001"  -> uid=1000, gid=1001, ok=true
//   - "alice"      -> ok=false (it is a name; caller must look it up)
//
// ok=false with a nil error means the spec is a name, not a number. A non-nil
// error means the spec looked numeric (contains '/') but was malformed.
func parseNumericSystemUser(spec string) (uid, gid int, ok bool, err error) {
	if u, g, hasSlash := strings.Cut(spec, "/"); hasSlash {
		uid, uerr := strconv.Atoi(u)
		gid, gerr := strconv.Atoi(g)
		if uerr != nil || gerr != nil {
			return 0, 0, false, fmt.Errorf("system_user %q: uid/gid form requires two integers", spec)
		}
		return uid, gid, true, nil
	}
	n, nerr := strconv.Atoi(spec)
	if nerr != nil {
		return 0, 0, false, nil // not numeric: treat as a name
	}
	return n, n, true, nil
}

// Validate inspects cfg, fills SystemUID/SystemGID from SystemUser, and
// rejects invalid configurations.
func Validate(cfg *Config) error {
	if _, _, err := net.SplitHostPort(cfg.Server.Listen); err != nil {
		return fmt.Errorf("listen %q: %w", cfg.Server.Listen, err)
	}

	switch cfg.Server.Encryption {
	case EncryptionRequired, EncryptionPreferred, EncryptionOff:
	default:
		return fmt.Errorf("encryption %q: must be required|preferred|off", cfg.Server.Encryption)
	}
	switch cfg.Server.Signing {
	case SigningRequired, SigningPreferred:
	default:
		return fmt.Errorf("signing %q: must be required|preferred", cfg.Server.Signing)
	}
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q: must be debug|info|warn|error", cfg.Log.Level)
	}
	switch cfg.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format %q: must be text|json", cfg.Log.Format)
	}

	// NetBIOS is parsed and merged but nothing ever binds :139 — there is no
	// NBSS listener in the server. Silently accepting the flag would let an
	// operator believe legacy clients can reach the server when they cannot,
	// so refuse to start rather than lie. SMB2/3 needs only :445.
	if cfg.Server.Netbios {
		return fmt.Errorf("netbios: not implemented — nothing binds :139; remove --netbios / netbios = true (SMB2/3 uses :445 only)")
	}

	// Share names are matched case-insensitively at TREE_CONNECT
	// (strings.EqualFold in parent/dispatch.go), so "Work" and "work" are the
	// same share to a client but two entries here: the first would always win
	// and the second would be permanently unreachable. Compare the same way
	// the lookup does so the ambiguity is rejected instead of silently
	// resolved.
	seenShares := make(map[string]struct{})
	for i, s := range cfg.Shares {
		if s.Name == "" {
			return fmt.Errorf("share[%d]: name is empty", i)
		}
		if s.Name == "." || s.Name == ".." {
			return fmt.Errorf("share %q: name is reserved; choose a descriptive name with <path>=<name> or set name in the config file", s.Name)
		}
		key := strings.ToLower(s.Name)
		if _, dup := seenShares[key]; dup {
			return fmt.Errorf("share %q: duplicate name (share names are matched case-insensitively)", s.Name)
		}
		seenShares[key] = struct{}{}

		st, err := os.Stat(s.Path)
		if err != nil {
			return fmt.Errorf("share %q: path %q: %w", s.Name, s.Path, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("share %q: path %q is not a directory", s.Name, s.Path)
		}
	}

	// zeroHash is what a user is left with when no credential ever reached it:
	// file.go skips the hex decode when nt_hash is missing or empty, leaving
	// NTHash at its zero value. See the check below.
	var zeroHash [16]byte

	seenUsers := make(map[string]struct{})
	for i, u := range cfg.Users {
		if u.Name == "" {
			return fmt.Errorf("user[%d]: name is empty", i)
		}
		// SESSION_SETUP resolves the account name with strings.EqualFold
		// (parent/session.go) and takes the first match, so two users
		// differing only in case collide: the second one's password and
		// allow_shares would never take effect while the config still looks
		// like it granted them. Reject the ambiguity.
		nameKey := strings.ToLower(u.Name)
		if _, dup := seenUsers[nameKey]; dup {
			return fmt.Errorf("user %q: duplicate name (user names are matched case-insensitively)", u.Name)
		}
		seenUsers[nameKey] = struct{}{}

		// An all-zero NT hash is not a credential — it is the absence of one.
		// MD4 never produces 16 zero bytes for any password, so this value can
		// only come from a missing, misspelled or empty nt_hash (or from an
		// operator literally pasting zeros). Left unchecked it fails open
		// silently: NTLMv2 verification would succeed for anyone who computes
		// the response against 16 zero bytes, i.e. the account becomes
		// world-authenticatable. Every account must carry a real hash, whether
		// it came from nt_hash in the file or was derived from -u's password.
		if u.NTHash == zeroHash {
			return fmt.Errorf("user %q: no usable credential — set nt_hash (generate one with `gosamba hash`) or define the user with -u %s:<password>", u.Name, u.Name)
		}

		// No system_user: serve as the current process user, never privilege
		// drop. Resolved without touching /etc/passwd.
		if u.SystemUser == "" {
			cfg.Users[i].SystemUID = os.Getuid()
			cfg.Users[i].SystemGID = os.Getgid()
			continue
		}
		// Numeric system_user (uid or uid/gid): use the ids directly, no
		// /etc/passwd lookup. This is what makes minimal images (e.g. scratch)
		// work.
		if uid, gid, ok, err := parseNumericSystemUser(u.SystemUser); err != nil {
			return fmt.Errorf("user %q: %w", u.Name, err)
		} else if ok {
			cfg.Users[i].SystemUID = uid
			cfg.Users[i].SystemGID = gid
			continue
		}
		// Named system_user: resolve via /etc/passwd.
		sysu, err := user.Lookup(u.SystemUser)
		if err != nil {
			return fmt.Errorf("user %q: system_user %q: %w", u.Name, u.SystemUser, err)
		}
		uid, err := strconv.Atoi(sysu.Uid)
		if err != nil {
			return fmt.Errorf("user %q: non-numeric uid %q", u.Name, sysu.Uid)
		}
		gid, err := strconv.Atoi(sysu.Gid)
		if err != nil {
			return fmt.Errorf("user %q: non-numeric gid %q", u.Name, sysu.Gid)
		}
		cfg.Users[i].SystemUID = uid
		cfg.Users[i].SystemGID = gid
	}

	return nil
}
