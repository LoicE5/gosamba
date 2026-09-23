package config

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/ahmetozer/gosamba/internal/userdb"
)

// Merge combines defaults, file, and CLI into a final Config.
// Precedence (later overrides earlier): defaults < file < CLI.
// Shares: file shares first, then CLI shares appended.
// Users: file users first, then CLI users (plaintext-hashed) appended.
func Merge(cli CLI, file File) (Config, error) {
	cfg := Defaults()

	// --- server: file ---
	if v := file.Server.Listen; v != nil {
		cfg.Server.Listen = *v
	}
	if v := file.Server.Netbios; v != nil {
		cfg.Server.Netbios = *v
	}
	if v := file.Server.MDNS; v != nil {
		cfg.Server.MDNS = *v
	}
	if v := file.Server.Encryption; v != nil {
		cfg.Server.Encryption = *v
	}
	if v := file.Server.Signing; v != nil {
		cfg.Server.Signing = *v
	}
	if v := file.Server.DurableTimeout; v != nil {
		d, err := time.ParseDuration(*v)
		if err != nil {
			return Config{}, fmt.Errorf("durable_timeout in file: %w", err)
		}
		cfg.Server.DurableTimeout = d
	}
	if v := file.Server.StateDir; v != nil {
		cfg.Server.StateDir = *v
	}
	if v := file.Server.PerUserPrivdrop; v != nil {
		cfg.Server.PerUserPrivdrop = *v
	}

	// --- log: file ---
	if v := file.Log.Level; v != nil {
		cfg.Log.Level = *v
	}
	if v := file.Log.Format; v != nil {
		cfg.Log.Format = *v
	}

	// --- server: CLI ---
	if v := cli.Listen; v != nil {
		cfg.Server.Listen = *v
	}
	if v := cli.Netbios; v != nil {
		cfg.Server.Netbios = *v
	}
	if v := cli.MDNS; v != nil {
		cfg.Server.MDNS = *v
	}
	if v := cli.NoEncryption; v != nil && *v {
		cfg.Server.Encryption = EncryptionOff
	}
	if v := cli.NoSigning; v != nil && *v {
		cfg.Server.Signing = SigningPreferred
	}
	if v := cli.DurableTimeout; v != nil {
		d, err := time.ParseDuration(*v)
		if err != nil {
			return Config{}, fmt.Errorf("--durable-timeout: %w", err)
		}
		cfg.Server.DurableTimeout = d
	}
	if v := cli.StateDir; v != nil {
		cfg.Server.StateDir = *v
	}
	if v := cli.PerUserPrivdrop; v != nil {
		cfg.Server.PerUserPrivdrop = *v
	}

	// --- log: CLI ---
	if v := cli.LogLevel; v != nil {
		cfg.Log.Level = *v
	}
	if v := cli.LogFormat; v != nil {
		cfg.Log.Format = *v
	}

	// --- shares: file then CLI ---
	for _, fs := range file.Shares {
		name := fs.Name
		if name == "" {
			var err error
			name, err = defaultShareName(fs.Path)
			if err != nil {
				return Config{}, fmt.Errorf("share path %q: derive name: %w", fs.Path, err)
			}
		}
		cfg.Shares = append(cfg.Shares, ShareConfig{
			Name:     name,
			Path:     fs.Path,
			ReadOnly: fs.ReadOnly,
			GuestOK:  fs.GuestOK,
		})
	}
	for _, cs := range cli.Shares {
		name := cs.Name
		if name == "" {
			var err error
			name, err = defaultShareName(cs.Path)
			if err != nil {
				return Config{}, fmt.Errorf("share path %q: derive name: %w", cs.Path, err)
			}
		}
		cfg.Shares = append(cfg.Shares, ShareConfig{
			Name: name,
			Path: cs.Path,
		})
	}

	// --- users: file then CLI ---
	for _, fu := range file.Users {
		// allow_shares semantics, deliberately asymmetric:
		//
		//   key absent   (nil slice)   -> ["*"], every share. Kept for
		//                                backward compatibility: configs
		//                                written before allow_shares existed
		//                                must keep working.
		//   allow_shares = []          -> no shares at all. An operator who
		//                                writes an empty list is revoking
		//                                access, not asking for a wildcard;
		//                                the old len()==0 test turned that
		//                                into "every share" — a fail-open.
		//
		// The nil/empty distinction is the whole signal here: parseStringArray
		// returns a non-nil empty slice for "[]" precisely so this branch can
		// tell the two apart. Do not "simplify" either side to len(...) == 0.
		shares := fu.AllowShares
		if shares == nil {
			shares = []string{"*"}
		}
		cfg.Users = append(cfg.Users, UserConfig{
			Name:        fu.Name,
			NTHash:      fu.NTHash,
			SystemUser:  fu.SystemUser,
			AllowShares: shares,
		})
	}
	for _, cu := range cli.Users {
		hash := userdb.NTHash(cu.Password)
		cfg.Users = append(cfg.Users, UserConfig{
			Name:        cu.Name,
			NTHash:      hash,
			SystemUser:  cu.SystemUser,
			AllowShares: []string{"*"},
		})
	}

	return cfg, nil
}

// defaultShareName derives a stable, client-friendly name from the resolved
// share directory. Resolving before taking the base is important for paths
// such as "." and "..": their raw basenames are navigation markers that some
// SMB clients hide from share listings.
func defaultShareName(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Base(filepath.Clean(abs)), nil
}
