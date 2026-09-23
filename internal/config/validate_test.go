package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func currentUser(t *testing.T) (name string, uid, gid int) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip("user.Current unavailable")
	}
	ui, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Skip("non-numeric uid")
	}
	gi, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Skip("non-numeric gid")
	}
	return u.Username, ui, gi
}

func TestValidate_Happy(t *testing.T) {
	dir := t.TempDir()
	uname, _, _ := currentUser(t)

	cfg := Defaults()
	cfg.Server.Listen = ":0"
	cfg.Server.StateDir = filepath.Join(dir, "state")
	cfg.Shares = []ShareConfig{{Name: "a", Path: dir}}
	cfg.Users = []UserConfig{{
		Name: "u", NTHash: [16]byte{1}, SystemUser: uname, AllowShares: []string{"*"},
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Users[0].SystemUID < 0 {
		t.Errorf("uid should be filled in")
	}
}

func TestValidate_ShareMissing(t *testing.T) {
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: "/nonexistent/gosamba/test"}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("expected share-missing error, got %v", err)
	}
}

func TestValidate_ShareNotDir(t *testing.T) {
	tmp, _ := os.CreateTemp("", "gosambatest")
	defer os.Remove(tmp.Name())
	tmp.Close()
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: tmp.Name()}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("expected not-a-directory error, got %v", err)
	}
}

func TestValidate_DuplicateShareName(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: dir}, {Name: "x", Path: dir}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected duplicate-share error")
	}
}

func TestValidate_RejectsNavigationShareNames(t *testing.T) {
	for _, name := range []string{".", ".."} {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Shares = []ShareConfig{{Name: name, Path: t.TempDir()}}
			err := Validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), "name is reserved") || !strings.Contains(err.Error(), "descriptive name") {
				t.Fatalf("expected actionable reserved-name error, got %v", err)
			}
		})
	}
}

func TestValidate_UnknownSystemUser(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: dir}}
	cfg.Users = []UserConfig{{Name: "u", NTHash: [16]byte{1}, SystemUser: "nosuchuser_gosamba_test_xyz"}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected unknown-system-user error")
	}
}

func TestParseNumericSystemUser(t *testing.T) {
	cases := []struct {
		in      string
		wantUID int
		wantGID int
		wantOK  bool
		wantErr bool
	}{
		{in: "1000", wantUID: 1000, wantGID: 1000, wantOK: true},
		{in: "0", wantUID: 0, wantGID: 0, wantOK: true},
		{in: "1000/1001", wantUID: 1000, wantGID: 1001, wantOK: true},
		{in: "alice", wantOK: false},    // a name, not numeric
		{in: "", wantOK: false},         // empty handled by caller
		{in: "1000/", wantErr: true},    // malformed numeric form
		{in: "1000/abc", wantErr: true}, // malformed gid
		{in: "abc/1000", wantErr: true}, // slash form requires numeric uid
	}
	for _, c := range cases {
		uid, gid, ok, err := parseNumericSystemUser(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got none", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", c.in, err)
			continue
		}
		if ok != c.wantOK {
			t.Errorf("%q: ok=%v want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && (uid != c.wantUID || gid != c.wantGID) {
			t.Errorf("%q: uid=%d gid=%d, want uid=%d gid=%d", c.in, uid, gid, c.wantUID, c.wantGID)
		}
	}
}

func TestValidate_EmptySystemUser_UsesCurrentUser(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Server.Listen = ":0"
	cfg.Shares = []ShareConfig{{Name: "a", Path: dir}}
	cfg.Users = []UserConfig{{Name: "u", NTHash: [16]byte{1}, SystemUser: "", AllowShares: []string{"*"}}}
	if err := Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Users[0].SystemUID != os.Getuid() || cfg.Users[0].SystemGID != os.Getgid() {
		t.Errorf("empty system_user: uid=%d gid=%d, want current uid=%d gid=%d",
			cfg.Users[0].SystemUID, cfg.Users[0].SystemGID, os.Getuid(), os.Getgid())
	}
}

func TestValidate_NumericSystemUser_NoLookup(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Server.Listen = ":0"
	cfg.Shares = []ShareConfig{{Name: "a", Path: dir}}
	cfg.Users = []UserConfig{
		{Name: "u1", NTHash: [16]byte{1}, SystemUser: "1234", AllowShares: []string{"*"}},
		{Name: "u2", NTHash: [16]byte{2}, SystemUser: "1234/5678", AllowShares: []string{"*"}},
	}
	if err := Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Users[0].SystemUID != 1234 || cfg.Users[0].SystemGID != 1234 {
		t.Errorf("numeric uid: uid=%d gid=%d, want 1234/1234", cfg.Users[0].SystemUID, cfg.Users[0].SystemGID)
	}
	if cfg.Users[1].SystemUID != 1234 || cfg.Users[1].SystemGID != 5678 {
		t.Errorf("uid/gid: uid=%d gid=%d, want 1234/5678", cfg.Users[1].SystemUID, cfg.Users[1].SystemGID)
	}
}

func TestValidate_BadEncryption(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Encryption = "wibble"
	cfg.Shares = []ShareConfig{{Name: "x", Path: t.TempDir()}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected bad-encryption error")
	}
}
