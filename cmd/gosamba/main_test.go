package main

import (
	"strings"
	"testing"
)

func TestNTHashFromReader(t *testing.T) {
	// Reference value computed by internal/userdb.NTHash for "s3cret".
	const want = "d4c619cb16d4632b275658316a7e657e"

	cases := map[string]string{
		"trailing newline": "s3cret\n",
		"no newline":       "s3cret",
		"crlf":             "s3cret\r\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := nthashFromReader(strings.NewReader(in))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestNTHashFromReader_Empty(t *testing.T) {
	if _, err := nthashFromReader(strings.NewReader("\n")); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestBonjourNames(t *testing.T) {
	tests := []struct {
		name         string
		listenerHost string
		localHost    string
		wantInstance string
		wantHost     string
	}{
		{name: "empty wildcard", listenerHost: "", localHost: "media-box", wantInstance: "media-box", wantHost: "media-box"},
		{name: "IPv4 wildcard", listenerHost: "0.0.0.0", localHost: "media-box", wantInstance: "media-box", wantHost: "media-box"},
		{name: "IPv6 wildcard", listenerHost: "::", localHost: "media-box.local", wantInstance: "media-box", wantHost: "media-box"},
		{name: "expanded IPv6 wildcard", listenerHost: "0:0:0:0:0:0:0:0", localHost: "media-box.local.", wantInstance: "media-box", wantHost: "media-box"},
		{name: "explicit address", listenerHost: "192.0.2.10", localHost: "media-box", wantInstance: "media-box", wantHost: "192.0.2.10"},
		{name: "explicit local name", listenerHost: "files.local.", localHost: "media-box", wantInstance: "media-box", wantHost: "files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance, host := bonjourNames(tt.listenerHost, tt.localHost)
			if instance != tt.wantInstance || host != tt.wantHost {
				t.Fatalf("bonjourNames(%q, %q) = (%q, %q), want (%q, %q)",
					tt.listenerHost, tt.localHost, instance, host, tt.wantInstance, tt.wantHost)
			}
		})
	}
}
