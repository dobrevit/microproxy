package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped configuration file is what the README documents and what the
// container image runs, so it has to keep decoding into what it says.
func TestConfigFile(t *testing.T) {
	conf, err := loadConfig(filepath.Join("..", "..", "microproxy.toml"))
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string]struct {
		actual, want string
	}{
		"listen":        {conf.Listen, "127.0.0.1:3129"},
		"access_log":    {conf.AccessLog, "/tmp/microproxy.access.log"},
		"auth_file":     {conf.AuthFile, "auth.txt"},
		"auth_realm":    {conf.AuthRealm, "proxy"},
		"auth_type":     {conf.AuthType, "basic"},
		"forwarded_for": {conf.ForwardedForHeader, "on"},
	}

	for name, field := range expected {
		if field.actual != field.want {
			t.Errorf("%v: got %v, expected %v", name, field.actual, field.want)
		}
	}

	if len(conf.AllowedConnectPorts) != 2 ||
		conf.AllowedConnectPorts[0] != 443 || conf.AllowedConnectPorts[1] != 80 {
		t.Errorf("allowed_connect_ports: got %v, expected [443 80]", conf.AllowedConnectPorts)
	}
}

// A configuration naming an authentication file but no type can't be used, and
// has to be reported while -t can still catch it.
func TestConfigRejectsAnAuthFileWithoutAType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microproxy.toml")

	if err := os.WriteFile(path, []byte("auth_file = \"auth.txt\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Error("expected a configuration error")
	}
}

// The library's own settings are validated through the same path, so a typo in
// one of them is caught by -t as well.
func TestConfigValidatesTheLibrarySettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microproxy.toml")

	if err := os.WriteFile(path, []byte("via_header = \"maybe\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Error("expected a configuration error")
	}
}
