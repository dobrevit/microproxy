package microproxy

import (
	"net"
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	conf, err := Config{}.compile(nil)
	if err != nil {
		t.Fatal(err)
	}

	if conf.Listen != DefaultListenAddress {
		t.Errorf("expected the listen address %v, got %v", DefaultListenAddress, conf.Listen)
	}

	if len(conf.AllowedConnectPorts) != 1 || conf.AllowedConnectPorts[0] != DefaultAllowedConnectPort {
		t.Errorf("expected the connect port %v, got %v", DefaultAllowedConnectPort, conf.AllowedConnectPorts)
	}

	if conf.ForwardedForHeader != "on" || conf.ViaHeader != "on" {
		t.Errorf("expected the headers to be on, got %v and %v", conf.ForwardedForHeader, conf.ViaHeader)
	}

	if conf.ReadTimeout != DefaultReadTimeout || conf.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("expected the default timeouts, got %v and %v", conf.ReadTimeout, conf.WriteTimeout)
	}

	// Via announces the host name when no name was configured.
	if conf.ViaProxyName == "" {
		t.Error("expected a Via proxy name")
	}
}

// A proxy that neither authenticates nor limits its clients would be an open
// relay, so it has to end up bound to the loopback.
func TestUnconfiguredProxyIsLimitedToTheLoopback(t *testing.T) {
	server := newTestServer(t, Config{})

	networks := server.Config().AllowedNetworks
	if len(networks) != 1 || networks[0] != DefaultAllowedNetwork {
		t.Errorf("expected the allowed networks to be [%v], got %v", DefaultAllowedNetwork, networks)
	}
}

// Configuring credentials is what makes a proxy reachable from anywhere, since
// its clients then have to prove who they are.
func TestAuthenticatedProxyIsNotLimitedToTheLoopback(t *testing.T) {
	server, err := New(Config{}, WithCredentials(NewBasicUsers("realm")))
	if err != nil {
		t.Fatal(err)
	}

	if networks := server.Config().AllowedNetworks; len(networks) != 0 {
		t.Errorf("expected no network restriction, got %v", networks)
	}
}

func TestConfigRejectsBrokenSettings(t *testing.T) {
	tests := map[string]Config{
		"bad bind ip":            {BindIP: "not an address"},
		"bad allowed network":    {AllowedNetworks: []string{"10.0.0.0/33"}},
		"bad disallowed network": {DisallowedNetworks: []string{"nonsense"}},
		"bad forwarded-for":      {ForwardedForHeader: "maybe"},
		"bad via":                {ViaHeader: "maybe"},
	}

	for name, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%v: expected a configuration error", name)
		}
	}
}

// A bare address is a single host network, which is how the shipped
// configuration files have always written one.
func TestBareIPAddressIsASingleHostNetwork(t *testing.T) {
	conf, err := Config{AllowedNetworks: []string{"127.0.0.1", "10.0.0.0/8"}}.compile(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(conf.allowedNetworks) != 2 {
		t.Fatalf("expected 2 networks, got %v", conf.allowedNetworks)
	}

	if !conf.allowedNetworks[0].Contains(net.ParseIP("127.0.0.1")) {
		t.Error("expected 127.0.0.1 to be in the first network")
	}

	if conf.allowedNetworks[0].Contains(net.ParseIP("127.0.0.2")) {
		t.Error("expected the first network to hold a single host")
	}
}

// New copies the configuration, so a caller that reuses the Config it passed
// can't change what a running proxy does.
func TestConfigIsCopied(t *testing.T) {
	cfg := Config{
		AllowedNetworks: []string{"127.0.0.1/32"},
		AddHeaders:      [][]string{{"X-Test", "before"}},
		Rules:           map[string]string{"example.com": "first"},
		Proxies:         map[string]string{"first": "http://proxy1:3128"},
	}

	server := newTestServer(t, cfg)

	cfg.AllowedNetworks[0] = "0.0.0.0/0"
	cfg.AddHeaders[0][1] = "after"
	cfg.Rules["other.net"] = "first"

	inForce := server.Config()

	if inForce.AllowedNetworks[0] != "127.0.0.1/32" {
		t.Errorf("the allowed networks changed under the server: %v", inForce.AllowedNetworks)
	}

	if inForce.AddHeaders[0][1] != "before" {
		t.Errorf("the headers changed under the server: %v", inForce.AddHeaders)
	}

	if len(inForce.Rules) != 1 {
		t.Errorf("the rules changed under the server: %v", inForce.Rules)
	}
}

// A negative timeout is how a caller says "no deadline at all", and has to
// survive the defaulting that turns a zero one into the default.
func TestNegativeTimeoutIsKept(t *testing.T) {
	conf, err := Config{ReadTimeout: -1, WriteTimeout: -1 * time.Second}.compile(nil)
	if err != nil {
		t.Fatal(err)
	}

	if conf.ReadTimeout >= 0 || conf.WriteTimeout >= 0 {
		t.Errorf("expected the timeouts to stay negative, got %v and %v",
			conf.ReadTimeout, conf.WriteTimeout)
	}
}
