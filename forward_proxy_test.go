package microproxy

import (
	"net/http"
	"net/url"
	"testing"
)

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("couldn't create the proxy: %v", err)
	}

	return server
}

// proxyFor is the upstream proxy url a host is routed to, or "" for a direct
// connection.
func proxyFor(t *testing.T, server *Server, host string) string {
	t.Helper()

	route, err := server.route(host)
	if err != nil {
		t.Fatalf("couldn't route %v: %v", host, err)
	}

	if route.Proxy == nil {
		return ""
	}

	return route.Proxy.String()
}

func TestForwardProxyRules(t *testing.T) {
	server := newTestServer(t, Config{
		Proxies: map[string]string{
			"first":  "http://proxy1:3128",
			"second": "http://proxy2:3128",
		},
		Rules: map[string]string{
			"example.com":       "first",
			"inner.example.com": "second",
		},
	})

	tests := []struct {
		host     string
		expected string
	}{
		{"example.com", "http://proxy1:3128"},
		{"www.example.com", "http://proxy1:3128"},
		{"inner.example.com", "http://proxy2:3128"},
		{"deep.inner.example.com", "http://proxy2:3128"},
		{"example.com:8080", "http://proxy1:3128"},
		// a bare suffix test would send these to proxy1 as well
		{"notexample.com", ""},
		{"evil-example.com", ""},
		{"example.com.evil.net", ""},
	}

	for _, test := range tests {
		if actual := proxyFor(t, server, test.host); actual != test.expected {
			t.Errorf("%v: expected proxy '%v', got '%v'", test.host, test.expected, actual)
		}
	}
}

// The generic "." rule is more specific than ForwardProxyURL and has to win.
func TestForwardProxyGenericRulePrecedence(t *testing.T) {
	server := newTestServer(t, Config{
		ForwardProxyURL: "http://fallback:3128",
		Proxies:         map[string]string{"catchall": "http://catchall:3128"},
		Rules:           map[string]string{GenericProxyRule: "catchall"},
	})

	expected := "http://catchall:3128"
	if actual := proxyFor(t, server, "anything.net"); actual != expected {
		t.Errorf("expected proxy '%v', got '%v'", expected, actual)
	}
}

func TestForwardProxyURLUsedWhenNoRuleMatches(t *testing.T) {
	server := newTestServer(t, Config{
		ForwardProxyURL: "http://fallback:3128",
		Proxies:         map[string]string{"first": "http://proxy1:3128"},
		Rules:           map[string]string{"example.com": "first"},
	})

	expected := "http://fallback:3128"
	if actual := proxyFor(t, server, "other.net"); actual != expected {
		t.Errorf("expected proxy '%v', got '%v'", expected, actual)
	}
}

// Without a matching rule, a generic proxy or a proxy in the environment, the
// request has to be reported as direct instead of failing.
//
// net/http reads the proxy environment once per process and caches it, so this
// has to be the only test that depends on it: clearing the variables here fixes
// the cached value for the whole test binary.
func TestForwardProxyFallsBackToDirect(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")

	server := newTestServer(t, Config{
		Proxies: map[string]string{"first": "http://proxy1:3128"},
		Rules:   map[string]string{"example.com": "first"},
	})

	for _, host := range []string{"other.net", "other.net:443"} {
		route, err := server.route(host)
		if err != nil {
			t.Fatalf("couldn't route %v: %v", host, err)
		}

		if !route.Direct() {
			t.Errorf("%v: expected a direct connection, got %+v", host, route)
		}
	}
}

// A SOCKS5 upstream is reached with a dialer rather than with CONNECT, so it
// has to come back as a route that carries one and no proxy url.
func TestSOCKS5UpstreamIsRoutedThroughADialer(t *testing.T) {
	server := newTestServer(t, Config{
		Proxies: map[string]string{
			"tunnel": "socks5://127.0.0.1:1080",
			"remote": "socks5h://user:secret@127.0.0.1:1081",
			"plain":  "http://proxy1:3128",
		},
		Rules: map[string]string{
			"tunnelled.example.com": "tunnel",
			"remote.example.com":    "remote",
			"plain.example.com":     "plain",
		},
	})

	for _, host := range []string{"tunnelled.example.com", "remote.example.com"} {
		route, err := server.route(host)
		if err != nil {
			t.Fatalf("couldn't route %v: %v", host, err)
		}

		if route.Proxy != nil {
			t.Errorf("%v: expected no proxy url, got %v", host, route.Proxy)
		}

		if route.Dialer == nil {
			t.Errorf("%v: expected a dialer", host)
		}
	}

	route, err := server.route("plain.example.com")
	if err != nil {
		t.Fatal(err)
	}

	if route.Dialer != nil {
		t.Error("an http upstream must not be routed through a dialer")
	}
}

// A Router replaces the routing a configuration describes.
func TestRouterOverridesTheConfiguration(t *testing.T) {
	upstream, err := url.Parse("http://router-said-so:3128")
	if err != nil {
		t.Fatal(err)
	}

	server, err := New(
		Config{
			Proxies: map[string]string{"first": "http://proxy1:3128"},
			Rules:   map[string]string{"example.com": "first"},
		},
		WithRouter(RouterFunc(func(host string) (Route, error) {
			return Route{Proxy: upstream}, nil
		})),
	)
	if err != nil {
		t.Fatal(err)
	}

	if actual := proxyFor(t, server, "example.com"); actual != upstream.String() {
		t.Errorf("expected proxy '%v', got '%v'", upstream, actual)
	}
}

func TestConfigurationRejectsBrokenProxySettings(t *testing.T) {
	tests := map[string]Config{
		"unknown alias": {
			Proxies: map[string]string{"first": "http://proxy1:3128"},
			Rules:   map[string]string{"example.com": "typo"},
		},
		"proxy url without host": {
			Proxies: map[string]string{"first": "proxy1:3128"},
			Rules:   map[string]string{"example.com": "first"},
		},
		"forward proxy url without host": {ForwardProxyURL: "proxy1:3128"},
		"misspelled proxy url scheme":    {ForwardProxyURL: "htp://proxy1:3128"},
		"unsupported proxy url scheme":   {ForwardProxyURL: "ftp://proxy1:21"},
		// SOCKS4 is a different protocol and is not implemented
		"socks4 proxy url": {ForwardProxyURL: "socks4://proxy1:1080"},
	}

	for name, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%v: expected a configuration error", name)
		}
	}
}

func TestConnectPort(t *testing.T) {
	tests := []struct {
		host     string
		expected int
	}{
		{"example.com:443", 443},
		{"example.com:8443", 8443},
		// goproxy tunnels a portless host to the https port
		{"example.com", DefaultAllowedConnectPort},
		{"example.com:https", -1},
	}

	for _, test := range tests {
		req := &http.Request{Host: test.host, URL: &url.URL{Host: test.host}}
		if actual := connectPort(req); actual != test.expected {
			t.Errorf("%v: expected port %v, got %v", test.host, test.expected, actual)
		}
	}
}

func TestHostnameOf(t *testing.T) {
	tests := map[string]string{
		"example.com:443": "example.com",
		"example.com":     "example.com",
		"[::1]:443":       "::1",
		"[::1]":           "::1",
		"127.0.0.1:3128":  "127.0.0.1",
	}

	for host, expected := range tests {
		if actual := hostnameOf(host); actual != expected {
			t.Errorf("%v: expected hostname '%v', got '%v'", host, expected, actual)
		}
	}
}
