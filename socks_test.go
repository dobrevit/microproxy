package microproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestSOCKS serves the SOCKS5 frontend on an ephemeral port and returns the
// server and the address to point a client at.
func newTestSOCKS(t *testing.T, cfg Config, opts ...Option) (*Server, string) {
	t.Helper()

	server, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("couldn't create the proxy: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("couldn't listen: %v", err)
	}

	served := make(chan error, 1)
	go func() { served <- server.ServeSOCKS(listener) }()

	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("couldn't close the proxy: %v", err)
		}

		if err := <-served; err != nil {
			t.Errorf("ServeSOCKS returned %v", err)
		}
	})

	return server, listener.Addr().String()
}

// socksClient reaches the internet through the SOCKS5 proxy at addr.
func socksClient(t *testing.T, addr, user, password string) *http.Client {
	t.Helper()

	dialer, err := SOCKS5Dialer(addr, user, password, nil)
	if err != nil {
		t.Fatalf("couldn't create the SOCKS dialer: %v", err)
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext:     dialer.DialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the test server's certificate is self-signed
		},
	}
}

func TestSOCKSConnect(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	_, addr := newTestSOCKS(t, Config{AllowedConnectPorts: []int{portOf(t, background.URL)}})

	resp, err := socksClient(t, addr, "", "").Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Error("expected 200 status code, got", resp.Status)
	}

	if body := readBody(t, resp); body != expected {
		t.Errorf("expected '%s', got '%s'", expected, body)
	}
}

// The tunnel has to carry TLS as happily as it carries anything else.
func TestSOCKSConnectToTLS(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewTLSServer(constantHandler(expected))
	defer background.Close()

	_, addr := newTestSOCKS(t, Config{AllowedConnectPorts: []int{portOf(t, background.URL)}})

	resp, err := socksClient(t, addr, "", "").Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, resp); body != expected {
		t.Errorf("expected '%s', got '%s'", expected, body)
	}
}

// The credentials a proxy authenticates its HTTP clients against are the same
// ones its SOCKS clients have to present.
func TestSOCKSBasicAuth(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	_, addr := newTestSOCKS(t,
		Config{AllowedConnectPorts: []int{portOf(t, background.URL)}},
		WithCredentials(testBasicUsers()))

	resp, err := socksClient(t, addr, user, password).Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, resp); body != expected {
		t.Errorf("expected '%s', got '%s'", expected, body)
	}
}

// A digest store never holds the password, but it can still tell whether the
// one a SOCKS client offered is the right one.
func TestSOCKSDigestAuth(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	_, addr := newTestSOCKS(t,
		Config{AllowedConnectPorts: []int{portOf(t, background.URL)}},
		WithCredentials(testDigestUsers()))

	resp, err := socksClient(t, addr, user, password).Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, resp); body != expected {
		t.Errorf("expected '%s', got '%s'", expected, body)
	}
}

func TestSOCKSRefusesBadCredentials(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	_, addr := newTestSOCKS(t,
		Config{AllowedConnectPorts: []int{portOf(t, background.URL)}},
		WithCredentials(testBasicUsers()))

	tests := map[string][2]string{
		"wrong password": {user, "wrong"},
		"unknown user":   {"nobody", password},
		"no credentials": {"", ""},
	}

	for name, credentials := range tests {
		client := socksClient(t, addr, credentials[0], credentials[1])

		if _, err := client.Get(background.URL); err == nil {
			t.Errorf("%v: expected the connection to be refused", name)
		}
	}
}

func TestSOCKSRefusesADeniedNetwork(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	_, addr := newTestSOCKS(t, Config{
		AllowedNetworks:     []string{"172.16.11.0/24"},
		AllowedConnectPorts: []int{portOf(t, background.URL)},
	})

	if _, err := socksClient(t, addr, "", "").Get(background.URL); err == nil {
		t.Error("expected the connection to be refused")
	}
}

func TestSOCKSRefusesADisallowedPort(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	// the test server binds to a port other than 443
	_, addr := newTestSOCKS(t, Config{AllowedConnectPorts: []int{443}})

	if _, err := socksClient(t, addr, "", "").Get(background.URL); err == nil {
		t.Error("expected the connection to be refused")
	}
}

// A SOCKS client's traffic is routed by the same rules as an HTTP client's, so
// a rule sending a host to an upstream is honoured here too.
func TestSOCKSHonoursUpstreamRoutes(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	dialed := make(chan string, 1)

	_, addr := newTestSOCKS(t,
		Config{AllowedConnectPorts: []int{portOf(t, background.URL)}},
		WithRouter(RouterFunc(func(host string) (Route, error) {
			return Route{Dialer: DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
				select {
				case dialed <- addr:
				default:
				}

				return new(net.Dialer).DialContext(ctx, network, addr)
			})}, nil
		})))

	resp, err := socksClient(t, addr, "", "").Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, resp); body != expected {
		t.Errorf("expected '%s', got '%s'", expected, body)
	}

	select {
	case target := <-dialed:
		if expected := background.Listener.Addr().String(); target != expected {
			t.Errorf("expected the route to be asked for %v, got %v", expected, target)
		}
	default:
		t.Error("expected the route's dialer to have been used")
	}
}

// Every connection the proxy serves ends up in the access log, whichever
// frontend it arrived at.
func TestSOCKSWritesTheAccessLog(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	entries := make(chan *AccessEntry, 4)

	_, addr := newTestSOCKS(t,
		Config{AllowedConnectPorts: []int{portOf(t, background.URL)}},
		WithAccessLogger(AccessLoggerFunc(func(entry *AccessEntry) { entries <- entry })),
		WithCredentials(testBasicUsers()))

	resp, err := socksClient(t, addr, user, password).Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case entry := <-entries:
		if entry.User != user {
			t.Errorf("expected the entry to name %v, got %q", user, entry.User)
		}

		if entry.URL != background.Listener.Addr().String() {
			t.Errorf("expected the target %v, got %v", background.Listener.Addr(), entry.URL)
		}

		if entry.StatusCode != http.StatusOK {
			t.Errorf("expected a successful entry, got %v", entry.StatusCode)
		}
	case <-time.After(5 * time.Second):
		t.Error("the connection was not logged")
	}
}

// Shutdown has to stop accepting and return once the connections in flight are
// done.
func TestSOCKSShutdown(t *testing.T) {
	server, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	served := make(chan error, 1)
	go func() { served <- server.ServeSOCKS(listener) }()

	// wait for the frontend to be up
	deadline := time.Now().Add(5 * time.Second)
	for server.SOCKSAddr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if server.SOCKSAddr() == nil {
		t.Fatal("the SOCKS frontend never started")
	}

	addr := server.SOCKSAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("couldn't shut down: %v", err)
	}

	if err := <-served; err != nil {
		t.Errorf("ServeSOCKS returned %v", err)
	}

	if server.SOCKSAddr() != nil {
		t.Error("expected the frontend to report no address once it stopped")
	}

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("expected the listener to be closed")
	}
}

// unhealthy drives the tracker below its threshold, so that a later success is
// visible as a change rather than as the state it started in.
func unhealthy(t *testing.T, health *Health) {
	t.Helper()

	for i := 0; i < DefaultHealthFailureLimit; i++ {
		health.RecordFailure()
	}

	if health.Healthy() {
		t.Fatal("expected the proxy to be unhealthy to begin with")
	}
}

// A tunnel the proxy managed to open says it can reach the world.
func TestSOCKSRecordsHealthOnSuccess(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	server, addr := newTestSOCKS(t, Config{
		AllowedConnectPorts: []int{portOf(t, background.URL)},
		HealthCheckEnabled:  "on",
	})

	unhealthy(t, server.Health())

	resp, err := socksClient(t, addr, "", "").Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !server.Health().Healthy() {
		t.Error("expected an established tunnel to record a success")
	}
}

// A target the proxy could not reach is what the health endpoint exists to
// report.
func TestSOCKSRecordsHealthOnDialFailure(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	server, addr := newTestSOCKS(t,
		Config{
			AllowedConnectPorts: []int{portOf(t, background.URL)},
			HealthCheckEnabled:  "on",
		},
		WithRouter(RouterFunc(func(host string) (Route, error) {
			return Route{Dialer: DialerFunc(func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("the tunnel is down")
			})}, nil
		})))

	if _, err := socksClient(t, addr, "", "").Get(background.URL); err == nil {
		t.Fatal("expected the connection to fail")
	}

	if failures := server.Health().Failures(); failures != 1 {
		t.Errorf("expected one failure to be recorded, got %v", failures)
	}
}

// A client refused before the proxy tried to reach anything says nothing about
// the proxy, so it must not count against it.
func TestSOCKSRefusalDoesNotAffectHealth(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	server, addr := newTestSOCKS(t,
		Config{
			AllowedConnectPorts: []int{portOf(t, background.URL)},
			HealthCheckEnabled:  "on",
		},
		WithCredentials(testBasicUsers()))

	if _, err := socksClient(t, addr, user, "wrong").Get(background.URL); err == nil {
		t.Fatal("expected the connection to be refused")
	}

	if failures := server.Health().Failures(); failures != 0 {
		t.Errorf("expected a refused client to record nothing, got %v failures", failures)
	}

	if !server.Health().Healthy() {
		t.Error("expected the proxy to still be healthy")
	}
}

// A client the network ACLs turn away is refused for the same reason.
func TestSOCKSDeniedNetworkDoesNotAffectHealth(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	server, addr := newTestSOCKS(t, Config{
		AllowedNetworks:     []string{"172.16.11.0/24"},
		AllowedConnectPorts: []int{portOf(t, background.URL)},
		HealthCheckEnabled:  "on",
	})

	if _, err := socksClient(t, addr, "", "").Get(background.URL); err == nil {
		t.Fatal("expected the connection to be refused")
	}

	if failures := server.Health().Failures(); failures != 0 {
		t.Errorf("expected a denied client to record nothing, got %v failures", failures)
	}
}
