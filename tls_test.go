package microproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// selfSigned issues a certificate for 127.0.0.1 that a test client can pin,
// standing in for the proxy's own certificate.
func selfSigned(t *testing.T, commonName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"microproxy test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, pool
}

// newTLSProxy serves the proxy over TLS on an ephemeral port and returns a
// client that reaches the internet through it.
func newTLSProxy(t *testing.T, cfg Config, tlsConfig *tls.Config, pool *x509.CertPool, opts ...Option) (*Server, *http.Client) {
	t.Helper()

	server, err := New(cfg, append(opts, WithListenerTLS(tlsConfig))...)
	if err != nil {
		t.Fatalf("couldn't create the proxy: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	t.Cleanup(func() {
		_ = server.Close()
		<-served
	})

	// Serve wraps the listener, so its address is where the client connects.
	proxyURL, err := url.Parse("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
			// the target servers in these tests are self-signed too
			InsecureSkipVerify: true, //nolint:gosec // the proxy's own certificate is pinned through RootCAs
		},
	}}

	return server, client
}

// A client has to be able to speak the proxy protocol inside a TLS connection,
// for a plain target and for a tunnelled one.
func TestListenerTLS(t *testing.T) {
	plain := httptest.NewServer(constantHandler("plain-ok"))
	defer plain.Close()

	secure := httptest.NewTLSServer(constantHandler("tls-ok"))
	defer secure.Close()

	certificate, pool := selfSigned(t, "127.0.0.1")

	_, client := newTLSProxy(t,
		Config{AllowedConnectPorts: []int{portOf(t, secure.URL)}},
		&tls.Config{Certificates: []tls.Certificate{certificate}}, //nolint:gosec // MinVersion is applied by WithListenerTLS
		pool)

	for name, test := range map[string]struct{ url, expected string }{
		"plain target":     {plain.URL, "plain-ok"},
		"tunnelled target": {secure.URL, "tls-ok"},
	} {
		resp, err := client.Get(test.url)
		if err != nil {
			t.Errorf("%v: %v", name, err)

			continue
		}

		if body := readBody(t, resp); body != test.expected {
			t.Errorf("%v: expected %q, got %q", name, test.expected, body)
		}
	}
}

// Encrypting the hop to the proxy must not stop it authenticating the client;
// that is the main reason to encrypt it.
func TestListenerTLSStillAuthenticates(t *testing.T) {
	background := httptest.NewServer(constantHandler("hello"))
	defer background.Close()

	certificate, pool := selfSigned(t, "127.0.0.1")

	_, client := newTLSProxy(t, Config{},
		&tls.Config{Certificates: []tls.Certificate{certificate}}, //nolint:gosec // MinVersion is applied by WithListenerTLS
		pool,
		WithCredentials(testBasicUsers()))

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407 without credentials, got %v", resp.Status)
	}

	req, err := http.NewRequest(http.MethodGet, background.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, resp); body != "hello" {
		t.Errorf("expected 'hello', got %q", body)
	}
}

// A plaintext client talking to a TLS listener has to fail rather than be
// served, so that nobody is silently downgraded.
func TestListenerTLSRefusesPlaintext(t *testing.T) {
	background := httptest.NewServer(constantHandler("hello"))
	defer background.Close()

	certificate, _ := selfSigned(t, "127.0.0.1")

	server, err := New(Config{}, WithListenerTLS(&tls.Config{ //nolint:gosec // MinVersion is applied by WithListenerTLS
		Certificates: []tls.Certificate{certificate},
	}))
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	t.Cleanup(func() {
		_ = server.Close()
		<-served
	})

	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	plaintext := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	if _, err := plaintext.Get(background.URL); err == nil {
		t.Error("expected a plaintext client to be refused by a TLS listener")
	}
}

// The option must not keep a handle on the caller's configuration, and has to
// insist on a floor for the protocol version.
func TestListenerTLSCopiesTheConfigAndSetsAFloor(t *testing.T) {
	certificate, _ := selfSigned(t, "127.0.0.1")

	given := &tls.Config{Certificates: []tls.Certificate{certificate}} //nolint:gosec // that is what is being tested

	server, err := New(Config{}, WithListenerTLS(given))
	if err != nil {
		t.Fatal(err)
	}

	if server.listenerTLS.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 to be the floor, got %v", server.listenerTLS.MinVersion)
	}

	if given.MinVersion != 0 {
		t.Error("the caller's configuration was modified")
	}

	// a floor the caller did set has to be respected
	server, err = New(Config{}, WithListenerTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}))
	if err != nil {
		t.Fatal(err)
	}

	if server.listenerTLS.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected the configured floor to be kept, got %v", server.listenerTLS.MinVersion)
	}
}

// Without the option the listener stays plaintext, so nobody has to opt out.
func TestListenerIsPlaintextByDefault(t *testing.T) {
	server := newTestServer(t, Config{})

	if server.listenerTLS != nil {
		t.Error("expected the listener to be plaintext by default")
	}
}
