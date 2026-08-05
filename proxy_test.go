package microproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"testing"
)

// constantHandler answers every request with the same body.
type constantHandler string

func (h constantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, err := io.WriteString(w, string(h)); err != nil {
		fmt.Printf("Error: %v", err)
	}
}

// newTestProxy builds a proxy from cfg and serves it, returning a client that
// reaches the internet through it and the proxy's own url.
func newTestProxy(t *testing.T, cfg Config, opts ...Option) (*http.Client, string) {
	t.Helper()

	server, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("couldn't create the proxy: %v", err)
	}

	proxyServer := httptest.NewServer(server.Handler())
	t.Cleanup(proxyServer.Close)

	return proxyClient(t, proxyServer.URL), proxyServer.URL
}

// proxyClient reaches the internet through the proxy serving at proxyURL.
func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("couldn't parse the proxy url %v: %v", proxyURL, err)
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(parsed),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the test server's certificate is self-signed
		},
	}
}

// needsCommand skips the test when the external program it drives is missing,
// so that the suite still runs somewhere without curl or python.
func needsCommand(t *testing.T, name string) {
	t.Helper()

	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%v is not installed", name)
	}
}

func times(n int, s string) string {
	r := make([]byte, 0, n*len(s))

	for i := 0; i < n; i++ {
		r = append(r, s...)
	}

	return string(r)
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("couldn't read the response body: %v", err)
	}

	return string(body)
}
