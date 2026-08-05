package microproxy

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// >>> import hashlib
// >>> ha1 = hashlib.md5("user:my_realm:open sesame").hexdigest()
// >>> ha1
// 'e0d80a524f34d30b658136e2e89c1677'
const (
	user     = "user"
	password = "open sesame"
	realm    = "my_realm"
	ha1      = "e0d80a524f34d30b658136e2e89c1677"
	nc       = "00000001"
	cnonce   = "7e1d7e39d76092ea"
	uri      = "/"
	method   = "GET"
	qop      = "auth"
)

func testBasicUsers() *BasicUsers {
	users := NewBasicUsers(realm)
	users.Set(user, password)

	return users
}

func testDigestUsers() *DigestUsers {
	users := NewDigestUsers(realm)
	users.SetHA1(user, realm, ha1)

	return users
}

func TestBasicAuth(t *testing.T) {
	expected := "hello"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	client, _ := newTestProxy(t, Config{}, WithCredentials(testBasicUsers()))

	// without credentials
	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	expectedChallenge := fmt.Sprintf("Basic realm=%q", realm)
	if challenge := resp.Header.Get("Proxy-Authenticate"); challenge != expectedChallenge {
		t.Errorf("expected the challenge %v, got %v", expectedChallenge, challenge)
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Error("expected status 407 Proxy Authentication Required, got", resp.Status)
	}

	// with credentials
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

	if resp.StatusCode != http.StatusOK {
		t.Error("expected status 200 OK, got", resp.Status)
	}

	if body := readBody(t, resp); body != expected {
		t.Errorf("expected '%s', got '%s'", expected, body)
	}
}

func TestBasicAuthRejectsAWrongPassword(t *testing.T) {
	background := httptest.NewServer(constantHandler("hello"))
	defer background.Close()

	client, _ := newTestProxy(t, Config{}, WithCredentials(testBasicUsers()))

	for name, credentials := range map[string]string{
		"wrong password": user + ":wrong",
		"unknown user":   "nobody:" + password,
		"empty":          ":",
	} {
		req, err := http.NewRequest(http.MethodGet, background.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("%v: expected status 407, got %v", name, resp.Status)
		}
	}
}

// digestResponse computes what a client authenticating as the test user would
// send back for the given nonce.
func digestResponse(nonce string) string {
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(method+":"+uri)))

	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(
		[]string{ha1, nonce, nc, cnonce, qop, ha2}, ":"))))
}

func digestHeader(nonce, response, counter string) string {
	return fmt.Sprintf(
		"Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q, qop=%s, nc=%s, cnonce=%q",
		user, realm, nonce, uri, response, qop, counter, cnonce)
}

// challengeNonce asks the proxy for a challenge and returns the nonce it
// offered.
func challengeNonce(t *testing.T, client *http.Client, targetURL string) string {
	t.Helper()

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatal("expected status 407 Proxy Authentication Required, got", resp.Status)
	}

	header := resp.Header.Get("Proxy-Authenticate")
	if header == "" {
		t.Fatal("couldn't get the expected Proxy-Authenticate header")
	}

	scheme, parameters, found := strings.Cut(header, " ")
	if !found || scheme != "Digest" {
		t.Fatal("expected a Digest Proxy-Authenticate header, got", header)
	}

	matches := regexp.MustCompile(`nonce="(.*?)"`).FindAllStringSubmatch(parameters, -1)
	if len(matches) == 0 {
		t.Fatal("the challenge carries no nonce:", header)
	}

	return matches[0][1]
}

func TestDigestAuth(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	client, _ := newTestProxy(t, Config{}, WithCredentials(testDigestUsers()))

	nonce := challengeNonce(t, client, background.URL)

	req, err := http.NewRequest(http.MethodGet, background.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", digestHeader(nonce, digestResponse(nonce), nc))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Error("expected status 200 OK, got", resp.Status)
	}

	if body := readBody(t, resp); body != expected {
		t.Errorf("expected '%s', got '%s'", expected, body)
	}
}

// A nonce counter that does not move on is a replayed request, and the second
// one has to be refused even though its digest is perfectly valid.
func TestDigestAuthRejectsAReplayedNonceCounter(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	client, _ := newTestProxy(t, Config{}, WithCredentials(testDigestUsers()))

	nonce := challengeNonce(t, client, background.URL)
	header := digestHeader(nonce, digestResponse(nonce), nc)

	statuses := make([]int, 0, 2)

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, background.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Proxy-Authorization", header)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		statuses = append(statuses, resp.StatusCode)
	}

	if statuses[0] != http.StatusOK {
		t.Error("expected the first request to be served, got", statuses[0])
	}

	if statuses[1] != http.StatusProxyAuthRequired {
		t.Error("expected the replayed request to be refused, got", statuses[1])
	}
}

// A nonce this proxy never issued has to be refused, whatever digest comes
// with it.
func TestDigestAuthRejectsAnUnknownNonce(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	client, _ := newTestProxy(t, Config{}, WithCredentials(testDigestUsers()))

	nonce := "0123456789abcdef0123456789abcdef"

	req, err := http.NewRequest(http.MethodGet, background.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", digestHeader(nonce, digestResponse(nonce), nc))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Error("expected status 407, got", resp.Status)
	}
}

func TestBasicAuthWithCurl(t *testing.T) {
	needsCommand(t, "curl")

	expected := ":c>"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	_, proxyURL := newTestProxy(t, Config{}, WithCredentials(testBasicUsers()))

	out, err := exec.Command("curl",
		"--silent",
		"--show-error",
		"--proxy", proxyURL,
		"--proxy-user", user+":"+password,
		"--url", background.URL+"/[1-3]",
	).CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}

	if expected := times(3, expected); string(out) != expected {
		t.Error("expected", expected, "got", string(out))
	}
}

func TestBasicConnectAuthWithCurl(t *testing.T) {
	needsCommand(t, "curl")

	expected := ":c>"

	background := httptest.NewTLSServer(constantHandler(expected))
	defer background.Close()

	_, proxyURL := newTestProxy(t,
		Config{AllowedConnectPorts: []int{portOf(t, background.URL)}},
		WithCredentials(testBasicUsers()))

	out, err := exec.Command("curl",
		"--silent",
		"--show-error",
		"--insecure",
		"--proxy", proxyURL,
		"--proxy-user", user+":"+password,
		"--proxytunnel",
		"--url", background.URL+"/[1-3]",
	).CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}

	if expected := times(3, expected); string(out) != expected {
		t.Error("expected", expected, "got", string(out))
	}
}

func TestDigestAuthWithCurl(t *testing.T) {
	needsCommand(t, "curl")

	expected := "Hello, World!"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	_, proxyURL := newTestProxy(t, Config{}, WithCredentials(testDigestUsers()))

	out, err := exec.Command("curl",
		"--silent",
		"--show-error",
		"--proxy-digest",
		"--proxy", proxyURL,
		"--proxy-user", user+":"+password,
		"--url", background.URL,
	).CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}

	if string(out) != expected {
		t.Error("expected", expected, "got", string(out))
	}
}

func TestDigestAuthWithPython(t *testing.T) {
	needsCommand(t, "python3")

	expected := "Hello, World!"

	background := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprint(w, expected)
	}))
	defer background.Close()

	_, proxyURL := newTestProxy(t, Config{}, WithCredentials(testDigestUsers()))

	out, err := exec.Command("python3",
		"proxy-digest-auth-test.py",
		"--proxy", proxyURL,
		"--user", user,
		"--password", password,
		"--url", background.URL,
	).CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}

	// python adds '\n' so we need to remove it
	result := strings.Trim(string(out), "\r\n")

	// output comes in the form b'...', so remove prefix "b'" and suffix "'"
	if len(result) <= 3 {
		t.Fatal("response is too short")
	}

	if result = result[2 : len(result)-2]; result != expected {
		t.Error("expected", expected, "got", result)
	}
}

func TestIPBasedAccessDenied(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	client, _ := newTestProxy(t, Config{AllowedNetworks: []string{"172.16.11.0/24"}})

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("expected 403 status code, got", resp.Status)
	}
}

func TestIPBasedAccessAllowed(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(constantHandler(expected))
	defer background.Close()

	client, _ := newTestProxy(t, Config{AllowedNetworks: []string{"127.0.0.1/32"}})

	resp, err := client.Get(background.URL)
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

// A client that is on the disallowed list is refused even when the allowed
// list would let it through.
func TestDisallowedNetworkWins(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	client, _ := newTestProxy(t, Config{
		AllowedNetworks:    []string{"127.0.0.0/8"},
		DisallowedNetworks: []string{"127.0.0.1/32"},
	})

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Error("expected 403 status code, got", resp.Status)
	}
}

func TestHTTPSConnectDenied(t *testing.T) {
	background := httptest.NewTLSServer(constantHandler("Hello, World!"))
	defer background.Close()

	// the test server binds to a port other than 443
	client, _ := newTestProxy(t, Config{AllowedConnectPorts: []int{443}})

	if _, err := client.Get(background.URL); err == nil {
		t.Fatal("expected the CONNECT request to be rejected")
	}
}

func TestHTTPSConnectAllowed(t *testing.T) {
	background := httptest.NewTLSServer(constantHandler("Hello, World!"))
	defer background.Close()

	client, _ := newTestProxy(t, Config{AllowedConnectPorts: []int{portOf(t, background.URL)}})

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error("expected 200 status code, got", resp.Status)
	}
}

func portOf(t *testing.T, rawURL string) int {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("couldn't parse %v: %v", rawURL, err)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("couldn't read the port of %v: %v", rawURL, err)
	}

	return port
}
