package microproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// headerCheckHandler answers "OK" when the request carries every header it was
// given, and reports what it did receive otherwise.
type headerCheckHandler struct {
	headers map[string]string
}

func (h *headerCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for name, value := range h.headers {
		if r.Header.Get(name) != value {
			fmt.Fprintf(w, "FAIL. Headers: %v", r.Header)

			return
		}
	}

	fmt.Fprint(w, "OK")
}

func expectHeaders(t *testing.T, cfg Config, headers map[string]string) {
	t.Helper()

	background := httptest.NewServer(&headerCheckHandler{headers: headers})
	defer background.Close()

	client, _ := newTestProxy(t, cfg)

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Error("expected 200 status code, got", resp.Status)
	}

	if body := readBody(t, resp); body != "OK" {
		t.Errorf("expected 'OK', got '%s'", body)
	}
}

func TestCustomHeaders(t *testing.T) {
	expected := map[string]string{
		"X-Custom-Header-1": "Value-1",
		"X-Custom-Header-2": "Value-2",
	}

	expectHeaders(t, Config{
		AddHeaders: [][]string{
			{"X-Custom-Header-1", "Value-1"},
			{"X-Custom-Header-2", "Value-2"},
		},
	}, expected)
}

func TestViaHeaders(t *testing.T) {
	expectHeaders(t,
		Config{ViaHeader: "on", ViaProxyName: "octopus"},
		map[string]string{"Via": "1.1 octopus"})
}

// A request that already carries a Via header has to leave with a single one
// listing this proxy after the hops it went through, not with the inbound value
// repeated next to the extended one.
func TestViaHeaderAppendedToExistingOne(t *testing.T) {
	received := make(chan []string, 1)

	background := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Values("Via")
		fmt.Fprint(w, "OK")
	}))
	defer background.Close()

	client, _ := newTestProxy(t, Config{ViaHeader: "on", ViaProxyName: "octopus"})

	req, err := http.NewRequest(http.MethodGet, background.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Via", "1.0 upstream-cache")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	headers := <-received

	expected := "1.0 upstream-cache, 1.1 octopus"
	if len(headers) != 1 || headers[0] != expected {
		t.Errorf("expected a single Via header '%v', got %v", expected, headers)
	}
}

// X-Forwarded-For behaves the same way: the client's address is appended to the
// hops already listed, and "truncate" keeps only the client's own.
func TestForwardedForHeader(t *testing.T) {
	tests := map[string]struct {
		action   string
		sent     string
		expected func(clientIP string) string
	}{
		"on appends":            {"on", "10.0.0.1", func(ip string) string { return "10.0.0.1, " + ip }},
		"on adds":               {"on", "", func(ip string) string { return ip }},
		"truncate replaces":     {"truncate", "10.0.0.1", func(ip string) string { return ip }},
		"delete removes":        {"delete", "10.0.0.1", func(string) string { return "" }},
		"off leaves it alone":   {"off", "10.0.0.1", func(string) string { return "10.0.0.1" }},
		"off adds nothing":      {"off", "", func(string) string { return "" }},
		"delete removes it all": {"delete", "", func(string) string { return "" }},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			received := make(chan string, 1)

			background := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.Header.Get("X-Forwarded-For")
				fmt.Fprint(w, "OK")
			}))
			defer background.Close()

			client, _ := newTestProxy(t, Config{ForwardedForHeader: test.action})

			req, err := http.NewRequest(http.MethodGet, background.URL, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			if test.sent != "" {
				req.Header.Set("X-Forwarded-For", test.sent)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			// the proxy connects from the loopback in these tests
			if actual, expected := <-received, test.expected("127.0.0.1"); actual != expected {
				t.Errorf("expected X-Forwarded-For '%v', got '%v'", expected, actual)
			}
		})
	}
}

// Handlers are registered once, but have to serve the requests that arrive
// after a reload with the reloaded configuration.
func TestReloadedConfigurationIsUsed(t *testing.T) {
	background := httptest.NewServer(&headerCheckHandler{
		headers: map[string]string{"X-Test-Header": "reloaded"},
	})
	defer background.Close()

	server, err := New(Config{AddHeaders: [][]string{{"X-Test-Header", "startup"}}})
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(server.Handler())
	defer proxyServer.Close()

	if err := server.Reload(Config{AddHeaders: [][]string{{"X-Test-Header", "reloaded"}}}); err != nil {
		t.Fatal(err)
	}

	client := proxyClient(t, proxyServer.URL)

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, resp); body != "OK" {
		t.Errorf("expected 'OK', got '%s'", body)
	}
}

// A reload that can't be used has to leave the running configuration in place.
func TestFailedReloadKeepsTheRunningConfiguration(t *testing.T) {
	server, err := New(Config{AddHeaders: [][]string{{"X-Test-Header", "startup"}}})
	if err != nil {
		t.Fatal(err)
	}

	if err := server.Reload(Config{ViaHeader: "nonsense"}); err == nil {
		t.Fatal("expected the reload to be refused")
	}

	headers := server.Config().AddHeaders
	if len(headers) != 1 || headers[0][1] != "startup" {
		t.Errorf("expected the startup configuration to still be in force, got %v", headers)
	}
}
