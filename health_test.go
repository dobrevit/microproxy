package microproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthTurnsUnhealthyAfterTheFailureLimit(t *testing.T) {
	health := NewHealth(3)

	if !health.Healthy() {
		t.Error("expected a new tracker to start out healthy")
	}

	health.RecordFailure()
	health.RecordFailure()

	if !health.Healthy() {
		t.Error("expected the proxy to still be healthy below the limit")
	}

	health.RecordFailure()

	if health.Healthy() {
		t.Error("expected the proxy to be unhealthy at the limit")
	}

	// a single success clears the run
	health.RecordSuccess()

	if !health.Healthy() || health.Failures() != 0 {
		t.Errorf("expected a success to clear the failures, got healthy=%v failures=%v",
			health.Healthy(), health.Failures())
	}
}

func TestHealthDefaultsTheFailureLimit(t *testing.T) {
	health := NewHealth(0)

	for i := 0; i < DefaultHealthFailureLimit-1; i++ {
		health.RecordFailure()
	}

	if !health.Healthy() {
		t.Error("expected the proxy to still be healthy below the default limit")
	}

	health.RecordFailure()

	if health.Healthy() {
		t.Error("expected the default limit to apply")
	}
}

func TestHealthHandler(t *testing.T) {
	health := NewHealth(1)
	handler := health.Handler()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", http.NoBody))

	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 while healthy, got %v", recorder.Code)
	}

	health.RecordFailure()

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", http.NoBody))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 once unhealthy, got %v", recorder.Code)
	}
}

// A served request has to count towards the proxy's health, which is what makes
// the endpoint mean anything.
func TestServerRecordsHealthOfServedRequests(t *testing.T) {
	background := httptest.NewServer(constantHandler("Hello, World!"))
	defer background.Close()

	server, err := New(Config{HealthCheckEnabled: "on"})
	if err != nil {
		t.Fatal(err)
	}

	if server.Health() == nil {
		t.Fatal("expected the configuration to enable health tracking")
	}

	// start out unhealthy, so that a served request is what turns it around
	server.Health().RecordFailure()
	server.Health().RecordFailure()
	server.Health().RecordFailure()
	server.Health().RecordFailure()
	server.Health().RecordFailure()

	if server.Health().Healthy() {
		t.Fatal("expected the proxy to be unhealthy after the failures")
	}

	proxyServer := httptest.NewServer(server.Handler())
	defer proxyServer.Close()

	resp, err := proxyClient(t, proxyServer.URL).Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !server.Health().Healthy() {
		t.Error("expected a served request to record a success")
	}
}

// Health tracking is off unless it is asked for, so that a program embedding
// the package pays nothing for it.
func TestHealthIsOffByDefault(t *testing.T) {
	server := newTestServer(t, Config{})

	if server.Health() != nil {
		t.Error("expected health tracking to be off by default")
	}
}

// A tracker supplied by the program wins over the configuration flag.
func TestWithHealthOverridesTheConfiguration(t *testing.T) {
	health := NewHealth(1)

	server, err := New(Config{HealthCheckEnabled: "on"}, WithHealth(health))
	if err != nil {
		t.Fatal(err)
	}

	if server.Health() != health {
		t.Error("expected the supplied tracker to be used")
	}
}
