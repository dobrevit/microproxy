package microproxy

import (
	"net/http"
	"sync"
)

// DefaultHealthFailureLimit is how many consecutive failures put a proxy in the
// unhealthy state when Config.HealthFailureLimit is not set.
const DefaultHealthFailureLimit = 5

// Health tracks whether the proxy is answering requests successfully. A run of
// consecutive failures marks it unhealthy; a single success clears the run.
//
// It is safe for concurrent use, and a program embedding this package can read
// it directly or serve it over HTTP with Handler.
type Health struct {
	mu sync.Mutex

	healthy      bool
	failures     int
	failureLimit int
}

// NewHealth returns a tracker that turns unhealthy after failureLimit
// consecutive failures. A limit of zero or less means
// DefaultHealthFailureLimit. A new tracker starts out healthy.
func NewHealth(failureLimit int) *Health {
	if failureLimit <= 0 {
		failureLimit = DefaultHealthFailureLimit
	}

	return &Health{healthy: true, failureLimit: failureLimit}
}

// RecordFailure counts a failed request, and marks the proxy unhealthy once
// enough of them have happened in a row.
func (h *Health) RecordFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.failures++
	if h.failures >= h.failureLimit {
		h.healthy = false
	}
}

// RecordSuccess counts a served request, which clears the run of failures.
func (h *Health) RecordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.healthy = true
	h.failures = 0
}

// Healthy reports the state the proxy is in.
func (h *Health) Healthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.healthy
}

// Failures is the number of consecutive failures recorded since the last
// success.
func (h *Health) Failures() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.failures
}

// Handler serves the state as a health endpoint: 200 while the proxy is
// healthy, 503 once it is not, which is what a container or a load balancer
// probes.
func (h *Health) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.Healthy() {
			http.Error(w, "Proxy is unhealthy", http.StatusServiceUnavailable)

			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Proxy is healthy\n"))
	})
}

// Health returns the proxy's health tracker, or nil when health tracking was
// not enabled with WithHealth.
func (s *Server) Health() *Health {
	return s.health
}

// recordHealth notes how a response went. An authentication challenge is a
// failure of the client rather than of the proxy, but it is what the original
// health check counted, so it is kept: a proxy whose upstream credentials have
// gone stale answers nothing but 407.
func (s *Server) recordHealth(resp *http.Response) {
	if s.health == nil {
		return
	}

	if resp == nil || resp.StatusCode == http.StatusProxyAuthRequired {
		s.health.RecordFailure()

		return
	}

	s.health.RecordSuccess()
}
