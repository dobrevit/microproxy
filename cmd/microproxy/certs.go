package main

import (
	"crypto/tls"
	"fmt"
	"sync"
)

// certificateReloader holds the proxy's own certificate and can replace it
// without restarting, which is what a 90-day certificate needs.
//
// tls.Config asks for the certificate on every handshake, so a reload takes
// effect on the next connection and the ones already established are left
// alone.
type certificateReloader struct {
	certFile string
	keyFile  string

	mu          sync.RWMutex
	certificate *tls.Certificate
}

// newCertificateReloader loads the pair once, so that a bad path or an
// unreadable key is reported at startup rather than on the first client.
func newCertificateReloader(certFile, keyFile string) (*certificateReloader, error) {
	reloader := &certificateReloader{certFile: certFile, keyFile: keyFile}

	if err := reloader.reload(); err != nil {
		return nil, err
	}

	return reloader, nil
}

// reload re-reads the pair from disk. A pair that can't be used leaves the one
// in force untouched, so a half-written file during renewal does not take the
// listener down.
func (r *certificateReloader) reload() error {
	certificate, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("couldn't load the certificate %v and key %v: %w", r.certFile, r.keyFile, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.certificate = &certificate

	return nil
}

// tlsConfig serves the certificate in force at the time of each handshake.
func (r *certificateReloader) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			r.mu.RLock()
			defer r.mu.RUnlock()

			return r.certificate, nil
		},
	}
}
