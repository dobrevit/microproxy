package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPair puts a self-signed certificate and its key at the given paths,
// with serial as the way to tell one from another.
func writeKeyPair(t *testing.T, certPath, keyPath string, serial int64) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "microproxy"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func serialOf(t *testing.T, reloader *certificateReloader) int64 {
	t.Helper()

	certificate, err := reloader.tlsConfig().GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	return leaf.SerialNumber.Int64()
}

// A renewed certificate has to be picked up without restarting the proxy.
func TestCertificateReloader(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "proxy.crt")
	keyPath := filepath.Join(dir, "proxy.key")

	writeKeyPair(t, certPath, keyPath, 1)

	reloader, err := newCertificateReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if serial := serialOf(t, reloader); serial != 1 {
		t.Fatalf("expected the first certificate, got serial %v", serial)
	}

	// renewal replaces the files underneath the running proxy
	writeKeyPair(t, certPath, keyPath, 2)

	if serial := serialOf(t, reloader); serial != 1 {
		t.Error("expected the certificate in force to be unchanged until a reload")
	}

	if err := reloader.reload(); err != nil {
		t.Fatal(err)
	}

	if serial := serialOf(t, reloader); serial != 2 {
		t.Errorf("expected the renewed certificate, got serial %v", serial)
	}
}

// A half-written or broken pair must not take the listener down.
func TestCertificateReloaderKeepsTheCurrentPairOnError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "proxy.crt")
	keyPath := filepath.Join(dir, "proxy.key")

	writeKeyPair(t, certPath, keyPath, 1)

	reloader, err := newCertificateReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certPath, []byte("half a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := reloader.reload(); err == nil {
		t.Error("expected a broken pair to be reported")
	}

	if serial := serialOf(t, reloader); serial != 1 {
		t.Errorf("expected the working certificate to still be served, got serial %v", serial)
	}
}

// A pair that cannot be read at all is a startup error, not a surprise on the
// first client.
func TestCertificateReloaderReportsAMissingPair(t *testing.T) {
	dir := t.TempDir()

	if _, err := newCertificateReloader(
		filepath.Join(dir, "absent.crt"), filepath.Join(dir, "absent.key")); err == nil {
		t.Error("expected a missing certificate to be reported at startup")
	}
}

// The two settings only make sense together.
func TestConfigRejectsAHalfConfiguredCertificate(t *testing.T) {
	for name, contents := range map[string]string{
		"cert without key": "tls_cert_file = \"/tmp/proxy.crt\"\n",
		"key without cert": "tls_key_file = \"/tmp/proxy.key\"\n",
	} {
		path := filepath.Join(t.TempDir(), "microproxy.toml")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := loadConfig(path); err == nil {
			t.Errorf("%v: expected a configuration error", name)
		}
	}
}
