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

// writeTestCert writes a self-signed cert with the given validity
// window to dir and returns its path.
func writeTestCert(t *testing.T, dir string, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "check-cert-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckCert(t *testing.T) {
	now := time.Now()

	t.Run("valid", func(t *testing.T) {
		p := writeTestCert(t, t.TempDir(), now.Add(-time.Hour), now.Add(time.Hour))
		if err := checkCert(p, 30*time.Second, now); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		p := writeTestCert(t, t.TempDir(), now.Add(-2*time.Hour), now.Add(-time.Hour))
		if err := checkCert(p, 30*time.Second, now); err == nil {
			t.Fatal("want error for expired cert")
		}
	})

	t.Run("expires within window", func(t *testing.T) {
		p := writeTestCert(t, t.TempDir(), now.Add(-time.Hour), now.Add(10*time.Second))
		if err := checkCert(p, 30*time.Second, now); err == nil {
			t.Fatal("want error for cert expiring within --within")
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		p := writeTestCert(t, t.TempDir(), now.Add(time.Hour), now.Add(2*time.Hour))
		if err := checkCert(p, 30*time.Second, now); err == nil {
			t.Fatal("want error for not-yet-valid cert")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if err := checkCert(filepath.Join(t.TempDir(), "absent.pem"), 30*time.Second, now); err == nil {
			t.Fatal("want error for missing file")
		}
	})

	t.Run("not a cert", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "junk.pem")
		if err := os.WriteFile(p, []byte("not pem"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkCert(p, 30*time.Second, now); err == nil {
			t.Fatal("want error for non-PEM file")
		}
	})
}
