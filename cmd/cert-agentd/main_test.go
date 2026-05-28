package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePEMCertKey generates a self-signed ECDSA cert with the given
// Subject CN, writes its cert and key PEM files to the supplied
// paths, and returns the SerialNumber so the caller can confirm
// which cert was loaded via certReloader.
func writePEMCertKey(t *testing.T, certPath, keyPath, cn string, serial int64) *big.Int {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn}, // SAN mirrors CN so hostname verification finds a match
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return tmpl.SerialNumber
}
func TestLoadCAPool_RejectsBundleWithoutPEM(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "ca")
	_ = os.WriteFile(bad, []byte("not a pem"), 0o644)
	_, err := loadCAPool(bad)
	if err == nil || !strings.Contains(err.Error(), "no PEM certs") {
		t.Errorf("err = %v, want no-PEM rejection", err)
	}
}

func TestLoadCAPool_AcceptsValidBundle(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, "ca", 1)
	pool, err := loadCAPool(certPath)
	if err != nil {
		t.Fatalf("loadCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}
	// Equivalent cert can be verified against the pool.
	pemBytes, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(pemBytes)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("cert should verify against pool: %v", err)
	}
}
