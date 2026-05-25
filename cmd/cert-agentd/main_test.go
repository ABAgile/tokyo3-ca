package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestCertReloader_LoadsInitialPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	wantSerial := writePEMCertKey(t, certPath, keyPath, "initial", 1)

	r, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	cert, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if leaf.SerialNumber.Cmp(wantSerial) != 0 {
		t.Errorf("loaded cert serial = %v, want %v", leaf.SerialNumber, wantSerial)
	}
}

func TestCertReloader_RefreshPicksUpNewCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	firstSerial := writePEMCertKey(t, certPath, keyPath, "v1", 1)

	r, _ := newCertReloader(certPath, keyPath)

	// Renewal happens on disk — same paths, different cert.
	secondSerial := writePEMCertKey(t, certPath, keyPath, "v2", 2)
	if firstSerial.Cmp(secondSerial) == 0 {
		t.Fatal("test setup: serials should differ")
	}

	// Before Refresh, the reloader still returns the original cert.
	cert, _ := r.GetClientCertificate(nil)
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if leaf.SerialNumber.Cmp(firstSerial) != 0 {
		t.Errorf("before Refresh: serial = %v, want %v (stale)", leaf.SerialNumber, firstSerial)
	}

	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	cert, _ = r.GetClientCertificate(nil)
	leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	if leaf.SerialNumber.Cmp(secondSerial) != 0 {
		t.Errorf("after Refresh: serial = %v, want %v", leaf.SerialNumber, secondSerial)
	}
}

func TestCertReloader_RejectsMissingFiles(t *testing.T) {
	_, err := newCertReloader("/no/such/cert", "/no/such/key")
	if err == nil {
		t.Fatal("expected error for missing files")
	}
}

func TestCertReloader_ConcurrentGetClientCertWithRefresh(t *testing.T) {
	// GetClientCertificate is called from TLS handshakes in parallel
	// with Refresh from the renewer's OnRenewed hook. The race
	// detector catches a missing lock here; the assertion just
	// confirms no nil cert leaks out under contention.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, "initial", 1)
	r, _ := newCertReloader(certPath, keyPath)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					cert, err := r.GetClientCertificate(nil)
					if err != nil || cert == nil {
						t.Errorf("GetClientCertificate returned nil/err under contention: %v", err)
						return
					}
				}
			}
		})
	}
	for i := range 10 {
		// New cert + Refresh.
		writePEMCertKey(t, certPath, keyPath, "v", int64(2+i))
		if err := r.Refresh(); err != nil {
			t.Errorf("Refresh %d: %v", i, err)
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
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

// Compile-time check: the reloader's getter actually matches
// tls.Config.GetClientCertificate.
var _ = func() {
	var r *certReloader
	cfg := &tls.Config{GetClientCertificate: r.GetClientCertificate}
	_ = cfg
}
