package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
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

func TestCertReloader_LoadsInitialPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	wantSerial := writePEMCertKey(t, certPath, keyPath, "initial", 1)

	r, err := newCertReloader(certPath, keyPath, certPath, nil)
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

func TestCertReloader_LeafExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, "initial", 1)

	r, err := newCertReloader(certPath, keyPath, certPath, nil)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	exp := r.LeafExpiry()
	// writePEMCertKey sets NotAfter to now+1h; allow a wide window
	// for slow CI without losing the assertion's intent.
	remaining := time.Until(exp)
	if remaining < 30*time.Minute || remaining > 90*time.Minute {
		t.Errorf("LeafExpiry remaining = %v, want ~1h", remaining)
	}
}

func TestCertReloader_RefreshPicksUpNewCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	firstSerial := writePEMCertKey(t, certPath, keyPath, "v1", 1)

	r, _ := newCertReloader(certPath, keyPath, certPath, nil)

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
	_, err := newCertReloader("/no/such/cert", "/no/such/key", "/no/such/ca", nil)
	if err == nil {
		t.Fatal("expected error for missing files")
	}
}

// TestCertReloader_RefreshCABundleOnMtimeChange asserts the
// mtime-poll path: writing a new bundle PEM with a later mtime
// must update the in-memory pool. Same mtime → no-op.
func TestCertReloader_RefreshCABundleOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "initial", 1)
	caV1Path := filepath.Join(dir, "ca-v1.pem")
	caV2Path := filepath.Join(dir, "ca-v2.pem")
	writePEMCertKey(t, caV1Path, filepath.Join(dir, "ca-v1.key"), "ca-v1", 100)
	writePEMCertKey(t, caV2Path, filepath.Join(dir, "ca-v2.key"), "ca-v2", 200)
	caV1, _ := os.ReadFile(caV1Path)
	caV2, _ := os.ReadFile(caV2Path)
	if err := os.WriteFile(caPath, caV1, 0o644); err != nil {
		t.Fatalf("write initial bundle: %v", err)
	}

	r, err := newCertReloader(certPath, keyPath, caPath, nil)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	initialMtime := r.caMtime

	// Re-call refreshCABundle without changing the file — no-op.
	if err := r.refreshCABundle(); err != nil {
		t.Fatalf("refreshCABundle (unchanged): %v", err)
	}
	if !r.caMtime.Equal(initialMtime) {
		t.Errorf("caMtime advanced without file change: %v → %v", initialMtime, r.caMtime)
	}

	// Drop in an expanded bundle. Sleep so the filesystem records a
	// different mtime (second-granularity filesystems can otherwise
	// collapse two rapid writes onto the same stamp).
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(caPath, append(caV1, caV2...), 0o644); err != nil {
		t.Fatalf("write expanded bundle: %v", err)
	}
	if err := r.refreshCABundle(); err != nil {
		t.Fatalf("refreshCABundle (after change): %v", err)
	}
	if !r.caMtime.After(initialMtime) {
		t.Errorf("caMtime did not advance after file change: %v → %v", initialMtime, r.caMtime)
	}
}

// TestCertReloader_LogsOnBundleReload asserts the info log
// operators rely on for rotation coordination fires (only) when
// the pool actually changes. No-op polls stay silent.
func TestCertReloader_LogsOnBundleReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "initial", 1)
	caV1Path := filepath.Join(dir, "ca-v1.pem")
	caV2Path := filepath.Join(dir, "ca-v2.pem")
	writePEMCertKey(t, caV1Path, filepath.Join(dir, "ca-v1.key"), "ca-v1", 100)
	writePEMCertKey(t, caV2Path, filepath.Join(dir, "ca-v2.key"), "ca-v2", 200)
	caV1, _ := os.ReadFile(caV1Path)
	caV2, _ := os.ReadFile(caV2Path)
	if err := os.WriteFile(caPath, caV1, 0o644); err != nil {
		t.Fatalf("write initial bundle: %v", err)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	r, err := newCertReloader(certPath, keyPath, caPath, log)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	// Constructor's first refresh fires one log line.
	if got := strings.Count(buf.String(), "CA bundle reloaded"); got != 1 {
		t.Errorf("after construction: %d 'CA bundle reloaded' lines, want 1", got)
	}
	wantFP := bundleFingerprint(caV1)
	if !strings.Contains(buf.String(), "fingerprint="+wantFP) {
		t.Errorf("constructor log missing fingerprint=%s; got:\n%s", wantFP, buf.String())
	}

	// No-op poll stays silent.
	buf.Reset()
	if err := r.refreshCABundle(); err != nil {
		t.Fatalf("refreshCABundle (no-op): %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no-op poll logged: %s", buf.String())
	}

	// Drop in [v1, v2] — second log line fires with new fingerprint.
	time.Sleep(1100 * time.Millisecond)
	expanded := append(caV1, caV2...)
	if err := os.WriteFile(caPath, expanded, 0o644); err != nil {
		t.Fatalf("write expanded bundle: %v", err)
	}
	if err := r.refreshCABundle(); err != nil {
		t.Fatalf("refreshCABundle (after change): %v", err)
	}
	wantFP2 := bundleFingerprint(expanded)
	if !strings.Contains(buf.String(), "fingerprint="+wantFP2) {
		t.Errorf("expected log with fingerprint=%s; got:\n%s", wantFP2, buf.String())
	}
}

// TestCertReloader_VerifyConnection_UsesCurrentPool exercises the
// VerifyConnection callback against a synthesised tls.ConnectionState.
// A peer signed by a CA in the bundle verifies; one signed outside
// does not.
func TestCertReloader_VerifyConnection_UsesCurrentPool(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "agent", 1)

	// Use the agent's own self-signed cert as the trusted CA. A peer
	// presenting that same cert verifies; a different self-signed
	// cert (= different CA) does not.
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(caPath, b, 0o644); err != nil {
		t.Fatalf("write ca bundle: %v", err)
	}
	r, err := newCertReloader(certPath, keyPath, caPath, nil)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	trustedBlock, _ := pem.Decode(b)
	trustedLeaf, err := x509.ParseCertificate(trustedBlock.Bytes)
	if err != nil {
		t.Fatalf("parse trusted leaf: %v", err)
	}

	cs := tls.ConnectionState{
		ServerName:       "agent",
		PeerCertificates: []*x509.Certificate{trustedLeaf},
	}
	if err := r.VerifyConnection(cs); err != nil {
		t.Errorf("VerifyConnection (trusted): %v", err)
	}

	// Untrusted peer: a fresh self-signed cert not in the bundle.
	otherCertPath := filepath.Join(dir, "other.pem")
	otherKeyPath := filepath.Join(dir, "other.key")
	writePEMCertKey(t, otherCertPath, otherKeyPath, "agent", 99)
	otherPEM, _ := os.ReadFile(otherCertPath)
	otherBlock, _ := pem.Decode(otherPEM)
	otherLeaf, err := x509.ParseCertificate(otherBlock.Bytes)
	if err != nil {
		t.Fatalf("parse other leaf: %v", err)
	}
	cs.PeerCertificates = []*x509.Certificate{otherLeaf}
	if err := r.VerifyConnection(cs); err == nil {
		t.Error("VerifyConnection (untrusted) should reject peer signed outside bundle")
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
	r, _ := newCertReloader(certPath, keyPath, certPath, nil)

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
