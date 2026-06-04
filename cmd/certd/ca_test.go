package main

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// mintIssuerForTest produces a self-signed issuer cert from a fresh
// ephemeral key — the same path `certd ca bootstrap` takes.
func mintIssuerForTest(t *testing.T, cn string) []byte {
	t.Helper()
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("NewEphemeralEd25519: %v", err)
	}
	cert, err := x509engine.NewSelfSignedCA(rand.Reader, sig, cn)
	if err != nil {
		t.Fatalf("NewSelfSignedCA: %v", err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, cn+".crt")
	if err := writeCertPEM(out, cert, false); err != nil {
		t.Fatalf("writeCertPEM: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read minted cert: %v", err)
	}
	return b
}

func TestWriteCertPEM_OverwriteGuard(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "issuer.crt")
	sig, _ := signer.NewEphemeralEd25519()
	cert, _ := x509engine.NewSelfSignedCA(rand.Reader, sig, "tokyo3-ca")

	if err := writeCertPEM(out, cert, false); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeCertPEM(out, cert, false); err == nil {
		t.Fatal("second write without --force should error")
	}
	if err := writeCertPEM(out, cert, true); err != nil {
		t.Fatalf("write with force: %v", err)
	}
}

func TestReadCertFilePEM_RejectsNonCert(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "notacert.pem")
	if err := os.WriteFile(bad, []byte("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCertFilePEM(bad); err == nil {
		t.Fatal("expected error for non-CERTIFICATE PEM")
	}
	if _, err := readCertFilePEM(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWriteBundle_ConcatenatesInOrder(t *testing.T) {
	a := mintIssuerForTest(t, "old")
	b := mintIssuerForTest(t, "new")
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.crt")

	if err := writeBundle(out, [][]byte{a, b}, false); err != nil {
		t.Fatalf("writeBundle: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(got), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("bundle has %d certs, want 2", n)
	}
	// Each input must round-trip back out of the bundle, in order.
	if !strings.HasPrefix(string(got), string(a)) {
		t.Error("bundle does not start with the first (old) cert")
	}
}

func TestResolveCASigner_RequiresSource(t *testing.T) {
	if _, err := resolveCASigner(context.Background(), "", ""); err == nil {
		t.Fatal("resolveCASigner with no key source should error")
	}
}

func TestResolveCASigner_KMSWithoutBinding(t *testing.T) {
	// Default build has no KMS factory registered → a KMS key ref must
	// fail with a clear "no binding compiled in" error, not a panic.
	if kmsClientFactory != nil {
		t.Skip("a KMS binding is registered in this build")
	}
	_, err := resolveCASigner(context.Background(), "", "arn:aws:kms:...:key/abc")
	if err == nil || !strings.Contains(err.Error(), "no KMS binding") {
		t.Fatalf("err = %v, want 'no KMS binding compiled in'", err)
	}
}
