package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// issuerPEM self-signs a CA issuer cert over sig and returns its PEM.
func issuerPEM(t *testing.T, sig signer.Signer) []byte {
	t.Helper()
	cert, err := x509engine.NewSelfSignedCA(rand.Reader, sig, "tokyo3-ca-test")
	if err != nil {
		t.Fatalf("NewSelfSignedCA: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// bumpMTime forces a distinct mtime so the reloader's mtime gate fires even
// when two writes land within the filesystem's timestamp resolution.
func bumpMTime(t *testing.T, path string, d time.Duration) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mt := fi.ModTime().Add(d)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func TestPEMReloader_ReloadsOnChange_KeepsLastGoodOnBadFile(t *testing.T) {
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	path := filepath.Join(t.TempDir(), "issuer.crt")
	if err := os.WriteFile(path, issuerPEM(t, sig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	rl, err := newPEMReloader(path, "issuer", slog.New(slog.DiscardHandler), issuerLoader(sig.Public()))
	if err != nil {
		t.Fatalf("newPEMReloader: %v", err)
	}
	first := rl.get()
	if first == nil {
		t.Fatal("get returned nil after successful load")
	}

	// A truncated/garbage drop-in must be IGNORED — the last good cert stays.
	if err := os.WriteFile(path, []byte("not a pem"), 0o644); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	bumpMTime(t, path, 2*time.Second)
	if got := rl.get(); got == nil || !got.Equal(first) {
		t.Fatal("bad drop-in should keep the previous value (fail-safe)")
	}

	// A valid same-key re-mint must be picked up live.
	if err := os.WriteFile(path, issuerPEM(t, sig), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	bumpMTime(t, path, 4*time.Second)
	if got := rl.get(); got == nil {
		t.Fatal("valid re-mint should reload")
	}
}

func TestNewPEMReloader_FailsFastOnMissingFile(t *testing.T) {
	_, err := newPEMReloader(filepath.Join(t.TempDir(), "nope.crt"), "issuer",
		slog.New(slog.DiscardHandler), loadCAPool)
	if err == nil {
		t.Fatal("expected error for a missing file at construction")
	}
}

func TestIssuerLoader_RejectsKeyMismatch(t *testing.T) {
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	other, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	certPEM := issuerPEM(t, sig)

	// Same key → accepted.
	if _, err := issuerLoader(sig.Public())(certPEM); err != nil {
		t.Fatalf("matching key should load: %v", err)
	}
	// Different key → refused (the live-swap guard).
	if _, err := issuerLoader(other.Public())(certPEM); err == nil {
		t.Fatal("issuer cert with a non-matching public key must be refused")
	}
}

func TestBuildServerTLS_ClientCAHotReloadWiring(t *testing.T) {
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "client-ca.crt")
	if err := os.WriteFile(caPath, issuerPEM(t, sig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Only the client CA is set, so the server cert self-signs (dev path).
	t.Setenv("CERTD_API_CLIENT_CA", caPath)
	t.Setenv("CERTD_API_CERT", "")
	t.Setenv("CERTD_API_KEY", "")
	t.Setenv("CERTD_WORKLOAD_CA", "")

	cfg, err := buildServerTLS(slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient not wired — client CA can't hot-reload")
	}
	sub, err := cfg.GetConfigForClient(nil)
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if sub.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", sub.ClientAuth)
	}
	if sub.ClientCAs == nil {
		t.Error("per-handshake config has nil ClientCAs")
	}
	if sub.GetConfigForClient != nil {
		t.Error("per-handshake config must not recurse (GetConfigForClient should be nil)")
	}
}

func TestLoadCAPool_ParsesIssuer(t *testing.T) {
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pool, err := loadCAPool(issuerPEM(t, sig))
	if err != nil {
		t.Fatalf("loadCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}
