package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

type pubEqualer interface{ Equal(crypto.PublicKey) bool }

func TestLoadX509Signer_SingleTierFallback(t *testing.T) {
	t.Setenv("CERTD_CA_SEALED_KEY_FILE", "")
	t.Setenv("CERTD_CA_SEAL_KMS_KEY", "")
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	got, err := loadX509Signer(context.Background(), slog.New(slog.DiscardHandler), caSig)
	if err != nil {
		t.Fatalf("loadX509Signer: %v", err)
	}
	if got != caSig {
		t.Error("single-tier: X.509 signer should fall back to the CA signer")
	}
}

func TestLoadX509Signer_RequiresBothEnv(t *testing.T) {
	t.Setenv("CERTD_CA_SEALED_KEY_FILE", filepath.Join(t.TempDir(), "k"))
	t.Setenv("CERTD_CA_SEAL_KMS_KEY", "")
	caSig, _ := signer.NewEphemeralEd25519()
	_, err := loadX509Signer(context.Background(), slog.New(slog.DiscardHandler), caSig)
	if err == nil || !strings.Contains(err.Error(), "needs both") {
		t.Errorf("err = %v, want 'needs both'", err)
	}
}

func TestLoadX509Signer_UnsealsIntermediate(t *testing.T) {
	withFakeSealer(t) // Decrypt strips the "SEALED:" prefix Encrypt adds
	pub, keyPEM, err := generateLeafKey("ed25519")
	if err != nil {
		t.Fatalf("gen intermediate key: %v", err)
	}
	// Mirror fakeSealer.Encrypt + the base64 wrapping issue-intermediate writes.
	sealed := append([]byte("SEALED:"), keyPEM...)
	b64 := base64.StdEncoding.EncodeToString(sealed)
	sealedPath := filepath.Join(t.TempDir(), "int.key.sealed")
	if err := os.WriteFile(sealedPath, []byte(b64), 0o600); err != nil {
		t.Fatalf("write sealed: %v", err)
	}
	t.Setenv("CERTD_CA_SEALED_KEY_FILE", sealedPath)
	t.Setenv("CERTD_CA_SEAL_KMS_KEY", "fake")

	caSig, _ := signer.NewEphemeralEd25519()
	got, err := loadX509Signer(context.Background(), slog.New(slog.DiscardHandler), caSig)
	if err != nil {
		t.Fatalf("loadX509Signer: %v", err)
	}
	if got == caSig {
		t.Fatal("expected a distinct unsealed signer, got the CA signer")
	}
	if !got.Public().(pubEqualer).Equal(pub) {
		t.Error("unsealed signer public key does not match the sealed intermediate key")
	}
}

func TestLoadX509Issuer_VerifiesRootChain(t *testing.T) {
	rootKeyPath, rootCertPath := setupTestRoot(t)
	rootSig, err := signer.LoadEd25519FromPEMFile(rootKeyPath)
	if err != nil {
		t.Fatalf("load root key: %v", err)
	}
	root := loadCertFile(t, rootCertPath)
	intSig, _ := signer.NewEphemeralEd25519()
	now := time.Now().UTC()
	inter, err := x509engine.SignIntermediateCA(rand.Reader, rootSig, root, x509engine.IntermediateCertParams{
		PublicKey:   intSig.Public(),
		ValidAfter:  now,
		ValidBefore: now.Add(90 * 24 * time.Hour),
		Serial:      big.NewInt(9),
	})
	if err != nil {
		t.Fatalf("sign intermediate: %v", err)
	}
	interPath := filepath.Join(t.TempDir(), "int.crt")
	if err := writeCertPEM(interPath, inter, false); err != nil {
		t.Fatalf("write intermediate: %v", err)
	}
	t.Setenv("CERTD_CA_X509_CERT_FILE", interPath)
	t.Setenv("CERTD_CA_ROOT_CERT_FILE", rootCertPath)

	cert, getter, err := loadX509Issuer(slog.New(slog.DiscardHandler), intSig)
	if err != nil {
		t.Fatalf("loadX509Issuer: %v", err)
	}
	if getter == nil {
		t.Error("expected a hot-reload getter")
	}
	if cert == nil || !cert.Equal(inter) {
		t.Error("returned issuer cert is not the intermediate")
	}
}

func TestLoadX509Issuer_RejectsWrongRoot(t *testing.T) {
	rootKeyPath, _ := setupTestRoot(t)
	rootSig, err := signer.LoadEd25519FromPEMFile(rootKeyPath)
	if err != nil {
		t.Fatalf("load root key: %v", err)
	}
	root, err := x509engine.NewSelfSignedRootCA(rand.Reader, rootSig, "root-A")
	if err != nil {
		t.Fatalf("root A: %v", err)
	}
	intSig, _ := signer.NewEphemeralEd25519()
	now := time.Now().UTC()
	inter, err := x509engine.SignIntermediateCA(rand.Reader, rootSig, root, x509engine.IntermediateCertParams{
		PublicKey:   intSig.Public(),
		ValidAfter:  now,
		ValidBefore: now.Add(90 * 24 * time.Hour),
		Serial:      big.NewInt(10),
	})
	if err != nil {
		t.Fatalf("sign intermediate: %v", err)
	}
	interPath := filepath.Join(t.TempDir(), "int.crt")
	if err := writeCertPEM(interPath, inter, false); err != nil {
		t.Fatalf("write intermediate: %v", err)
	}
	// Point the root anchor at a DIFFERENT root (B) the intermediate doesn't chain to.
	_, rootBCertPath := setupTestRoot(t)
	t.Setenv("CERTD_CA_X509_CERT_FILE", interPath)
	t.Setenv("CERTD_CA_ROOT_CERT_FILE", rootBCertPath)

	if _, _, err := loadX509Issuer(slog.New(slog.DiscardHandler), intSig); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Errorf("err = %v, want 'does not chain'", err)
	}
}
