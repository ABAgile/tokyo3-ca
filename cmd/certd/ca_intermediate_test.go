package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// fakeSealer is a reversible, non-identity stand-in for a KMS symmetric key so
// the test runs without AWS. The "SEALED:" prefix lets the test prove the seal
// seam actually ran (the key was transformed, not written in the clear).
type fakeSealer struct{}

func (fakeSealer) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return append([]byte("SEALED:"), plaintext...), nil
}
func (fakeSealer) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	return bytes.TrimPrefix(ciphertext, []byte("SEALED:")), nil
}

func withFakeSealer(t *testing.T) {
	t.Helper()
	// The tests use a scheme-less seal ref ("fake"), which resolveSealer routes
	// to the "aws" default — so register the fake there.
	prev := sealerFactories
	t.Cleanup(func() { sealerFactories = prev })
	sealerFactories = map[string]sealerFactory{
		"aws": func(context.Context, string) (sealer, error) { return fakeSealer{}, nil },
	}
}

// setupTestRoot writes a path-length-1 root key + cert — what issue-intermediate
// requires (NewSelfSignedCA's path-length-0 root cannot sign an intermediate).
func setupTestRoot(t *testing.T) (rootKeyPath, rootCertPath string) {
	t.Helper()
	dir := t.TempDir()
	_, keyPEM, err := generateLeafKey("ed25519")
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	rootKeyPath = filepath.Join(dir, "root.key")
	if err := os.WriteFile(rootKeyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write root key: %v", err)
	}
	sig, err := signer.LoadEd25519FromPEMFile(rootKeyPath)
	if err != nil {
		t.Fatalf("load root key: %v", err)
	}
	root, err := x509engine.NewSelfSignedRootCA(rand.Reader, sig, "tokyo3-ca-root-test")
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCertPath = filepath.Join(dir, "root.crt")
	if err := writeCertPEM(rootCertPath, root, false); err != nil {
		t.Fatalf("write root cert: %v", err)
	}
	return rootKeyPath, rootCertPath
}

func TestIssueIntermediate_HappyPath(t *testing.T) {
	withFakeSealer(t)
	rootKeyPath, rootCertPath := setupTestRoot(t)
	dir := t.TempDir()
	outCert := filepath.Join(dir, "intermediate.crt")
	outSealed := filepath.Join(dir, "intermediate.key.sealed")

	if err := runCmd(caCmd(), "issue-intermediate",
		"--root-key", "file:"+rootKeyPath,
		"--root-cert", rootCertPath,
		"--seal-key", "fake",
		"--cn", "test-int",
		"--out-cert", outCert,
		"--out-sealed-key", outSealed,
	); err != nil {
		t.Fatalf("issue-intermediate: %v", err)
	}

	// The intermediate is a path-length-0 CA that verifies to the root.
	root := loadCertFile(t, rootCertPath)
	inter := loadCertFile(t, outCert)
	if !inter.IsCA || !inter.MaxPathLenZero {
		t.Errorf("intermediate IsCA=%v MaxPathLenZero=%v, want true/true", inter.IsCA, inter.MaxPathLenZero)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := inter.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("intermediate failed to verify to root: %v", err)
	}

	// The sealed-key file is 0600 and base64(sealer(PKCS#8 of the int key)).
	fi, err := os.Stat(outSealed)
	if err != nil {
		t.Fatalf("stat sealed key: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("sealed key perms = %v, want 0600", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(outSealed)
	sealed, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("sealed key not base64: %v", err)
	}
	if !bytes.HasPrefix(sealed, []byte("SEALED:")) {
		t.Fatal("sealed key was not run through the sealer")
	}
	blk, _ := pem.Decode(bytes.TrimPrefix(sealed, []byte("SEALED:")))
	if blk == nil {
		t.Fatal("unsealed key is not PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parse unsealed key: %v", err)
	}
	ks, ok := priv.(crypto.Signer)
	if !ok || !publicKeysEqual(ks.Public(), inter.PublicKey) {
		t.Error("sealed key does not match the issued intermediate cert")
	}
}

func TestIssueIntermediate_RejectsPathLenZeroRoot(t *testing.T) {
	withFakeSealer(t)
	// setupTestCA mints a NewSelfSignedCA root → path length 0.
	keyPath, certPath := setupTestCA(t)
	dir := t.TempDir()
	err := runCmd(caCmd(), "issue-intermediate",
		"--root-key", "file:"+keyPath,
		"--root-cert", certPath,
		"--seal-key", "fake",
		"--out-cert", filepath.Join(dir, "i.crt"),
		"--out-sealed-key", filepath.Join(dir, "i.key"),
	)
	if err == nil || !strings.Contains(err.Error(), "path length 0") {
		t.Errorf("err = %v, want 'path length 0'", err)
	}
}
