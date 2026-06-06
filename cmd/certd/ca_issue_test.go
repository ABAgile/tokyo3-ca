package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// setupTestCA writes a PKCS#8 Ed25519 CA key file and a self-signed issuer
// cert over it, returning their paths (the inputs the issue-* commands need).
func setupTestCA(t *testing.T) (keyPath, caCertPath string) {
	t.Helper()
	dir := t.TempDir()
	_, keyPEM, err := generateLeafKey("ed25519")
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	keyPath = filepath.Join(dir, "ca.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write ca key: %v", err)
	}
	sig, err := signer.LoadEd25519FromPEMFile(keyPath)
	if err != nil {
		t.Fatalf("load ca key: %v", err)
	}
	issuer, err := x509engine.NewSelfSignedCA(rand.Reader, sig, "tokyo3-ca-test")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	caCertPath = filepath.Join(dir, "issuer.crt")
	if err := writeCertPEM(caCertPath, issuer, false); err != nil {
		t.Fatalf("write issuer: %v", err)
	}
	return keyPath, caCertPath
}

func loadCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s: no PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: parse: %v", path, err)
	}
	return cert
}

func runCmd(cmd *cobra.Command, args ...string) error {
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

// assertChainsTo verifies leaf chains to issuer and that the on-disk key
// matches the leaf's public key with 0600 perms.
func assertLeaf(t *testing.T, certOut, keyOut string, issuer *x509.Certificate) *x509.Certificate {
	t.Helper()
	leaf := loadCertFile(t, certOut)
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("chain verify: %v", err)
	}
	fi, err := os.Stat(keyOut)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perms = %v, want 0600", fi.Mode().Perm())
	}
	kb, _ := os.ReadFile(keyOut)
	blk, _ := pem.Decode(kb)
	priv, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	ks, ok := priv.(crypto.Signer)
	if !ok || !publicKeysEqual(ks.Public(), leaf.PublicKey) {
		t.Error("written key does not match the issued cert")
	}
	return leaf
}

func hasEKU(leaf *x509.Certificate, want x509.ExtKeyUsage) bool {
	return slices.Contains(leaf.ExtKeyUsage, want)
}

func TestIssueWorkload_HappyPath(t *testing.T) {
	keyPath, caCertPath := setupTestCA(t)
	issuer := loadCertFile(t, caCertPath)
	for _, keyType := range []string{"ed25519", "ecdsa-p256"} {
		t.Run(keyType, func(t *testing.T) {
			dir := t.TempDir()
			certOut := filepath.Join(dir, "svid.pem")
			keyOut := filepath.Join(dir, "svid.key")
			if err := runCmd(caIssueWorkloadCmd(),
				"--spiffe-uri", "spiffe://tokyo3/authd/agent", "--cn", "auth_app",
				"--key-type", keyType, "--ca-cert", caCertPath, "--key", keyPath,
				"--out-cert", certOut, "--out-key", keyOut,
			); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			leaf := assertLeaf(t, certOut, keyOut, issuer)
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://tokyo3/authd/agent" {
				t.Errorf("URIs = %v", leaf.URIs)
			}
			if leaf.Subject.CommonName != "auth_app" {
				t.Errorf("CN = %q", leaf.Subject.CommonName)
			}
			if !hasEKU(leaf, x509.ExtKeyUsageClientAuth) {
				t.Error("workload SVID missing clientAuth EKU")
			}
		})
	}
}

func TestIssueWorkload_RequiresSpiffeURI(t *testing.T) {
	keyPath, caCertPath := setupTestCA(t)
	dir := t.TempDir()
	if err := runCmd(caIssueWorkloadCmd(),
		"--ca-cert", caCertPath, "--key", keyPath,
		"--out-cert", filepath.Join(dir, "c"), "--out-key", filepath.Join(dir, "k"),
	); err == nil {
		t.Fatal("expected error when --spiffe-uri is missing")
	}
}

func TestIssueWorkload_RejectsCACertKeyMismatch(t *testing.T) {
	keyPath, _ := setupTestCA(t)
	_, otherCA := setupTestCA(t) // issuer over a DIFFERENT key
	dir := t.TempDir()
	if err := runCmd(caIssueWorkloadCmd(),
		"--spiffe-uri", "spiffe://x/y", "--ca-cert", otherCA, "--key", keyPath,
		"--out-cert", filepath.Join(dir, "c"), "--out-key", filepath.Join(dir, "k"),
	); err == nil {
		t.Fatal("expected error when --ca-cert key != signing key")
	}
}

func TestIssueServer_HappyPath(t *testing.T) {
	keyPath, caCertPath := setupTestCA(t)
	issuer := loadCertFile(t, caCertPath)
	dir := t.TempDir()
	certOut := filepath.Join(dir, "nats.crt")
	keyOut := filepath.Join(dir, "nats.key")
	if err := runCmd(caIssueServerCmd(),
		"--dns", "nats", "--dns", "localhost", "--ip", "127.0.0.1",
		"--ca-cert", caCertPath, "--key", keyPath,
		"--out-cert", certOut, "--out-key", keyOut,
	); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	leaf := assertLeaf(t, certOut, keyOut, issuer)
	if got := leaf.DNSNames; len(got) != 2 || got[0] != "nats" || got[1] != "localhost" {
		t.Errorf("DNSNames = %v", got)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v", leaf.IPAddresses)
	}
	if !hasEKU(leaf, x509.ExtKeyUsageServerAuth) {
		t.Error("server cert missing serverAuth EKU")
	}
	if leaf.Subject.CommonName != "nats" { // defaults to first --dns
		t.Errorf("CN = %q, want nats", leaf.Subject.CommonName)
	}
}

func TestIssueServer_RequiresSAN(t *testing.T) {
	keyPath, caCertPath := setupTestCA(t)
	dir := t.TempDir()
	if err := runCmd(caIssueServerCmd(),
		"--ca-cert", caCertPath, "--key", keyPath,
		"--out-cert", filepath.Join(dir, "c"), "--out-key", filepath.Join(dir, "k"),
	); err == nil {
		t.Fatal("expected error when neither --dns nor --ip is given")
	}
}

func TestIssueServer_RejectsBadIP(t *testing.T) {
	keyPath, caCertPath := setupTestCA(t)
	dir := t.TempDir()
	if err := runCmd(caIssueServerCmd(),
		"--ip", "not-an-ip", "--ca-cert", caCertPath, "--key", keyPath,
		"--out-cert", filepath.Join(dir, "c"), "--out-key", filepath.Join(dir, "k"),
	); err == nil {
		t.Fatal("expected error for an invalid --ip")
	}
}
