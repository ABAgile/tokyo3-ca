package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCAInitEnv_RequiresManifestArg(t *testing.T) {
	if err := runCmd(caInitEnvCmd(), "--out-dir", t.TempDir()); err == nil {
		t.Fatal("expected error when the manifest argument is omitted")
	}
}

func TestCAInitEnv_GeneratesBootstrapEnvironment(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "bootstrap.yaml")
	if err := os.WriteFile(manifest, []byte(`ssh_ca:
  key: certd-signing.key
  public_key: certd-signing.key.pub
root:
  key: root.key
  cert: root.crt
  cn: test root
seal:
  key: seal.key
intermediate:
  cert: int.crt
  sealed_key: int.key.sealed
  ttl: 24h
servers:
  - name: nats
    dns: [nats]
    ips: [127.0.0.1]
workloads:
  - name: agent
    spiffe_uri: spiffe://tokyo3/authd/agent
`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if err := runCmd(caInitEnvCmd(), manifest, "--out-dir", dir, "--force"); err != nil {
		t.Fatalf("init-env: %v", err)
	}

	for _, rel := range []string{
		"certd-signing.key", "certd-signing.key.pub",
		"root.key", "root.crt", "seal.key", "int.crt", "int.key.sealed",
		"nats.crt", "nats.key", "agent.crt", "agent.key",
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("expected %s: %v", rel, err)
		}
	}

	root := loadCertFile(t, filepath.Join(dir, "root.crt"))
	intermediate := loadCertFile(t, filepath.Join(dir, "int.crt"))
	if !root.IsCA || root.MaxPathLen != 1 {
		t.Fatalf("root is not pathlen:1 CA: is_ca=%v pathlen=%d", root.IsCA, root.MaxPathLen)
	}
	if !intermediate.IsCA || !intermediate.MaxPathLenZero {
		t.Fatalf("intermediate is not pathlen:0 CA")
	}

	serverChain := loadCertsFile(t, filepath.Join(dir, "nats.crt"))
	if len(serverChain) != 2 {
		t.Fatalf("server cert file has %d certs, want leaf+intermediate", len(serverChain))
	}
	verifyLeafToRoot(t, serverChain[0], serverChain[1], root, x509.ExtKeyUsageServerAuth)
	if len(serverChain[0].DNSNames) != 1 || serverChain[0].DNSNames[0] != "nats" {
		t.Fatalf("server DNSNames = %v", serverChain[0].DNSNames)
	}

	workloadChain := loadCertsFile(t, filepath.Join(dir, "agent.crt"))
	if len(workloadChain) != 2 {
		t.Fatalf("workload cert file has %d certs, want leaf+intermediate", len(workloadChain))
	}
	verifyLeafToRoot(t, workloadChain[0], workloadChain[1], root, x509.ExtKeyUsageClientAuth)
	if len(workloadChain[0].URIs) != 1 || workloadChain[0].URIs[0].String() != "spiffe://tokyo3/authd/agent" {
		t.Fatalf("workload URIs = %v", workloadChain[0].URIs)
	}

	rootBefore := root.SerialNumber.String()
	if err := runCmd(caInitEnvCmd(), manifest, "--out-dir", dir, "--force"); err != nil {
		t.Fatalf("second init-env: %v", err)
	}
	rootAfter := loadCertFile(t, filepath.Join(dir, "root.crt")).SerialNumber.String()
	if rootAfter != rootBefore {
		t.Fatalf("init-env rotated existing root: before=%s after=%s", rootBefore, rootAfter)
	}
}

func loadCertsFile(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []*x509.Certificate
	for len(raw) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		raw = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		out = append(out, cert)
	}
	return out
}

func verifyLeafToRoot(t *testing.T, leaf, intermediate, root *x509.Certificate, usage x509.ExtKeyUsage) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	inters.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		t.Fatalf("verify leaf chain: %v", err)
	}
}
