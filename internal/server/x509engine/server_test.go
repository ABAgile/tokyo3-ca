package x509engine_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

func TestSignServerCert(t *testing.T) {
	caSig, caCert := makeCA(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	serial, err := x509engine.RandomSerial(rand.Reader)
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	now := time.Now()
	cert, err := x509engine.SignServerCert(rand.Reader, caSig, caCert, x509engine.ServerCertParams{
		PublicKey:   pub,
		DNSNames:    []string{"nats", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ValidAfter:  now,
		ValidBefore: now.Add(time.Hour),
		Serial:      serial,
	})
	if err != nil {
		t.Fatalf("SignServerCert: %v", err)
	}

	if len(cert.DNSNames) != 2 || cert.DNSNames[0] != "nats" {
		t.Errorf("DNSNames = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v", cert.IPAddresses)
	}
	if cert.Subject.CommonName != "nats" {
		t.Errorf("CN = %q, want nats (first DNS)", cert.Subject.CommonName)
	}
	var serverAuth bool
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Error("missing serverAuth EKU")
	}

	// Chains to the CA and verifies for the server hostname.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "nats", Roots: pool}); err != nil {
		t.Errorf("hostname verify (nats): %v", err)
	}
}

func TestSignServerCert_RequiresSAN(t *testing.T) {
	caSig, caCert := makeCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	serial, _ := x509engine.RandomSerial(rand.Reader)
	now := time.Now()
	_, err := x509engine.SignServerCert(rand.Reader, caSig, caCert, x509engine.ServerCertParams{
		PublicKey:   pub,
		ValidAfter:  now,
		ValidBefore: now.Add(time.Hour),
		Serial:      serial,
	})
	if err == nil {
		t.Fatal("expected error when no DNS/IP SAN is given")
	}
}
