package sshengine_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/sshengine"
)

// makeCA returns a fresh in-memory CA signer and the corresponding
// ssh.PublicKey for verifier setup.
func makeCA(t *testing.T) (signer.Signer, ssh.PublicKey) {
	t.Helper()
	ca, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("new CA signer: %v", err)
	}
	caPub, err := ssh.NewPublicKey(ca.Public())
	if err != nil {
		t.Fatalf("wrap CA public key: %v", err)
	}
	return ca, caPub
}

// makeSubjectKey returns a fresh Ed25519 ssh.PublicKey to act as the
// cert subject (the "user" or "host" the cert is issued to).
func makeSubjectKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate subject key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("wrap subject public key: %v", err)
	}
	return pub
}

func TestSignUserCert_RoundTrip(t *testing.T) {
	ca, caPub := makeCA(t)
	subject := makeSubjectKey(t)

	now := time.Now().UTC()
	cert, err := sshengine.SignUserCert(rand.Reader, ca, sshengine.UserCertParams{
		PublicKey:  subject,
		KeyID:      "user:alice@example.com",
		Principals: []string{"alice", "deploy"},
		Extensions: map[string]string{
			"permit-pty":              "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
		},
		CriticalOptions: map[string]string{
			"source-address": "10.0.0.0/8",
		},
		ValidAfter:  now,
		ValidBefore: now.Add(1 * time.Hour),
		Serial:      42,
	})
	if err != nil {
		t.Fatalf("SignUserCert: %v", err)
	}

	// Cert fields populated as expected.
	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want UserCert (%d)", cert.CertType, ssh.UserCert)
	}
	if cert.KeyId != "user:alice@example.com" {
		t.Errorf("KeyId = %q, want %q", cert.KeyId, "user:alice@example.com")
	}
	if cert.Serial != 42 {
		t.Errorf("Serial = %d, want 42", cert.Serial)
	}
	if got, want := cert.ValidPrincipals, []string{"alice", "deploy"}; !equalStrSlice(got, want) {
		t.Errorf("ValidPrincipals = %v, want %v", got, want)
	}
	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Error("expected permit-pty in Extensions")
	}
	if cert.Permissions.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("source-address option missing or wrong: %v", cert.Permissions.CriticalOptions)
	}

	// SignatureKey is the CA's public key (so verifiers know which CA
	// to trust).
	if !sshKeysEqual(cert.SignatureKey, caPub) {
		t.Error("cert.SignatureKey does not match the CA's public key")
	}

	// A CertChecker configured to trust this CA should accept the cert
	// for one of the listed principals.
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return sshKeysEqual(auth, caPub)
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Errorf("CertChecker.CheckCert(alice): %v", err)
	}
	// And reject a principal not in the list.
	if err := checker.CheckCert("mallory", cert); err == nil {
		t.Error("CertChecker.CheckCert(mallory) accepted unauthorized principal")
	}
}

func TestSignHostCert_RoundTrip(t *testing.T) {
	ca, caPub := makeCA(t)
	subject := makeSubjectKey(t)

	now := time.Now().UTC()
	cert, err := sshengine.SignHostCert(rand.Reader, ca, sshengine.HostCertParams{
		PublicKey:   subject,
		KeyID:       "host:db-1.prod.internal",
		Principals:  []string{"db-1.prod.internal", "db-1"},
		ValidAfter:  now,
		ValidBefore: now.Add(7 * 24 * time.Hour),
		Serial:      1001,
	})
	if err != nil {
		t.Fatalf("SignHostCert: %v", err)
	}

	if cert.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want HostCert (%d)", cert.CertType, ssh.HostCert)
	}
	if !sshKeysEqual(cert.SignatureKey, caPub) {
		t.Error("cert.SignatureKey does not match the CA's public key")
	}

	// CertChecker.CheckHostKey is the symmetric host-side validation
	// path. It returns an error type that wraps the principal mismatch
	// or expiry — for happy path on a valid cert with one of its
	// principals it must succeed.
	checker := ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return sshKeysEqual(auth, caPub)
		},
	}
	if err := checker.CheckHostKey("db-1.prod.internal:22", &fakeAddr{"db-1.prod.internal:22"}, cert); err != nil {
		t.Errorf("CheckHostKey(db-1.prod.internal): %v", err)
	}
	if err := checker.CheckHostKey("other.host:22", &fakeAddr{"other.host:22"}, cert); err == nil {
		t.Error("CheckHostKey accepted cert for an unlisted principal")
	}
}

func TestSignUserCert_ExpiredCertRejected(t *testing.T) {
	ca, caPub := makeCA(t)
	subject := makeSubjectKey(t)

	past := time.Now().UTC().Add(-2 * time.Hour)
	cert, err := sshengine.SignUserCert(rand.Reader, ca, sshengine.UserCertParams{
		PublicKey:   subject,
		KeyID:       "user:alice",
		Principals:  []string{"alice"},
		ValidAfter:  past,
		ValidBefore: past.Add(1 * time.Hour), // expired an hour ago
		Serial:      1,
	})
	if err != nil {
		t.Fatalf("SignUserCert: %v", err)
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return sshKeysEqual(auth, caPub)
		},
	}
	if err := checker.CheckCert("alice", cert); err == nil {
		t.Error("CheckCert accepted an expired cert")
	} else if !strings.Contains(err.Error(), "expire") {
		t.Errorf("expected an expiry-related error, got %v", err)
	}
}

func TestSignUserCert_ValidationErrors(t *testing.T) {
	ca, _ := makeCA(t)
	subject := makeSubjectKey(t)
	now := time.Now().UTC()

	tests := []struct {
		name    string
		params  sshengine.UserCertParams
		wantMsg string
	}{
		{
			name: "nil public key",
			params: sshengine.UserCertParams{
				KeyID:       "k",
				Principals:  []string{"alice"},
				ValidAfter:  now,
				ValidBefore: now.Add(time.Hour),
			},
			wantMsg: "public key is required",
		},
		{
			name: "missing KeyID",
			params: sshengine.UserCertParams{
				PublicKey:   subject,
				Principals:  []string{"alice"},
				ValidAfter:  now,
				ValidBefore: now.Add(time.Hour),
			},
			wantMsg: "key id is required",
		},
		{
			name: "empty principals",
			params: sshengine.UserCertParams{
				PublicKey:   subject,
				KeyID:       "k",
				ValidAfter:  now,
				ValidBefore: now.Add(time.Hour),
			},
			wantMsg: "principals must contain",
		},
		{
			name: "ValidAfter zero",
			params: sshengine.UserCertParams{
				PublicKey:   subject,
				KeyID:       "k",
				Principals:  []string{"alice"},
				ValidBefore: now.Add(time.Hour),
			},
			wantMsg: "valid-after is required",
		},
		{
			name: "ValidBefore equal to ValidAfter",
			params: sshengine.UserCertParams{
				PublicKey:   subject,
				KeyID:       "k",
				Principals:  []string{"alice"},
				ValidAfter:  now,
				ValidBefore: now,
			},
			wantMsg: "must be after",
		},
		{
			name: "ValidBefore before ValidAfter",
			params: sshengine.UserCertParams{
				PublicKey:   subject,
				KeyID:       "k",
				Principals:  []string{"alice"},
				ValidAfter:  now,
				ValidBefore: now.Add(-time.Hour),
			},
			wantMsg: "must be after",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sshengine.SignUserCert(rand.Reader, ca, tc.params)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should contain %q", err, tc.wantMsg)
			}
		})
	}
}

func TestSignHostCert_ValidationErrors(t *testing.T) {
	ca, _ := makeCA(t)
	subject := makeSubjectKey(t)

	_, err := sshengine.SignHostCert(rand.Reader, ca, sshengine.HostCertParams{
		PublicKey:  subject,
		KeyID:      "host:db-1",
		Principals: nil, // empty
	})
	if err == nil {
		t.Fatal("expected error for empty principals")
	}
	if !strings.Contains(err.Error(), "principals") {
		t.Errorf("error %q should mention principals", err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func sshKeysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return string(a.Marshal()) == string(b.Marshal())
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fakeAddr lets us hand CertChecker.CheckHostKey a net.Addr without
// dragging in real network setup.
type fakeAddr struct{ s string }

func (a *fakeAddr) Network() string { return "tcp" }
func (a *fakeAddr) String() string  { return a.s }
