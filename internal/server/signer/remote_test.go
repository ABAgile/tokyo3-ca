package signer_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// inMemoryRemoteSignFn returns a [signer.RemoteSignFn] backed by an
// in-process Ed25519 key. Simulates how a real KMS adapter would
// behave: ctx-aware, returns raw signature bytes, never exposes the
// private key to the caller. Useful for testing the abstraction
// without standing up an actual KMS.
func inMemoryRemoteSignFn(priv ed25519.PrivateKey) signer.RemoteSignFn {
	return func(ctx context.Context, digest []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return ed25519.Sign(priv, digest), nil
	}
}

func TestNewRemoteSigner_RequiresFields(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	fn := func(context.Context, []byte) ([]byte, error) { return nil, nil }

	cases := []struct {
		name string
		cfg  signer.RemoteSignerConfig
		want string
	}{
		{"no public key", signer.RemoteSignerConfig{Sign: fn, Description: "x"}, "PublicKey is required"},
		{"no sign fn", signer.RemoteSignerConfig{PublicKey: pub, Description: "x"}, "Sign is required"},
		{"no description", signer.RemoteSignerConfig{PublicKey: pub, Sign: fn}, "Description is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signer.NewRemoteSigner(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRemoteSigner_SignsAndVerifiesEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	s, err := signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey:   pub,
		Sign:        inMemoryRemoteSignFn(priv),
		Description: "in-memory remote ed25519 (test)",
	})
	if err != nil {
		t.Fatalf("NewRemoteSigner: %v", err)
	}

	msg := []byte("the quick brown fox")
	sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature did not verify against the public key")
	}
	if s.Description() != "in-memory remote ed25519 (test)" {
		t.Errorf("Description = %q", s.Description())
	}
	if _, ok := s.Public().(ed25519.PublicKey); !ok {
		t.Errorf("Public() type = %T, want ed25519.PublicKey", s.Public())
	}
}

func TestRemoteSigner_DrivesSSHCertSigning(t *testing.T) {
	// End-to-end: a remote-signer-backed Ed25519 key signs an SSH
	// cert via gossh.NewSignerFromSigner — the same path certd's
	// SSH cert engine uses. The signed cert verifies against the
	// matching public key.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey:   pub,
		Sign:        inMemoryRemoteSignFn(priv),
		Description: "remote ed25519 (ssh)",
	})

	sshSigner, err := gossh.NewSignerFromSigner(s)
	if err != nil {
		t.Fatalf("NewSignerFromSigner: %v", err)
	}

	// Build a cert that the remote signer will sign over.
	_, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userSSH, err := gossh.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	cert := &gossh.Certificate{
		Key:             userSSH.PublicKey(),
		CertType:        gossh.UserCert,
		ValidPrincipals: []string{"alice"},
		ValidAfter:      0,
		ValidBefore:     gossh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, sshSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	// Verify the cert was actually signed by the remote signer's
	// public key.
	caKey, _ := gossh.NewPublicKey(pub)
	if string(cert.SignatureKey.Marshal()) != string(caKey.Marshal()) {
		t.Error("cert.SignatureKey does not match the remote signer's pubkey")
	}

	// CertChecker validation round-trip: the cert must validate as
	// signed by the same CA pubkey.
	checker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return string(auth.Marshal()) == string(caKey.Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Errorf("CheckCert: %v", err)
	}
}

func TestRemoteSigner_DrivesX509CertSigning(t *testing.T) {
	// crypto/x509.CreateCertificate consumes a crypto.Signer. The
	// remote signer satisfies it, so an X.509 cert signed by it
	// verifies against the matching ed25519 public key.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey:   pub,
		Sign:        inMemoryRemoteSignFn(priv),
		Description: "remote ed25519 (x509)",
	})

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, s)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	// Self-verification: cert signed by the remote signer must
	// validate against the same public key.
	if err := parsed.CheckSignatureFrom(parsed); err != nil {
		t.Errorf("CheckSignatureFrom: %v", err)
	}
}

func TestRemoteSigner_PropagatesRemoteError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey: pub,
		Sign: func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("kms.AccessDeniedException")
		},
		Description: "stub",
	})

	_, err := s.Sign(rand.Reader, []byte("x"), crypto.Hash(0))
	if err == nil || !strings.Contains(err.Error(), "kms.AccessDenied") {
		t.Errorf("err = %v, want surfaced remote error", err)
	}
	if !strings.Contains(err.Error(), "remote sign:") {
		t.Errorf("error should be wrapped with remote-sign prefix: %v", err)
	}
}

func TestRemoteSigner_RespectsSignTimeout(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Sign fn blocks longer than SignTimeout, then returns. Sign()
	// must surface the ctx.DeadlineExceeded.
	var called atomic.Int32
	s, _ := signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey: pub,
		Sign: func(ctx context.Context, _ []byte) ([]byte, error) {
			called.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		Description: "slow",
		SignTimeout: 30 * time.Millisecond,
	})

	_, err := s.Sign(rand.Reader, []byte("x"), crypto.Hash(0))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "context") {
		t.Errorf("err = %v, want deadline-style", err)
	}
	if called.Load() != 1 {
		t.Errorf("Sign fn invocations = %d, want 1", called.Load())
	}
}

func TestRemoteSigner_HonorsParentContextCancel(t *testing.T) {
	// Parent ctx cancels before SignTimeout fires — the remote call
	// must observe ctx.Err() = context.Canceled, not DeadlineExceeded.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	parentCtx, cancelParent := context.WithCancel(context.Background())

	signCh := make(chan error, 1)
	s, _ := signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey: pub,
		Sign: func(ctx context.Context, _ []byte) ([]byte, error) {
			<-ctx.Done()
			signCh <- ctx.Err()
			return nil, ctx.Err()
		},
		Description: "parent-ctx",
		Context:     parentCtx,
		SignTimeout: time.Hour,
	})

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancelParent()
	}()
	_, err := s.Sign(rand.Reader, []byte("x"), crypto.Hash(0))
	if err == nil {
		t.Fatal("expected ctx-cancelled error")
	}
	inner := <-signCh
	if !errors.Is(inner, context.Canceled) {
		t.Errorf("inner ctx err = %v, want context.Canceled", inner)
	}
}
