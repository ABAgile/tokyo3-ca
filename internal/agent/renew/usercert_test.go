package renew_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/agent/renew"
	"github.com/abagile/tokyo3-ca/internal/client"
)

// stubUserSigner is the [renew.UserSigner] test double.
type stubUserSigner struct {
	mu     sync.Mutex
	calls  atomic.Int32
	gotReq client.SignUserRequest
	respFn func(client.SignUserRequest) (*client.SignUserResponse, error)
}

func (s *stubUserSigner) SignUserCert(_ context.Context, req client.SignUserRequest) (*client.SignUserResponse, error) {
	s.mu.Lock()
	s.calls.Add(1)
	s.gotReq = req
	fn := s.respFn
	s.mu.Unlock()
	if fn == nil {
		now := time.Now().UTC()
		return &client.SignUserResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA-stub",
			Serial:      1,
			KeyID:       req.KeyID,
			Principals:  req.Principals,
			ValidAfter:  now,
			ValidBefore: now.Add(time.Hour),
		}, nil
	}
	return fn(req)
}

func TestNewUserCertRenewer_RejectsMissingConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  renew.UserCertConfig
		want string
	}{
		{"no signer", renew.UserCertConfig{KeyID: "k", Principals: []string{"p"}, CertOutputPath: "/c", KeyOutputPath: "/k"}, "signer is required"},
		{"no key id", renew.UserCertConfig{Signer: &stubUserSigner{}, Principals: []string{"p"}, CertOutputPath: "/c", KeyOutputPath: "/k"}, "KeyID is required"},
		{"no principals", renew.UserCertConfig{Signer: &stubUserSigner{}, KeyID: "k", CertOutputPath: "/c", KeyOutputPath: "/k"}, "Principal is required"},
		{"no cert path", renew.UserCertConfig{Signer: &stubUserSigner{}, KeyID: "k", Principals: []string{"p"}, KeyOutputPath: "/k"}, "CertOutputPath is required"},
		{"no key path", renew.UserCertConfig{Signer: &stubUserSigner{}, KeyID: "k", Principals: []string{"p"}, CertOutputPath: "/c"}, "KeyOutputPath is required"},
		{"bad renew fraction", renew.UserCertConfig{Signer: &stubUserSigner{}, KeyID: "k", Principals: []string{"p"}, CertOutputPath: "/c", KeyOutputPath: "/k", RenewFraction: 1.5}, "RenewFraction must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renew.NewUserCertRenewer(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestUserCertRenewer_SignOnce_GeneratesKeyAndWritesCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "user-cert.pub")
	keyPath := filepath.Join(dir, "user-key")

	signer := &stubUserSigner{}
	r, err := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer:         signer,
		KeyID:          "user:cert-agentd-dev",
		Principals:     []string{"alice", "deployer"},
		CertOutputPath: certPath,
		KeyOutputPath:  keyPath,
		RequestedTTL:   time.Hour,
		Extensions:     map[string]string{"permit-pty": ""},
	})
	if err != nil {
		t.Fatalf("NewUserCertRenewer: %v", err)
	}

	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("SignOnce: %v", err)
	}

	certBody, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !strings.HasPrefix(string(certBody), "ssh-ed25519-cert-v01@openssh.com") {
		t.Errorf("cert body = %q", string(certBody))
	}
	if !strings.HasSuffix(string(certBody), "\n") {
		t.Errorf("cert file should end with newline; got %q", string(certBody))
	}

	// Key file is 0600.
	info, _ := os.Stat(keyPath)
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key file mode = %o, want 0600", mode)
	}
	// Cert file is 0644.
	info, _ = os.Stat(certPath)
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("cert file mode = %o, want 0644", mode)
	}

	// Key on disk is a valid SSH ed25519 private key.
	keyBytes, _ := os.ReadFile(keyPath)
	if _, err := gossh.ParsePrivateKey(keyBytes); err != nil {
		t.Errorf("parse key from disk: %v", err)
	}

	// Public key shipped to certd is the matching ed25519 authorized_keys line.
	if pub := signer.gotReq.PublicKey; !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("pub key on the wire = %q", pub)
	}
	if signer.gotReq.KeyID != "user:cert-agentd-dev" {
		t.Errorf("KeyID = %q", signer.gotReq.KeyID)
	}
	if got := signer.gotReq.Principals; len(got) != 2 || got[0] != "alice" {
		t.Errorf("Principals = %v", got)
	}
	if signer.gotReq.TTLSeconds != 3600 {
		t.Errorf("TTLSeconds = %d", signer.gotReq.TTLSeconds)
	}
	if _, ok := signer.gotReq.Extensions["permit-pty"]; !ok {
		t.Errorf("Extensions missing permit-pty: %v", signer.gotReq.Extensions)
	}
}

func TestUserCertRenewer_SignOnce_ReusesExistingKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "u-cert.pub")
	keyPath := filepath.Join(dir, "u-key")

	signer := &stubUserSigner{}
	r, _ := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer:         signer,
		KeyID:          "k",
		Principals:     []string{"alice"},
		CertOutputPath: certPath,
		KeyOutputPath:  keyPath,
	})
	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("first SignOnce: %v", err)
	}
	prevPub := signer.gotReq.PublicKey
	keyBefore, _ := os.ReadFile(keyPath)

	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("second SignOnce: %v", err)
	}
	if signer.gotReq.PublicKey != prevPub {
		t.Error("SSH public key changed between renewals (key should be stable)")
	}
	keyAfter, _ := os.ReadFile(keyPath)
	if string(keyBefore) != string(keyAfter) {
		t.Error("key file rewritten on second renewal")
	}
}

func TestUserCertRenewer_SignOnce_LoadsExistingKeyFromDisk(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "u-cert.pub")
	keyPath := filepath.Join(dir, "u-key")

	r1, _ := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer:         &stubUserSigner{},
		KeyID:          "k",
		Principals:     []string{"a"},
		CertOutputPath: certPath,
		KeyOutputPath:  keyPath,
	})
	if _, _, err := r1.SignOnce(context.Background()); err != nil {
		t.Fatalf("seed SignOnce: %v", err)
	}
	keyBefore, _ := os.ReadFile(keyPath)

	// Fresh instance — must read keyBefore from disk.
	signer2 := &stubUserSigner{}
	r2, _ := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer: signer2, KeyID: "k", Principals: []string{"a"},
		CertOutputPath: certPath, KeyOutputPath: keyPath,
	})
	if _, _, err := r2.SignOnce(context.Background()); err != nil {
		t.Fatalf("second-instance SignOnce: %v", err)
	}
	keyAfter, _ := os.ReadFile(keyPath)
	if string(keyBefore) != string(keyAfter) {
		t.Error("key file changed when a second instance picked it up")
	}
}

func TestUserCertRenewer_SignOnce_PropagatesSignerError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c")
	keyPath := filepath.Join(dir, "k")

	signer := &stubUserSigner{respFn: func(_ client.SignUserRequest) (*client.SignUserResponse, error) {
		return nil, errors.New("certd 403")
	}}
	r, _ := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer: signer, KeyID: "k", Principals: []string{"a"},
		CertOutputPath: certPath, KeyOutputPath: keyPath,
	})
	_, _, err := r.SignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "certd 403") {
		t.Errorf("err = %v", err)
	}
	if _, statErr := os.Stat(certPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("cert file exists after failed sign: %v", statErr)
	}
}

func TestUserCertRenewer_SignOnce_AppendsTrailingNewline(t *testing.T) {
	// authorized_keys-format files conventionally end with a newline.
	// The renewer must add one when certd returns a cert without it
	// (some implementations strip it).
	dir := t.TempDir()
	signer := &stubUserSigner{respFn: func(_ client.SignUserRequest) (*client.SignUserResponse, error) {
		return &client.SignUserResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA-no-newline",
			Serial:      1,
			ValidAfter:  time.Now().UTC(),
			ValidBefore: time.Now().UTC().Add(time.Hour),
		}, nil
	}}
	certPath := filepath.Join(dir, "c")
	r, _ := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer: signer, KeyID: "k", Principals: []string{"a"},
		CertOutputPath: certPath, KeyOutputPath: filepath.Join(dir, "k"),
	})
	if _, _, err := r.SignOnce(context.Background()); err != nil {
		t.Fatalf("SignOnce: %v", err)
	}
	body, _ := os.ReadFile(certPath)
	if !strings.HasSuffix(string(body), "\n") {
		t.Errorf("cert body should end with newline: %q", string(body))
	}
}

func TestUserCertRenewer_Run_LoopsAndRenews(t *testing.T) {
	dir := t.TempDir()
	signer := &stubUserSigner{respFn: func(_ client.SignUserRequest) (*client.SignUserResponse, error) {
		now := time.Now().UTC()
		return &client.SignUserResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA-loop",
			ValidAfter:  now,
			ValidBefore: now.Add(time.Millisecond),
		}, nil
	}}
	r, _ := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer: signer, KeyID: "k", Principals: []string{"a"},
		CertOutputPath:   filepath.Join(dir, "c"),
		KeyOutputPath:    filepath.Join(dir, "k"),
		MinRenewInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	if got := signer.calls.Load(); got < 2 {
		t.Errorf("calls = %d, want at least 2 (initial + at least one renew)", got)
	}
}
