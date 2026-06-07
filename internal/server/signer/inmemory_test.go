package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewEphemeralEd25519_GeneratesUsableKey(t *testing.T) {
	s, err := NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("NewEphemeralEd25519: %v", err)
	}
	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want ed25519.PublicKey", s.Public())
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	msg := []byte("the quick brown fox")
	sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature did not verify against the signer's public key")
	}
}

func TestSign_RejectsNonZeroHash(t *testing.T) {
	s, err := NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("NewEphemeralEd25519: %v", err)
	}
	_, err = s.Sign(rand.Reader, []byte("x"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error when opts.HashFunc != 0, got nil")
	}
	if !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("error %q should mention ed25519", err)
	}
}

func TestEd25519PEM_RoundTrip(t *testing.T) {
	original, err := NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("NewEphemeralEd25519: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.key")
	if err := SaveEd25519ToPEMFile(original, path); err != nil {
		t.Fatalf("SaveEd25519ToPEMFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("PEM file mode = %o, want 0600", mode)
	}

	loaded, err := LoadEd25519FromPEMFile(path)
	if err != nil {
		t.Fatalf("LoadEd25519FromPEMFile: %v", err)
	}

	// Same public key on both ends of the round-trip.
	got := loaded.Public().(ed25519.PublicKey)
	want := original.Public().(ed25519.PublicKey)
	if !got.Equal(want) {
		t.Fatal("loaded signer's public key does not match the original")
	}

	// And signatures from the loaded signer verify against the original
	// public key (and vice versa) — proves we kept the right private half.
	msg := []byte("round-trip")
	sig, err := loaded.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign with loaded: %v", err)
	}
	if !ed25519.Verify(want, msg, sig) {
		t.Fatal("loaded signer's signature did not verify against original public key")
	}

	// Loaded signer's description includes the file path so operators
	// can grep audit logs back to the key source.
	if !strings.Contains(loaded.Description(), path) {
		t.Errorf("Description() = %q; expected to contain path %q", loaded.Description(), path)
	}
}

func TestLoadFromPKCS8PEM_RoundTrip(t *testing.T) {
	type equaler interface{ Equal(crypto.PublicKey) bool }

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}

	// The unsealed intermediate may be ed25519 or ecdsa-p256; both must load.
	cases := []struct {
		name string
		priv crypto.Signer
		pub  crypto.PublicKey
	}{
		{"ed25519", edPriv, edPub},
		{"ecdsa-p256", ecPriv, &ecPriv.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := x509.MarshalPKCS8PrivateKey(tc.priv)
			if err != nil {
				t.Fatalf("marshal pkcs8: %v", err)
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			s, err := LoadFromPKCS8PEM(pemBytes, "test-intermediate")
			if err != nil {
				t.Fatalf("LoadFromPKCS8PEM: %v", err)
			}
			if !s.Public().(equaler).Equal(tc.pub) {
				t.Error("loaded public key does not match the original")
			}
			if s.Description() != "test-intermediate" {
				t.Errorf("Description() = %q, want test-intermediate", s.Description())
			}
		})
	}
}

func TestLoadFromPKCS8PEM_RejectsBadInput(t *testing.T) {
	if _, err := LoadFromPKCS8PEM([]byte("not pem"), ""); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("err = %v, want 'no PEM block'", err)
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("deadbeef")})
	if _, err := LoadFromPKCS8PEM(bad, ""); err == nil || !strings.Contains(err.Error(), "parse pkcs8") {
		t.Errorf("err = %v, want 'parse pkcs8'", err)
	}
}

func TestLoadEd25519FromPEMFile_RejectsBadInput(t *testing.T) {
	tmp := t.TempDir()

	tests := []struct {
		name     string
		contents []byte
		wantMsg  string
	}{
		{"empty file", []byte{}, "no PEM block"},
		{"random bytes", []byte("not a PEM file"), "no PEM block"},
		{"invalid PEM", []byte("-----BEGIN PRIVATE KEY-----\ndeadbeef\n-----END PRIVATE KEY-----\n"), "parse pkcs8"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(tmp, tc.name+".key")
			if err := os.WriteFile(path, tc.contents, 0o600); err != nil {
				t.Fatalf("setup: %v", err)
			}
			_, err := LoadEd25519FromPEMFile(path)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should contain %q", err, tc.wantMsg)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadEd25519FromPEMFile(filepath.Join(tmp, "does-not-exist.key"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
			t.Errorf("error %q should indicate missing file", err)
		}
	})
}

func TestSaveEd25519ToPEMFile_RejectsNonInMemorySigner(t *testing.T) {
	// Construct a fake Signer that doesn't have access to a private key
	// the way the in-memory signer does — SaveEd25519ToPEMFile should
	// refuse to export it.
	fake := stubSigner{}
	err := SaveEd25519ToPEMFile(fake, filepath.Join(t.TempDir(), "x.key"))
	if err == nil {
		t.Fatal("expected error when saving a non-in-memory signer")
	}
	if !strings.Contains(err.Error(), "in-memory") {
		t.Errorf("error %q should mention 'in-memory'", err)
	}
}

type stubSigner struct{}

func (stubSigner) Public() crypto.PublicKey { return nil }
func (stubSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
func (stubSigner) Description() string { return "stub" }
