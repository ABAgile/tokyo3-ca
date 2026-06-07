package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// inMemory holds an Ed25519 private key in process memory. Created via
// [NewEphemeralEd25519] or [LoadEd25519FromPEMFile].
type inMemory struct {
	priv  ed25519.PrivateKey
	descr string
}

// NewEphemeralEd25519 generates a fresh Ed25519 keypair and returns it
// as a [Signer]. The key is lost on process exit — intended for
// short-lived dev/test instances where issued certs are also disposable.
func NewEphemeralEd25519() (Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &inMemory{priv: priv, descr: "in-memory ed25519 (ephemeral)"}, nil
}

// LoadEd25519FromPEMFile reads a PKCS#8-encoded Ed25519 private key from
// path and returns a [Signer] backed by it. Errors if the file is
// missing, not PEM, not PKCS#8, or holds a non-Ed25519 key.
//
// Generate a matching key with [SaveEd25519ToPEMFile] or via:
//
//	openssl genpkey -algorithm ed25519 -out ca.key
func LoadEd25519FromPEMFile(path string) (Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	s, err := parseEd25519PEM(b)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s.(*inMemory).descr = fmt.Sprintf("in-memory ed25519 (file: %s)", path)
	return s, nil
}

// SaveEd25519ToPEMFile writes the signer's private key as a PEM-encoded
// PKCS#8 block at path with mode 0600. Only valid for in-memory signers
// backed by Ed25519; KMS-backed signers cannot export their private key
// and will error.
func SaveEd25519ToPEMFile(s Signer, path string) error {
	im, ok := s.(*inMemory)
	if !ok {
		return errors.New("signer is not an in-memory ed25519 key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(im.priv)
	if err != nil {
		return fmt.Errorf("marshal pkcs8: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// parseEd25519PEM decodes the first PEM block of b and returns an
// in-memory signer backed by the contained Ed25519 key.
func parseEd25519PEM(b []byte) (Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519.PrivateKey, got %T", key)
	}
	return &inMemory{priv: priv, descr: "in-memory ed25519"}, nil
}

// genericInMemory wraps any PKCS#8-loaded [crypto.Signer] (Ed25519, ECDSA, or
// RSA) held in process memory. Used for the unsealed intermediate CA key, whose
// algorithm matches whatever the issuing ceremony generated. The embedded
// signer's own Sign already satisfies how [crypto/x509.CreateCertificate] calls
// it (raw message for Ed25519, pre-hashed digest for ECDSA/RSA), so no special
// handling is needed here.
type genericInMemory struct {
	crypto.Signer
	descr string
}

// Description satisfies [Signer]. Identifies key location; safe to log.
func (g genericInMemory) Description() string { return g.descr }

// LoadFromPKCS8PEM decodes the first PEM block of b as a PKCS#8 private key and
// returns an in-memory [Signer] backed by it. Unlike [LoadEd25519FromPEMFile]
// it accepts any signing key type (Ed25519, ECDSA, RSA) — the unsealed
// intermediate may be ed25519 or ecdsa-p256. descr is the human-readable
// key-location string surfaced in audit/portal; a default is used when empty.
func LoadFromPKCS8PEM(b []byte, descr string) (Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	cs, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T is not a crypto.Signer", key)
	}
	if descr == "" {
		descr = "in-memory (pkcs8)"
	}
	return genericInMemory{Signer: cs, descr: descr}, nil
}

// Public satisfies [crypto.Signer]. Returns the Ed25519 public key.
func (s *inMemory) Public() crypto.PublicKey { return s.priv.Public() }

// Sign satisfies [crypto.Signer]. For Ed25519, opts must be the zero
// value of [crypto.Hash] (the algorithm hashes internally); rand is
// ignored. digest is the raw message to sign, not a pre-hash.
func (s *inMemory) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("ed25519 requires opts.HashFunc == 0, got %v", opts.HashFunc())
	}
	return ed25519.Sign(s.priv, digest), nil
}

// Description satisfies [Signer]. Identifies key location; safe to log.
func (s *inMemory) Description() string { return s.descr }
