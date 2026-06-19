// DEV-ONLY local seal binding for the seal seam (seal.go). Wraps the
// intermediate CA private key with AES-256-GCM under a 32-byte key read from a
// local file, registered under the "file" scheme — so CERTD_CA_SEAL_KEY (or
// --seal-key) of the form "file:/path/to/key" selects it. It lets the docker
// rig exercise the two-tier hierarchy without KMS.
//
// This is NOT real at-rest protection: the AES key sits next to the ciphertext
// on the same host, so anyone who can read the sealed key can read the AES key.
// It is compiled into every build (no build tag) — the explicit "file:" scheme
// is the opt-in, and every selection logs a loud warning. Production must use a
// KMS seal key (the bare/"aws:" scheme), where the symmetric key never leaves
// the HSM.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

func init() {
	RegisterSealerFactory("file", func(_ context.Context, keyRef string) (sealer, error) {
		key, err := os.ReadFile(keyRef)
		if err != nil {
			return nil, fmt.Errorf("read local seal key %s: %w", keyRef, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("local seal key %s: want 32 bytes (AES-256), got %d", keyRef, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		slog.Default().Warn("DEV-ONLY local file seal in use — the intermediate CA key is protected only by a co-located AES key; NEVER use this in production, use a KMS seal key instead",
			"seal_key", keyRef)
		return &localSealer{gcm: gcm}, nil
	})
}

// localSealer seals/unseals with AES-256-GCM. The output is nonce‖ciphertext;
// the random nonce makes Encrypt non-deterministic and GCM authenticates the
// blob, so a tampered or wrong-key ciphertext fails Decrypt closed.
type localSealer struct{ gcm cipher.AEAD }

func (s *localSealer) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *localSealer) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	ns := s.gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("sealed blob too short")
	}
	return s.gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}
