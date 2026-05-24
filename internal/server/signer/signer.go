// Package signer abstracts CA key custody. Implementations:
//
//   - InMemorySigner: holds an Ed25519 private key in process memory.
//     Generated at startup or loaded from a PEM file. Suitable for
//     development. Production deployments should swap to a KMS-backed
//     signer (deferred to a later phase).
//
// All implementations satisfy [crypto.Signer], so the same value drives
// both X.509 issuance ([crypto/x509.CreateCertificate]) and SSH cert
// signing (via [golang.org/x/crypto/ssh.NewSignerFromSigner]).
package signer

import "crypto"

// Signer is the CA's signing primitive. Embeds [crypto.Signer]; adds a
// human-readable description used in audit events and the admin portal
// so operators can tell at a glance where the key lives.
type Signer interface {
	crypto.Signer
	// Description returns a short identifier (e.g., "in-memory ed25519"
	// or "AWS KMS arn:aws:kms:..."). Safe to log; MUST NOT contain
	// secret material.
	Description() string
}
