// Package kms adapts a remote KMS / HSM signing service into certd's
// [signer.Signer]. It is intentionally SDK-free: the cloud-specific
// glue is a small [Client] the operator's deployment build satisfies
// with the real SDK (AWS KMS, GCP KMS, Vault Transit, PKCS#11 HSM).
// All the fiddly parts — fetching + parsing the public key, choosing
// the signing algorithm and message type from the key type, wiring the
// [signer.NewRemoteSigner] timeout/ctx plumbing — live here and are
// unit-tested with a fake client, so the binding stays mechanical.
//
// See the package example in doc.go for the AWS KMS binding.
package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// Algorithm names the signing algorithm the [Client] must use. The
// string values match AWS KMS SigningAlgorithmSpec verbatim so an AWS
// binding is `types.SigningAlgorithmSpec(string(alg))` with no mapping
// table; other backends translate as needed.
type Algorithm string

const (
	ECDSAP256      Algorithm = "ECDSA_SHA_256"
	ECDSAP384      Algorithm = "ECDSA_SHA_384"
	RSAPKCS1SHA256 Algorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	// Ed25519 (pure EdDSA over the raw TBS, which is what crypto/x509
	// emits). AWS KMS offers this as the ED25519_SHA_512 algorithm on
	// ECC_NIST_EDWARDS25519 keys with MessageType=RAW (since 2025-11);
	// Vault Transit supports it too. GCP KMS does not.
	Ed25519 Algorithm = "ED25519_SHA_512"
)

// Client is the minimal KMS surface the adapter needs. Deployment code
// satisfies it with a real SDK; the core pulls no cloud dependency.
type Client interface {
	// PublicKey returns the CA key's DER-encoded SubjectPublicKeyInfo
	// (the bytes AWS KMS GetPublicKey / GCP KMS GetPublicKey return).
	// Called once at construction; the result is cached.
	PublicKey(ctx context.Context) ([]byte, error)

	// Sign returns the signature over message using alg. When prehashed
	// is true, message is a digest (ECDSA / RSA — AWS MessageType=DIGEST);
	// when false, message is the raw message (Ed25519 — MessageType=RAW).
	// The signature MUST be in the encoding crypto/x509 verifies against:
	// ASN.1 DER (r,s) for ECDSA, PKCS#1 v1.5 for RSA, the 64-byte value
	// for Ed25519 — which is exactly what these KMS Sign APIs return.
	Sign(ctx context.Context, message []byte, alg Algorithm, prehashed bool) ([]byte, error)
}

// New fetches the public key once, derives the signing algorithm from
// its type, and returns a [signer.Signer] that delegates each signature
// to client. signTimeout caps each remote Sign call (0 ⇒
// [signer.DefaultRemoteSignTimeout]). description is surfaced in audit
// events + the portal (e.g. "AWS KMS arn:aws:kms:...").
func New(ctx context.Context, client Client, description string, signTimeout time.Duration) (signer.Signer, error) {
	if client == nil {
		return nil, errors.New("kms: client is required")
	}
	if description == "" {
		return nil, errors.New("kms: description is required")
	}
	der, err := client.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms: fetch public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("kms: parse public key: %w", err)
	}
	alg, prehashed, err := algorithmFor(pub)
	if err != nil {
		return nil, err
	}
	return signer.NewRemoteSigner(signer.RemoteSignerConfig{
		PublicKey:   pub,
		Description: description,
		SignTimeout: signTimeout,
		// Context left nil ⇒ context.Background: the signer outlives the
		// construction ctx (serve issues for the process lifetime). The
		// per-call timeout still bounds each Sign.
		Sign: func(sctx context.Context, message []byte) ([]byte, error) {
			return client.Sign(sctx, message, alg, prehashed)
		},
	})
}

// algorithmFor maps a CA public key to the KMS signing algorithm and
// whether the message handed to Sign is pre-hashed. ECDSA pairs with
// SHA-256/384 per curve (what crypto/x509 picks); RSA defaults to
// PKCS#1 v1.5 SHA-256; Ed25519 signs the raw message.
func algorithmFor(pub crypto.PublicKey) (alg Algorithm, prehashed bool, err error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return ECDSAP256, true, nil
		case elliptic.P384():
			return ECDSAP384, true, nil
		default:
			return "", false, fmt.Errorf("kms: unsupported ECDSA curve %q (want P-256 or P-384)", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return "", false, fmt.Errorf("kms: RSA key too small (%d bits; want >= 2048)", k.N.BitLen())
		}
		return RSAPKCS1SHA256, true, nil
	case ed25519.PublicKey:
		return Ed25519, false, nil
	default:
		return "", false, fmt.Errorf("kms: unsupported public key type %T", pub)
	}
}
