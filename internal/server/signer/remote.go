package signer

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"time"
)

// RemoteSignFn signs digest using a service the operator owns —
// typically AWS KMS, GCP KMS, HashiCorp Vault, or a hardware HSM.
// The ctx + timeout pair lets callers cap an in-flight remote call;
// concrete adapters route the digest through their cloud SDK's
// Sign API and return the raw signature bytes.
//
// digest is whatever the [Signer] caller passed — for Ed25519 this
// is the full message (Sign hashes internally); for ECDSA / RSA it
// is the pre-hashed digest.
type RemoteSignFn func(ctx context.Context, digest []byte) ([]byte, error)

// RemoteSignerConfig wires a [Signer] backed by an external signing
// service.
type RemoteSignerConfig struct {
	// PublicKey is the cached public key. Adapters fetch this from
	// the remote service once at startup (KMS GetPublicKey, etc.)
	// and pass it here. Required.
	PublicKey crypto.PublicKey

	// Sign delegates each signature operation to the remote service.
	// Required.
	Sign RemoteSignFn

	// Description is the human-readable identifier surfaced in audit
	// events and the portal (e.g., "AWS KMS arn:aws:kms:..."). Safe
	// to log; MUST NOT contain secret material. Required.
	Description string

	// SignTimeout caps each remote Sign call. 0 ⇒
	// DefaultRemoteSignTimeout — chosen so a slow KMS call doesn't
	// strand the cert request indefinitely while still tolerating
	// cold-start latencies.
	SignTimeout time.Duration

	// Context is the parent context used when Sign() is invoked.
	// Typically [context.Background] — Sign() in [crypto.Signer]
	// doesn't accept a ctx, so the adapter derives one from this
	// plus the SignTimeout. nil ⇒ context.Background.
	Context context.Context
}

// DefaultRemoteSignTimeout matches what a healthy KMS call clears
// even on the largest cloud regions. Operators set a smaller value
// when their cert-issuance SLO is tight.
const DefaultRemoteSignTimeout = 5 * time.Second

// NewRemoteSigner adapts cfg into a [Signer]. Concrete cloud-SDK
// adapters live in deployment code — this package ships only the
// abstraction so callers can plug in any remote signing surface
// (AWS KMS Sign, GCP KMS AsymmetricSign, Vault Transit /sign,
// hardware HSM API) without changing certd's core.
//
// The returned signer's Sign call is synchronous: the caller blocks
// on the remote call. This matches certd's existing in-process
// signer semantics — issuance is sync everywhere; the only thing
// that changes is the underlying primitive.
func NewRemoteSigner(cfg RemoteSignerConfig) (Signer, error) {
	if cfg.PublicKey == nil {
		return nil, errors.New("PublicKey is required")
	}
	if cfg.Sign == nil {
		return nil, errors.New("Sign is required")
	}
	if cfg.Description == "" {
		return nil, errors.New("Description is required")
	}
	if cfg.SignTimeout == 0 {
		cfg.SignTimeout = DefaultRemoteSignTimeout
	}
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
	return &remoteSigner{cfg: cfg}, nil
}

// remoteSigner is the [Signer] implementation backing
// [NewRemoteSigner].
type remoteSigner struct {
	cfg RemoteSignerConfig
}

// Public satisfies [crypto.Signer]. Returns the cached public key
// — no remote round-trip.
func (s *remoteSigner) Public() crypto.PublicKey { return s.cfg.PublicKey }

// Sign satisfies [crypto.Signer]. Delegates to the configured
// [RemoteSignFn] under a ctx bounded by [Config.SignTimeout].
// The io.Reader rand is ignored — remote signers source entropy on
// their own side. opts is passed through implicitly by the caller's
// digest (for ECDSA / RSA the caller pre-hashes; for Ed25519 opts
// must be the zero hash).
func (s *remoteSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	ctx, cancel := context.WithTimeout(s.cfg.Context, s.cfg.SignTimeout)
	defer cancel()
	sig, err := s.cfg.Sign(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("remote sign: %w", err)
	}
	return sig, nil
}

// Description satisfies [Signer].
func (s *remoteSigner) Description() string { return s.cfg.Description }
