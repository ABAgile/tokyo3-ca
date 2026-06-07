// Package renew is cert-agentd's renewal scheduler. Owns the
// workload's private key, requests fresh X.509 certs from certd at
// ~60% of TTL, retries at a fixed interval ([DefaultRetryBackoff],
// 30s) on failure, and writes credentials atomically to the
// configured output paths so the consumer's TLS stack picks them up
// without restart.
//
// The renewer is split into two surfaces: [Renewer.SignOnce] performs
// exactly one round-trip + write — useful for the initial bootstrap
// and for tests — and [Renewer.Run] is the long-lived loop that
// re-signs when the cert reaches its renewal fraction.
package renew

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/abagile/tokyo3-ca/internal/agent/output"
	"github.com/abagile/tokyo3-ca/internal/client"
)

// Signer is the subset of [client.Client] [Renewer] needs. Defined
// here so tests can stub the network round-trip without spinning up
// an httptest server.
type Signer interface {
	SignWorkloadCert(ctx context.Context, req client.SignWorkloadRequest) (*client.SignWorkloadResponse, error)
	// AdoptCert acks that the just-issued cert is durably persisted, letting
	// certd's guard collapse the one-step grace for this identity.
	AdoptCert(ctx context.Context, spiffeURI, serial string) (bool, error)
}

// KeyType selects the algorithm for a workload's locally-generated
// private key. The zero value ("") defaults to ECDSA P-256.
type KeyType string

const (
	KeyECDSAP256 KeyType = "ecdsa-p256"
	KeyEd25519   KeyType = "ed25519"
)

// Config wires a [Renewer]. Required fields are validated at
// [New] time; optional knobs default to production-sensible values.
type Config struct {
	// Signer is the certd client. Required.
	Signer Signer

	// SPIFFEURI is the URI SAN to embed in the cert. Required.
	// Convention: "spiffe://<trust-domain>/<workload-path>" — certd's
	// role table decides whether the caller may obtain it.
	SPIFFEURI string

	// SubjectCommonName is optional. Modern verifiers ignore CN as
	// identity; populating it makes tooling output friendlier.
	SubjectCommonName string

	// KeyType selects the locally-generated private key's algorithm:
	// "ecdsa-p256" or "ed25519". Empty ⇒ ecdsa-p256.
	KeyType KeyType

	// RotateKey, when true, mints a FRESH private key on every renewal
	// (a new key+cert each cycle, written together as a bundle) instead
	// of reusing one stable key. Default false keeps the key stable —
	// which is what file-reading server consumers that can't verify a
	// cert/key pair on reload (e.g. Postgres) want, since then only the
	// cert changes. Enable per-workload only where the consumer tolerates
	// a rotating pair (a verifying/reloading loader, or a
	// reload-after-write hook on OnRenewed).
	RotateKey bool

	// Groups are the caller's group memberships sent on each sign
	// request for certd's body-groups policy path (dev/test). Ignored
	// by certd when it authenticates via OIDC or mTLS principals.
	Groups []string

	// CertOutputPath is where the renewed cert PEM is written
	// atomically. Required.
	CertOutputPath string

	// KeyOutputPath is where the matching private key PEM is written
	// atomically on first renewal (and re-used afterwards). Required.
	// The agent owns this key — it is generated locally and never
	// transmitted to certd.
	KeyOutputPath string

	// RequestedTTL is the validity window asked of certd. Certd may
	// cap it further; the renewer trusts the returned envelope when
	// scheduling the next renewal. Zero ⇒ certd's default.
	RequestedTTL time.Duration

	// RenewFraction is the fraction of validity elapsed before re-
	// signing. 0 ⇒ DefaultRenewFraction.
	RenewFraction float64

	// MinRenewInterval is the floor between renewals; guards against
	// short TTLs causing a tight signing loop. 0 ⇒ DefaultMinRenewInterval.
	MinRenewInterval time.Duration

	// RetryBackoff is the delay after a signing failure before
	// retrying. 0 ⇒ DefaultRetryBackoff.
	RetryBackoff time.Duration

	// OnRenewed is invoked after each successful write with the
	// validity envelope of the new cert. Production wires this to a
	// notify-consumer hook (SIGHUP a sidecar, touch a file watched
	// by the TLS stack, etc.). Nil ⇒ no-op.
	OnRenewed func(validAfter, validBefore time.Time)

	// SignErrorAttrs, if set, returns extra structured fields the
	// renewer appends to its per-failure retry-log warn line. Use
	// this to thread caller-specific context (e.g., remaining
	// validity on the mTLS material the agent presents to certd)
	// into the renewer's logs without coupling this package to the
	// caller's bootstrap concepts. Called once per failed SignOnce
	// inside Run, before the retry sleep. Nil ⇒ no extra fields.
	SignErrorAttrs func() []any

	// Now is the clock used for renewal scheduling. nil ⇒ time.Now.
	Now func() time.Time

	// Log is the logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// Sensible defaults — exported so callers can document deviations
// without re-deriving the constants.
const (
	DefaultRenewFraction    = 0.6 // re-sign at 60% of validity elapsed
	DefaultMinRenewInterval = 1 * time.Minute
	DefaultRetryBackoff     = 30 * time.Second
)

// Renewer owns the workload private key and the renewal loop. Safe
// for single-goroutine use; [Run] is intended to own its goroutine,
// while [SignOnce] is callable independently from the same caller.
type Renewer struct {
	cfg Config

	keyMu        sync.Mutex
	privateKey   crypto.Signer // lazily loaded/generated on first SignOnce
	keyPEM       []byte        // PKCS#8 PEM of privateKey; cached for the bundle write
	keyPersisted bool          // true once the key is durably on disk (loaded or bundle-written)
}

// New validates cfg and returns a [Renewer]. Returns an error rather
// than panicking so callers see config bugs at startup.
func New(cfg Config) (*Renewer, error) {
	if cfg.Signer == nil {
		return nil, errors.New("signer is required")
	}
	if cfg.SPIFFEURI == "" {
		return nil, errors.New("SPIFFEURI is required")
	}
	if cfg.CertOutputPath == "" {
		return nil, errors.New("CertOutputPath is required")
	}
	if cfg.KeyOutputPath == "" {
		return nil, errors.New("KeyOutputPath is required")
	}
	switch cfg.KeyType {
	case "":
		cfg.KeyType = KeyECDSAP256
	case KeyECDSAP256, KeyEd25519:
	default:
		return nil, fmt.Errorf("unsupported KeyType %q (want ecdsa-p256 or ed25519)", cfg.KeyType)
	}
	if cfg.RenewFraction == 0 {
		cfg.RenewFraction = DefaultRenewFraction
	}
	if cfg.RenewFraction <= 0 || cfg.RenewFraction >= 1 {
		return nil, fmt.Errorf("RenewFraction must be in (0,1), got %v", cfg.RenewFraction)
	}
	if cfg.MinRenewInterval == 0 {
		cfg.MinRenewInterval = DefaultMinRenewInterval
	}
	if cfg.RetryBackoff == 0 {
		cfg.RetryBackoff = DefaultRetryBackoff
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Renewer{cfg: cfg}, nil
}

// SignOnce performs one round-trip: ensures the private key exists
// (loading from KeyOutputPath or generating + persisting a fresh key
// of the configured KeyType), encodes its public half, asks certd for
// a fresh cert, and writes the cert atomically. Returns the validity
// envelope so the [Run] loop can schedule the next renewal.
func (r *Renewer) SignOnce(ctx context.Context) (validAfter, validBefore time.Time, err error) {
	priv, keyPEM, writeBundle, err := r.keyForRenewal()
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("private key: %w", err)
	}

	pubPEM, err := marshalPublicKeyPEM(priv.Public())
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("marshal public key: %w", err)
	}

	req := client.SignWorkloadRequest{
		PublicKey:         string(pubPEM),
		SPIFFEURI:         r.cfg.SPIFFEURI,
		SubjectCommonName: r.cfg.SubjectCommonName,
		Groups:            r.cfg.Groups,
		// Serial of the cert we're rotating from, read from disk so it
		// survives restarts without extra state. Empty on first issuance
		// (or after a fresh bootstrap). certd's anti-theft guard, when
		// active, accepts only the current or one-step-previous serial.
		CurrentSerial: readCurrentSerial(r.cfg.CertOutputPath),
	}
	if r.cfg.RequestedTTL > 0 {
		req.TTLSeconds = int64(r.cfg.RequestedTTL.Seconds())
	}
	resp, err := r.cfg.Signer.SignWorkloadCert(ctx, req)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("sign workload cert: %w", err)
	}
	if resp.Certificate == "" {
		return time.Time{}, time.Time{}, errors.New("certd returned empty certificate")
	}

	// When the key isn't yet on disk (first issuance / key generation),
	// write key+cert together (key-first, cert-last) to minimise the
	// desync window — see output.WriteBundleAtomic. This is not a
	// cross-file atomic guarantee; the consumer's loader must verify the
	// pair and keep the last-known-good on mismatch (base tls.CertLoader /
	// tls/reloader do). Once the key is persisted, normal renewals rotate
	// only the cert (the key is stable), so a plain atomic cert write
	// suffices.
	certPEM := certWithChain(resp)
	if writeBundle {
		if err := output.WriteBundleAtomic(
			r.cfg.CertOutputPath, certPEM, 0o644,
			r.cfg.KeyOutputPath, keyPEM, 0o600,
		); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("write cert+key bundle: %w", err)
		}
		if !r.cfg.RotateKey {
			r.markKeyPersisted()
		}
	} else if err := output.WriteAtomic(r.cfg.CertOutputPath, certPEM, 0o644); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("write cert: %w", err)
	}
	r.cfg.Log.Info("workload cert renewed",
		"spiffe_uri", resp.SPIFFEURI,
		"serial", resp.Serial,
		"valid_after", resp.ValidAfter,
		"valid_before", resp.ValidBefore,
		"cert_path", r.cfg.CertOutputPath,
	)
	// Ack adoption now that the new cert is durably on disk: certd drops the
	// serial we rotated from, shrinking the reuse-acceptance window. Best-
	// effort — a failure just leaves the one-step grace in place.
	if _, err := r.cfg.Signer.AdoptCert(ctx, resp.SPIFFEURI, resp.Serial); err != nil {
		r.cfg.Log.Warn("adopt cert (best-effort)", "spiffe_uri", resp.SPIFFEURI, "err", err)
	}
	if r.cfg.OnRenewed != nil {
		r.cfg.OnRenewed(resp.ValidAfter, resp.ValidBefore)
	}
	return resp.ValidAfter, resp.ValidBefore, nil
}

// Run signs immediately and then loops, renewing at the configured
// fraction of validity elapsed. Returns when ctx is cancelled.
// Signing failures schedule a retry after [Config.RetryBackoff]
// rather than crashing — the consumer keeps using the existing
// credentials until they expire.
func (r *Renewer) Run(ctx context.Context) error {
	for {
		validAfter, validBefore, err := r.SignOnce(ctx)
		var wait time.Duration
		if err != nil {
			args := []any{"err", err, "backoff", r.cfg.RetryBackoff}
			if r.cfg.SignErrorAttrs != nil {
				args = append(args, r.cfg.SignErrorAttrs()...)
			}
			r.cfg.Log.Warn("workload cert sign failed; will retry", args...)
			wait = r.cfg.RetryBackoff
		} else {
			wait = r.nextRenewalDelay(validAfter, validBefore)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// nextRenewalDelay returns how long to wait before the next sign
// attempt. Floored at [Config.MinRenewInterval].
func (r *Renewer) nextRenewalDelay(validAfter, validBefore time.Time) time.Duration {
	lifetime := validBefore.Sub(validAfter)
	renewAfter := time.Duration(float64(lifetime) * r.cfg.RenewFraction)
	deadline := validAfter.Add(renewAfter)
	wait := deadline.Sub(r.cfg.Now())
	if wait < r.cfg.MinRenewInterval {
		return r.cfg.MinRenewInterval
	}
	return wait
}

// keyForRenewal returns the private key to certify this cycle, its PKCS#8
// PEM, and whether the key must be written alongside the cert (a bundle
// write). With [Config.RotateKey] it mints a fresh keypair every call
// (always bundled, since key+cert change together); otherwise it returns
// the stable key via [ensureKey] (bundled only on first issuance, then
// cert-only).
func (r *Renewer) keyForRenewal() (priv crypto.Signer, keyPEM []byte, writeBundle bool, err error) {
	if !r.cfg.RotateKey {
		return r.ensureKey()
	}
	key, err := generateKey(r.cfg.KeyType)
	if err != nil {
		return nil, nil, false, fmt.Errorf("generate key: %w", err)
	}
	pemBytes, err := marshalPrivateKeyPEM(key)
	if err != nil {
		return nil, nil, false, fmt.Errorf("marshal generated key: %w", err)
	}
	return key, pemBytes, true, nil
}

// ensureKey returns the workload private key, its PKCS#8 PEM, and whether
// it still needs persisting to disk. It loads an existing key from
// KeyOutputPath (already on disk ⇒ needPersist false), or generates a
// fresh one of the configured type held only in memory (needPersist true)
// — [SignOnce] then writes it atomically alongside the new cert via
// [output.WriteBundleAtomic], so a reader never sees a new key without its
// matching cert. The key is cached so retries (and later renewals) reuse
// the same key without regenerating; needPersist stays true across retries
// until a bundle write succeeds.
func (r *Renewer) ensureKey() (priv crypto.Signer, keyPEM []byte, needPersist bool, err error) {
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	if r.privateKey != nil {
		return r.privateKey, r.keyPEM, !r.keyPersisted, nil
	}

	if b, err := os.ReadFile(r.cfg.KeyOutputPath); err == nil {
		key, err := parsePrivateKeyPEM(b)
		if err != nil {
			return nil, nil, false, fmt.Errorf("parse existing key %s: %w", r.cfg.KeyOutputPath, err)
		}
		r.privateKey = key
		r.keyPEM = b
		r.keyPersisted = true
		return key, b, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, fmt.Errorf("read key %s: %w", r.cfg.KeyOutputPath, err)
	}

	// Generate a fresh key of the configured type, held in memory until the
	// first successful sign persists it with the cert (workload private
	// keys are written 0600 — never world-readable).
	key, err := generateKey(r.cfg.KeyType)
	if err != nil {
		return nil, nil, false, fmt.Errorf("generate key: %w", err)
	}
	pemBytes, err := marshalPrivateKeyPEM(key)
	if err != nil {
		return nil, nil, false, fmt.Errorf("marshal generated key: %w", err)
	}
	r.cfg.Log.Info("workload private key generated (pending first-cert persist)", "path", r.cfg.KeyOutputPath, "key_type", r.cfg.KeyType)
	r.privateKey = key
	r.keyPEM = pemBytes
	r.keyPersisted = false
	return key, pemBytes, true, nil
}

// markKeyPersisted records that the key is now durably on disk.
func (r *Renewer) markKeyPersisted() {
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	r.keyPersisted = true
}

// generateKey produces a fresh private key of the requested type. Each
// returned type implements [crypto.Signer]; the renewer uses only its
// public half (certd does the signing).
func generateKey(kt KeyType) (crypto.Signer, error) {
	switch kt {
	case KeyECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported key type %q", kt)
	}
}

// certWithChain returns the PEM to write to disk: the leaf followed by any
// issuer chain certd returned (intermediate CA cert(s)), so the consumer's TLS
// stack presents leaf+intermediate and peers can build a path to the pinned
// root. Each block certd emits is newline-terminated, so concatenation yields a
// valid multi-block file and readCurrentSerial still reads the leaf (the first
// block). Empty Chain (single-tier) leaves the leaf standing alone.
func certWithChain(resp *client.SignWorkloadResponse) []byte {
	if resp.Chain == "" {
		return []byte(resp.Certificate)
	}
	return []byte(resp.Certificate + resp.Chain)
}

// readCurrentSerial returns the decimal serial of the cert currently at
// path, or "" when it's absent or unparseable (first issuance / fresh
// bootstrap). Reading from disk keeps the renewer stateless across
// restarts — the cert it holds IS its current serial.
func readCurrentSerial(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.SerialNumber.String()
}

// marshalPublicKeyPEM returns the SubjectPublicKeyInfo-encoded form
// certd expects in the sign-workload request body.
func marshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// marshalPrivateKeyPEM returns the PKCS#8-encoded private key PEM the
// workload's TLS stack reads via tls.LoadX509KeyPair.
func marshalPrivateKeyPEM(priv crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parsePrivateKeyPEM decodes the PKCS#8 PEM this package writes,
// accepting any key type that satisfies [crypto.Signer] (ECDSA, RSA,
// or Ed25519).
func parsePrivateKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
	return signer, nil
}
