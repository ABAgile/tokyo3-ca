package renew

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/agent/output"
	"github.com/abagile/tokyo3-ca/internal/client"
)

// UserSigner is the subset of [client.Client] [UserCertRenewer] needs.
// Defined here so tests can stub the network round-trip without
// spinning up an httptest server.
type UserSigner interface {
	SignUserCert(ctx context.Context, req client.SignUserRequest) (*client.SignUserResponse, error)
}

// UserCertConfig wires a [UserCertRenewer]. Required fields are
// validated at [NewUserCertRenewer] time; optional knobs default to
// production-sensible values.
type UserCertConfig struct {
	// Signer is the certd client. Required.
	Signer UserSigner

	// KeyID is the human-readable identifier embedded in the cert
	// (also surfaces in certd's audit log). Required. Convention:
	// "user:<service-name>".
	KeyID string

	// Principals are the Unix usernames the cert authorizes login
	// as. At least one entry required.
	Principals []string

	// CertOutputPath is where the renewed SSH cert is written
	// atomically. Required. Convention: alongside KeyOutputPath
	// with the "-cert.pub" suffix (sshd's CertificateFile +
	// IdentityFile pair).
	CertOutputPath string

	// KeyOutputPath is where the matching SSH private key is
	// written. The agent owns the key — generated locally on first
	// run, never transmitted to certd.
	KeyOutputPath string

	// Extensions are SSH cert extensions (e.g., "permit-pty": "").
	// Merged with certd's role-default extensions; request-level
	// values win on conflict.
	Extensions map[string]string

	// CriticalOptions are strictly-enforced sshd options. Optional.
	CriticalOptions map[string]string

	// RequestedTTL is the validity window asked of certd. Zero ⇒
	// certd's default.
	RequestedTTL time.Duration

	// RenewFraction is the fraction of validity elapsed before
	// re-signing. 0 ⇒ DefaultRenewFraction.
	RenewFraction float64

	// MinRenewInterval is the floor between renewals. 0 ⇒ DefaultMinRenewInterval.
	MinRenewInterval time.Duration

	// RetryBackoff is the delay after a signing failure before
	// retrying. 0 ⇒ DefaultRetryBackoff.
	RetryBackoff time.Duration

	// OnRenewed is invoked after each successful write with the
	// validity envelope of the new cert. Nil ⇒ no-op. Unlike the
	// X.509 renewer, consumer notification is rarely needed for
	// SSH certs — the OpenSSH client re-reads its config on every
	// connection.
	OnRenewed func(validAfter, validBefore time.Time)

	// Now is the clock used for renewal scheduling. nil ⇒ time.Now.
	Now func() time.Time

	// Log is the logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// UserCertRenewer owns the SSH user private key and the renewal
// loop. Mirrors [Renewer]'s shape for X.509 workload certs; the two
// differ only in key type (ed25519 vs ECDSA) and certd endpoint.
type UserCertRenewer struct {
	cfg UserCertConfig

	keyMu      sync.Mutex
	privateKey ed25519.PrivateKey
}

// NewUserCertRenewer validates cfg and returns a [UserCertRenewer].
func NewUserCertRenewer(cfg UserCertConfig) (*UserCertRenewer, error) {
	if cfg.Signer == nil {
		return nil, errors.New("signer is required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("KeyID is required")
	}
	if len(cfg.Principals) == 0 {
		return nil, errors.New("at least one Principal is required")
	}
	if cfg.CertOutputPath == "" {
		return nil, errors.New("CertOutputPath is required")
	}
	if cfg.KeyOutputPath == "" {
		return nil, errors.New("KeyOutputPath is required")
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
	return &UserCertRenewer{cfg: cfg}, nil
}

// SignOnce ensures the SSH private key exists (loading from disk or
// generating a fresh ed25519 keypair), encodes its public half in
// authorized_keys format, asks certd for a fresh user cert, and
// writes the cert line atomically.
func (r *UserCertRenewer) SignOnce(ctx context.Context) (validAfter, validBefore time.Time, err error) {
	signer, err := r.ensureKey()
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("ssh private key: %w", err)
	}

	pubAuth := gossh.MarshalAuthorizedKey(signer.PublicKey())

	req := client.SignUserRequest{
		PublicKey:       string(pubAuth),
		KeyID:           r.cfg.KeyID,
		Principals:      r.cfg.Principals,
		Extensions:      r.cfg.Extensions,
		CriticalOptions: r.cfg.CriticalOptions,
	}
	if r.cfg.RequestedTTL > 0 {
		req.TTLSeconds = int64(r.cfg.RequestedTTL.Seconds())
	}
	resp, err := r.cfg.Signer.SignUserCert(ctx, req)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("sign user cert: %w", err)
	}
	if resp.Certificate == "" {
		return time.Time{}, time.Time{}, errors.New("certd returned empty certificate")
	}

	// SSH cert files conventionally end with a newline (matching
	// what ssh-keygen and gossh.MarshalAuthorizedKey produce).
	certBytes := []byte(resp.Certificate)
	if len(certBytes) > 0 && certBytes[len(certBytes)-1] != '\n' {
		certBytes = append(certBytes, '\n')
	}
	if err := output.WriteAtomic(r.cfg.CertOutputPath, certBytes, 0o644); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("write cert: %w", err)
	}
	r.cfg.Log.Info("ssh user cert renewed",
		"key_id", resp.KeyID,
		"serial", resp.Serial,
		"valid_after", resp.ValidAfter,
		"valid_before", resp.ValidBefore,
		"cert_path", r.cfg.CertOutputPath,
	)
	if r.cfg.OnRenewed != nil {
		r.cfg.OnRenewed(resp.ValidAfter, resp.ValidBefore)
	}
	return resp.ValidAfter, resp.ValidBefore, nil
}

// Run signs immediately and then loops, renewing at the configured
// fraction of validity elapsed. Returns when ctx is cancelled.
// Failures retry after [UserCertConfig.RetryBackoff] rather than
// crashing.
func (r *UserCertRenewer) Run(ctx context.Context) error {
	for {
		validAfter, validBefore, err := r.SignOnce(ctx)
		var wait time.Duration
		if err != nil {
			r.cfg.Log.Warn("ssh user cert sign failed; will retry",
				"err", err, "backoff", r.cfg.RetryBackoff)
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

func (r *UserCertRenewer) nextRenewalDelay(validAfter, validBefore time.Time) time.Duration {
	lifetime := validBefore.Sub(validAfter)
	renewAfter := time.Duration(float64(lifetime) * r.cfg.RenewFraction)
	deadline := validAfter.Add(renewAfter)
	wait := deadline.Sub(r.cfg.Now())
	if wait < r.cfg.MinRenewInterval {
		return r.cfg.MinRenewInterval
	}
	return wait
}

// ensureKey loads or generates the ed25519 SSH key. Mirrors
// [Renewer.ensureKey] — fresh key only when the file doesn't exist;
// subsequent runs reuse the on-disk key.
func (r *UserCertRenewer) ensureKey() (gossh.Signer, error) {
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	if r.privateKey != nil {
		return gossh.NewSignerFromKey(r.privateKey)
	}

	if b, err := os.ReadFile(r.cfg.KeyOutputPath); err == nil {
		signer, err := gossh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("parse existing ssh key %s: %w", r.cfg.KeyOutputPath, err)
		}
		// Extract the ed25519 private key for the cache. ParsePrivateKey
		// returns a Signer, but we want to remember the raw key for the
		// cache. Re-derive from the marshaled form.
		if priv, ok := signerToEd25519(signer); ok {
			r.privateKey = priv
		}
		return signer, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ssh key %s: %w", r.cfg.KeyOutputPath, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	pemBlock, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal ssh key: %w", err)
	}
	if err := output.WriteAtomic(r.cfg.KeyOutputPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return nil, fmt.Errorf("write ssh key %s: %w", r.cfg.KeyOutputPath, err)
	}
	r.cfg.Log.Info("ssh user private key generated", "path", r.cfg.KeyOutputPath)
	r.privateKey = priv
	return gossh.NewSignerFromKey(priv)
}

// signerToEd25519 unwraps the underlying ed25519 private key from a
// gossh.Signer when possible. Best-effort — when the unwrap fails we
// just don't cache the key (subsequent calls re-parse from disk).
func signerToEd25519(s gossh.Signer) (ed25519.PrivateKey, bool) {
	type rawKey interface {
		PrivateKey() any
	}
	if rk, ok := s.(rawKey); ok {
		if pk, ok := rk.PrivateKey().(ed25519.PrivateKey); ok {
			return pk, true
		}
	}
	return nil, false
}
