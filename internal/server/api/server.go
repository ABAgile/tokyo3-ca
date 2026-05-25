// Package api hosts the certd HTTP handlers — health, signing endpoints,
// role-admin API, recording-metadata ingest from ssh-proxyd, and the
// portal session layer. Caller authentication is mTLS (workload SPIFFE
// certs) or OIDC ID tokens (humans driving the CLI), enforced per-route.
package api

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/abagile/tokyo3-base/journal"
	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/portal"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// Server holds all dependencies for the HTTP API. Pure value — safe to
// share across goroutines once constructed.
type Server struct {
	log            *slog.Logger
	caSigner       signer.Signer
	x509IssuerCert *x509.Certificate  // CA cert used as issuer for X.509 issuance; nil disables /x509/* routes.
	policy         *policy.Engine     // Role-table enforcer; nil = permissive (pre-auth wiring).
	oidc           oidc.TokenVerifier // Bearer-token verifier; nil = no OIDC auth.
	mtls           mtls.Store         // Cert-principal registry; nil = no mTLS auth.
	audit          audit.Sink         // JetStream publisher; NoopSink when CERTD_NATS_URL is unset.
	auditSrc       journal.Source     // JetStream reader for the portal audit page; NoopSource when CERTD_NATS_URL is unset.
	portal         *portal.Server     // Admin web UI; nil disables /portal/* routes.
	krl            krl.Store          // Revocation registry; nil disables /api/v1/ssh/revoke + /revocations.
	version        string             // build-time version string, surfaced in /healthz; empty allowed.
}

// Config is the constructor argument for [New].
type Config struct {
	// Log is the structured logger used for request logging and audit
	// fallbacks. Required.
	Log *slog.Logger
	// CASigner is the CA signing primitive used by the issuance
	// endpoints. Required.
	CASigner signer.Signer
	// X509IssuerCert is the CA certificate used as the issuer when
	// signing X.509 workload certs. Use [x509engine.NewSelfSignedCA]
	// to construct it from CASigner, or load a pre-issued cert from
	// disk. When nil, the /api/v1/x509/* routes return 503; the SSH
	// signing endpoints are unaffected.
	X509IssuerCert *x509.Certificate
	// Policy applies the role table to incoming sign requests. When
	// nil, sign endpoints are permissive — anyone reaching them can
	// sign anything within the endpoint TTL ceiling. Production builds
	// must set this; pre-OIDC/mTLS phases of the MVP leave it nil so
	// integration tests can exercise the cert engines directly.
	Policy *policy.Engine
	// OIDCVerifier validates inbound Authorization: Bearer tokens
	// against authd. When set, sign endpoints accept a valid token
	// and derive the caller's groups from its claims. When nil, the
	// bearer-token path is closed.
	OIDCVerifier oidc.TokenVerifier
	// MTLSStore maps the SANs presented on the inbound TLS client
	// cert to a workload identity + group claims. When set, sign
	// endpoints accept a verified client cert as an alternative to
	// the bearer-token path. When nil, the mTLS auth path is closed.
	//
	// When both OIDCVerifier and MTLSStore are configured, the
	// bearer-token path wins if an Authorization header is present.
	// Workloads that authenticate via mTLS simply omit the header.
	// When neither is configured, the request body's groups field
	// is used directly (pre-auth-wiring fallback for tests).
	MTLSStore mtls.Store
	// Audit is the audit-event sink. When nil, [audit.NoopSink] is
	// used (events are discarded silently).
	Audit audit.Sink
	// AuditSource is the live-tail reader for the portal audit page.
	// When nil, a no-op source is used.
	AuditSource journal.Source
	// Portal is the admin web UI handler. When nil, /portal/* routes
	// are not mounted (the API surface still works without a portal —
	// useful for headless certd deployments).
	Portal *portal.Server
	// KRL is the SSH cert revocation store. When non-nil, the
	// /api/v1/ssh/revoke + /api/v1/ssh/revocations endpoints are
	// mounted; otherwise they return 503. The same store should be
	// passed to ssh-proxyd so its IsRevoked callback uses the
	// authoritative set.
	KRL krl.Store
	// Version is the build-time semver / commit identifier surfaced in
	// /healthz. Empty acceptable but discouraged in deployed builds.
	Version string
}

// New constructs a Server from cfg, validating that the required
// dependencies are present.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		return nil, errors.New("api.New: Log is required")
	}
	if cfg.CASigner == nil {
		return nil, errors.New("api.New: CASigner is required")
	}
	auditSink := cfg.Audit
	if auditSink == nil {
		auditSink = audit.NoopSink
	}
	auditSrc := cfg.AuditSource
	if auditSrc == nil {
		auditSrc = journal.NoopSource{}
	}
	return &Server{
		log:            cfg.Log,
		caSigner:       cfg.CASigner,
		x509IssuerCert: cfg.X509IssuerCert,
		policy:         cfg.Policy,
		oidc:           cfg.OIDCVerifier,
		mtls:           cfg.MTLSStore,
		audit:          auditSink,
		auditSrc:       auditSrc,
		portal:         cfg.Portal,
		krl:            cfg.KRL,
		version:        cfg.Version,
	}, nil
}

// Routes returns the HTTP handler tree. Mount under any prefix; routes
// are absolute (no required prefix). When [Config.Portal] was set, the
// portal handlers are mounted under /portal/ — its routes use the
// host pattern itself, so the http.ServeMux StripPrefix call here is
// what makes them resolve correctly.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/v1/ssh/sign-user", s.handleSignUserCert)
	mux.HandleFunc("POST /api/v1/ssh/sign-host", s.handleSignHostCert)
	mux.HandleFunc("POST /api/v1/x509/sign-workload", s.handleSignX509WorkloadCert)
	mux.HandleFunc("POST /api/v1/ssh/revoke", s.handleRevoke)
	mux.HandleFunc("GET /api/v1/ssh/revocations", s.handleRevocations)
	if s.portal != nil {
		mux.Handle("/portal/", http.StripPrefix("/portal", s.portal.Routes()))
	}
	return mux
}

// healthzResponse is the body returned by GET /healthz. Stable for
// monitoring; new fields are additive.
type healthzResponse struct {
	Status       string `json:"status"`
	Version      string `json:"version,omitempty"`
	CASignerInfo string `json:"ca_signer"`
	CAPublicKey  string `json:"ca_public_key"`
	AuditActive  bool   `json:"audit_active"`
	PolicyActive bool   `json:"policy_active"`
	OIDCActive   bool   `json:"oidc_active"`
	MTLSActive   bool   `json:"mtls_active"`
	X509Active   bool   `json:"x509_active"`
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body := healthzResponse{
		Status:       "ok",
		Version:      s.version,
		CASignerInfo: s.caSigner.Description(),
		CAPublicKey:  caPublicKeyFingerprint(s.caSigner),
		AuditActive:  s.audit != audit.NoopSink,
		PolicyActive: s.policy != nil,
		OIDCActive:   s.oidc != nil,
		MTLSActive:   s.mtls != nil,
		X509Active:   s.x509IssuerCert != nil,
	}
	_ = json.NewEncoder(w).Encode(body)
}

// caPublicKeyFingerprint returns the SSH-format fingerprint of the CA's
// public key, suitable for operator-facing display. Returns an empty
// string if the key cannot be wrapped (a misconfigured signer).
func caPublicKeyFingerprint(s signer.Signer) string {
	pub := s.Public()
	// Path 1: Ed25519 — most common in this codebase.
	if ed, ok := pub.(ed25519.PublicKey); ok {
		k, err := ssh.NewPublicKey(ed)
		if err == nil {
			return ssh.FingerprintSHA256(k)
		}
	}
	// Path 2: anything ssh.NewPublicKey can wrap (RSA, ECDSA).
	if k, err := ssh.NewPublicKey(pub); err == nil {
		return ssh.FingerprintSHA256(k)
	}
	return ""
}
