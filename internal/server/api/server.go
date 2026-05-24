// Package api hosts the certd HTTP handlers — health, signing endpoints,
// role-admin API, recording-metadata ingest from ssh-proxyd, and the
// portal session layer. Caller authentication is mTLS (workload SPIFFE
// certs) or OIDC ID tokens (humans driving the CLI), enforced per-route.
package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/abagile/tokyo3-base/journal"
	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// Server holds all dependencies for the HTTP API. Pure value — safe to
// share across goroutines once constructed.
type Server struct {
	log      *slog.Logger
	caSigner signer.Signer
	audit    audit.Sink     // JetStream publisher; NoopSink when CERTD_NATS_URL is unset.
	auditSrc journal.Source // JetStream reader for the portal audit page; NoopSource when CERTD_NATS_URL is unset.
	version  string         // build-time version string, surfaced in /healthz; empty allowed.
}

// Config is the constructor argument for [New].
type Config struct {
	// Log is the structured logger used for request logging and audit
	// fallbacks. Required.
	Log *slog.Logger
	// CASigner is the CA signing primitive used by the issuance
	// endpoints. Required.
	CASigner signer.Signer
	// Audit is the audit-event sink. When nil, [audit.NoopSink] is
	// used (events are discarded silently).
	Audit audit.Sink
	// AuditSource is the live-tail reader for the portal audit page.
	// When nil, a no-op source is used.
	AuditSource journal.Source
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
		log:      cfg.Log,
		caSigner: cfg.CASigner,
		audit:    auditSink,
		auditSrc: auditSrc,
		version:  cfg.Version,
	}, nil
}

// Routes returns the HTTP handler tree. Mount under any prefix; routes
// are absolute (no required prefix).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/v1/ssh/sign-user", s.handleSignUserCert)
	mux.HandleFunc("POST /api/v1/ssh/sign-host", s.handleSignHostCert)
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
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body := healthzResponse{
		Status:       "ok",
		Version:      s.version,
		CASignerInfo: s.caSigner.Description(),
		CAPublicKey:  caPublicKeyFingerprint(s.caSigner),
		AuditActive:  s.audit != audit.NoopSink,
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
