// Command certd is the tokyo3-ca certificate authority server.
//
// Issues short-lived SSH and X.509 (SPIFFE) certificates against an
// internal role table that maps OIDC groups to allowed principals and
// host patterns. Authenticates callers via mTLS workload certs
// (machines) or OIDC ID tokens (humans), publishes audit events to NATS
// JetStream, and serves a web portal for role administration, session
// replay, and host registry browsing.
//
// Required env vars (none today; see Optional for the dev defaults):
//
// Optional env vars:
//
//	CERTD_ADDR  HTTPS listen address (default ":8443").
//
//	CERTD_DEBUG_ADDR  Optional plaintext address for net/http/pprof + a 30s goroutine/OS-thread
//	                  stats log (e.g. "127.0.0.1:6060"). Unset ⇒ disabled. Never expose publicly
//	                  — it serves unauthenticated profiling on its own listener, off the mTLS
//	                  API.
//
//	CERTD_API_CERT       Server TLS certificate PEM path. Hot-reloaded (mtime polled at most
//	                     once per second across handshakes, so rotations land within ~1s).
//	CERTD_API_KEY        Server TLS private key PEM path. Required iff CERTD_API_CERT is set. If
//	                     neither is set an ephemeral self-signed cert is generated (dev only).
//	CERTD_API_CLIENT_CA  Optional CA PEM for verifying inbound mTLS client certs (mesh
//	                     workloads); falls back to CERTD_WORKLOAD_CA. When set, client certs are
//	                     validated against the bundle (VerifyClientCertIfGiven mode). Both unset
//	                     ⇒ client-cert verification off.
//
//	CERTD_WORKLOAD_CA  CA PEM that signs every internal workload cert certd connects to (NATS,
//	                   future DB). Used as the fallback for CERTD_NATS_CA when that var is
//	                   unset.
//
//	CERTD_CA_KEY_FILE        PKCS#8-encoded Ed25519 private key PEM path — the CA signing key
//	                         used for BOTH SSH user/host certs and X.509/SPIFFE workload certs
//	                         (one key: wrapped for SSH, used directly for X.509). When unset
//	                         (and CERTD_CA_KMS_KEY also unset), certd generates an ephemeral key
//	                         at startup — dev only; certs are invalidated on every restart.
//	CERTD_CA_KMS_KEY         KMS key reference (ARN / GCP resource name / Vault key path) for a
//	                         CA key that never leaves the HSM. Takes precedence over
//	                         CERTD_CA_KEY_FILE. The AWS KMS binding (cmd/certd/kms_aws.go) is
//	                         compiled in by default, so this works on the stock binary; other
//	                         backends register via RegisterKMSClientFactory (see
//	                         internal/server/signer/kms). The same var drives `certd ca`.
//	CERTD_CA_X509_CERT_FILE  X.509-only issuer cert for the workload/SPIFFE certs signed by that
//	                         key. SSH needs no issuer cert — clients trust the key's public half
//	                         via TrustedUserCAKeys. When unset, certd self-signs one at startup
//	                         from the CA signing key — dev only; production should pin a stable
//	                         cert so consumers can verify the chain.
//	CERTD_CA_X509_CERT_CN    Subject CN for the self-signed startup CA cert. Default
//	                         "tokyo3-ca".
//
//	CERTD_NATS_URL   NATS server URL (e.g., nats://nats:4222 or tls://nats:4222). Empty disables
//	                 JetStream publishing — audit sink becomes [audit.NoopSink], audit source
//	                 becomes [journal.NoopSource].
//	CERTD_NATS_CERT  Publisher client certificate PEM path (mTLS).
//	CERTD_NATS_KEY   Publisher client key PEM path. Required iff CERTD_NATS_CERT is set.
//	CERTD_NATS_CA    CA certificate PEM path for verifying the NATS server cert. Falls back to
//	                 CERTD_WORKLOAD_CA.
//
//	CERTD_OIDC_ISSUER    OIDC IdP issuer URL (e.g., https://auth.example.com). When set together
//	                     with CERTD_OIDC_AUDIENCE, sign endpoints require a valid Authorization:
//	                     Bearer token and derive the caller's groups from its claims. When
//	                     unset, body groups are used (for tests and pre-prod).
//	CERTD_OIDC_AUDIENCE  The `aud` claim the IdP embeds on every token minted for certd (the
//	                     OIDC client_id the IdP registers for this service). Required when
//	                     CERTD_OIDC_ISSUER is set.
//
//	CERTD_MTLS_PRINCIPALS_FILE  Path to a JSON file mapping cert SANs
//	                            (SPIFFE URI or email) to workload identities
//	                            + group claims. When set, sign endpoints
//	                            accept a verified client cert as an
//	                            alternative to the OIDC bearer path. File
//	                            shape:
//
//	                              [
//	                                {"name":"ssh-proxyd-prod",
//	                                 "san":"spiffe://corp/svc/ssh-proxyd",
//	                                 "groups":["ssh-proxy-service"]},
//	                                {"name":"ops-bot",
//	                                 "san":"ops@corp.com",
//	                                 "groups":["ops"]}
//	                              ]
//
//	                            Unset disables the mTLS auth path. The
//	                            admin portal will replace the file with a
//	                            Postgres-backed registry in a later slice.
//
//	CERTD_PORTAL_USERNAME       When set together with CERTD_PORTAL_PASSWORD, every /portal/*
//	                            request (except /healthz) must present matching HTTP Basic
//	                            credentials. Unset leaves the portal open and operators are
//	                            expected to front it with oauth2-proxy / mTLS / similar.
//	CERTD_PORTAL_PASSWORD       The matching secret. Constant-time compared against the
//	                            request's Authorization header.
//	CERTD_PORTAL_REALM          Optional Basic-auth realm shown in the browser prompt. Default
//	                            "certd portal".
//
//	CERTD_CAST_DIR  Directory containing the asciinema cast files referenced by
//	                recording.completed events (typically the same path ssh-proxyd writes to,
//	                mounted into the certd container). Required for the portal's session-replay
//	                embed and the /sessions/{id}/cast endpoint; unset leaves the player hidden.
//	                Paths outside this directory are rejected with 403.
//
//	CERTD_SSH_AUDIT_URL  NATS URL for the ssh_audit stream ssh-proxyd publishes
//	                     recording.completed events to. When set, certd subscribes, decodes the
//	                     events, and powers the portal's /sessions page. Falls back to
//	                     CERTD_NATS_URL when unset; truly empty means "no sessions page". TLS
//	                     material comes from CERTD_SSH_AUDIT_CERT/_KEY/_CA with the same
//	                     CERTD_NATS_* fallback chain.
//
//	CERTD_ROLES_FILE  Path to a JSON file holding the role table — top-level array of role
//	                  objects matching the [policy.Role] shape (Name, GroupClaim,
//	                  AllowedPrincipals, HostPatterns, SPIFFEPatterns, MaxFooCertTTL,
//	                  DefaultExtensions). When set, role-table policy is applied to every sign
//	                  request and the portal's /roles page renders the configured roles. Unset
//	                  (and no CERTD_DATABASE_URL) leaves certd in permissive mode (existing dev
//	                  behavior) and the portal page returns 503. With CERTD_DATABASE_URL set,
//	                  this file seeds a fresh (empty) database once via SeedIfEmpty.
//
//	CERTD_DATABASE_URL  Persistent store for the role table, the mTLS principal registry, and
//	                    the SSH revocation list (KRL) — one backend behind all three. A Postgres
//	                    DSN selects the production backend (mirrors authd's AUTH_DATABASE_URL); a
//	                    "sqlite:<path>" URL selects the pure-Go SQLite backend for the dev rig
//	                    (e.g. sqlite:/var/lib/certd/certd.db, or sqlite::memory: for ephemeral).
//	                    When set, certd applies migrations and serves policy/principals/
//	                    revocations from the DB; CERTD_ROLES_FILE / CERTD_MTLS_PRINCIPALS_FILE
//	                    then only SEED a fresh (empty) database. Unset uses the in-memory stores
//	                    seeded from those files — the dev default.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/cli"
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/jetstream"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/abagile/tokyo3-base/version"
	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/portal"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
	"github.com/abagile/tokyo3-ca/internal/store"
	pgstore "github.com/abagile/tokyo3-ca/internal/store/postgres"
	sqlitestore "github.com/abagile/tokyo3-ca/internal/store/sqlite"
)

const appName = "certd"

// Version is overridden at build time via -ldflags "-X main.Version=...".
// When that injection is absent — most notably `go install
// github.com/abagile/tokyo3-ca/cmd/certd@vX.Y.Z` — version.Resolve falls
// back to runtime/debug.BuildInfo, which exposes the module version + VCS
// metadata the Go toolchain stamps into every binary since 1.18. Result:
// tagged installs report their tag, local builds report "dev-<sha7>",
// and ldflags-injected release builds win when present.
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   appName,
		Short: "tokyo3-ca certificate authority server",
	}
	root.AddCommand(serveCmd(), versionCmd(), caCmd())
	return root
}

// ── serve ─────────────────────────────────────────────────────────────────────

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the CA HTTPS server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context())
		},
	}
}

func runServe(ctx context.Context) error {
	rt := cli.App{Name: appName, EnvPrefix: "CERTD"}.Setup(ctx)
	defer rt.Shutdown()
	log := rt.Log

	addr := envutil.Or("CERTD_ADDR", ":8443")

	caSigner, err := loadCASigner(ctx, log)
	if err != nil {
		return fmt.Errorf("load CA signer: %w", err)
	}
	log.Info("ca signer ready", "signer", caSigner.Description())

	auditSink, err := cli.AuditSink[audit.Entry](rt, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer envutil.CloseIfCloser(auditSink)
	auditSrc, err := cli.AuditSource(rt, audit.StreamName, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit source: %w", err)
	}
	defer envutil.CloseIfCloser(auditSrc)

	tlsCfg, err := buildServerTLS(log)
	if err != nil {
		return fmt.Errorf("server tls: %w", err)
	}

	oidcVerifier, err := loadOIDCVerifier(ctx, log)
	if err != nil {
		return fmt.Errorf("oidc verifier: %w", err)
	}

	// Persistent backend (Postgres / sqlite) shared across the role,
	// principal, and revocation tables — one connection, so SQLite works.
	// nil when CERTD_DATABASE_URL is unset (in-memory/file dev path).
	db, err := openStore(ctx, log)
	if err != nil {
		return fmt.Errorf("open store database: %w", err)
	}
	if db != nil {
		defer envutil.CloseIfCloser(db)
	}

	mtlsStore, err := loadMTLSStore(db, log)
	if err != nil {
		return fmt.Errorf("mtls store: %w", err)
	}

	x509IssuerCert, err := loadOrGenerateX509Issuer(log, caSigner)
	if err != nil {
		return fmt.Errorf("x509 issuer cert: %w", err)
	}

	roleStore, policyEngine, err := loadRoleStore(db, log)
	if err != nil {
		return fmt.Errorf("role store: %w", err)
	}

	// The mtls.Store satisfies portal.HostStore (its All() returns
	// every registered principal). Passing it directly avoids
	// constructing a separate per-portal copy of the registry.
	var hostStore portal.HostStore
	if mtlsStore != nil {
		hostStore = mtlsStore
	}

	// SessionTracker subscribes to ssh-proxyd's ssh_audit stream and
	// powers the /sessions page. The same source feeds the
	// /audit page's tracker alongside certd's own audit stream so
	// operators see both streams in one viewer.
	sshAuditSrcForSessions, err := openSSHAuditSource(log)
	if err != nil {
		return fmt.Errorf("ssh-audit source (sessions): %w", err)
	}
	sessionTracker, err := newSessionTracker(log, sshAuditSrcForSessions)
	if err != nil {
		return fmt.Errorf("session tracker: %w", err)
	}
	var sessionStore portal.SessionStore
	if sessionTracker != nil {
		sessionStore = sessionTracker
	}

	// AuditTracker tails certd's own audit stream + (optionally)
	// ssh-proxyd's. Both subscriptions are independent of the
	// session tracker's so the audit page never blocks on
	// recording.completed processing.
	sshAuditSrcForAudit, err := openSSHAuditSource(log)
	if err != nil {
		return fmt.Errorf("ssh-audit source (audit): %w", err)
	}
	auditTracker, err := newAuditTracker(log, auditSrc, sshAuditSrcForAudit)
	if err != nil {
		return fmt.Errorf("audit tracker: %w", err)
	}
	var auditStore portal.AuditStore
	if auditTracker != nil {
		auditStore = auditTracker
	}

	castStore, err := loadCastStore(log)
	if err != nil {
		return fmt.Errorf("cast store: %w", err)
	}

	var krlStore krl.Store
	if db != nil {
		krlStore = db.Revocations()
		log.Info("revocation store ready (database)")
	} else {
		krlStore = krl.NewInMemoryStore()
		log.Info("revocation store ready (in-memory)")
	}

	// The X.509 renewal/anti-theft guard is opt-in with the persistent
	// store: nil (no DB) leaves the sign-workload endpoint unguarded.
	var activeCerts store.ActiveCertStore
	if db != nil {
		activeCerts = db.ActiveCerts()
		log.Info("x509 renewal/anti-theft guard active")
	}

	portalSrv, err := portal.New(portal.Config{
		Version:         Version,
		Log:             log,
		RoleStore:       roleStore,
		HostStore:       hostStore,
		SessionStore:    sessionStore,
		AuditStore:      auditStore,
		CastStore:       castStore,
		RevocationStore: krlStore,
		BasicAuth: portal.BasicAuthConfig{
			Username: os.Getenv("CERTD_PORTAL_USERNAME"),
			Password: os.Getenv("CERTD_PORTAL_PASSWORD"),
			Realm:    os.Getenv("CERTD_PORTAL_REALM"),
		},
	})
	if err != nil {
		return fmt.Errorf("portal: %w", err)
	}

	srv, err := api.New(api.Config{
		Log:             log,
		CASigner:        caSigner,
		X509IssuerCert:  x509IssuerCert,
		Policy:          policyEngine,
		OIDCVerifier:    oidcVerifier,
		MTLSStore:       mtlsStore,
		Audit:           auditSink,
		AuditSource:     auditSrc,
		Portal:          portalSrv,
		KRL:             krlStore,
		ActiveCertStore: activeCerts,
		Version:         Version,
	})
	if err != nil {
		return fmt.Errorf("api server: %w", err)
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		// IdleTimeout reaps idle keep-alive connections (and their
		// per-connection serve goroutines) instead of letting them
		// linger until TCP keepalive eventually trips — without it a
		// half-closed or pooled client connection can pin a goroutine
		// indefinitely. Set above cert-agentd's renewal interval so the
		// agent's reused connection isn't torn down between cycles.
		// WriteTimeout is deliberately omitted: the portal's audit
		// viewer streams a long-lived SSE response that a write deadline
		// would sever.
		IdleTimeout: 120 * time.Second,
	}

	rootCtx := rt.Ctx

	if sessionTracker != nil {
		go func() {
			if err := sessionTracker.Run(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn("session tracker exited", "err", err)
			}
		}()
	}
	if auditTracker != nil {
		go func() {
			if err := auditTracker.Run(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn("audit tracker exited", "err", err)
			}
		}()
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr)
		// Both empty: TLSConfig.GetCertificate (or .Certificates) is the source of truth.
		err := httpSrv.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-rootCtx.Done():
		log.Info("shutdown requested", "signal", rootCtx.Err())
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}

// ── version ───────────────────────────────────────────────────────────────────

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("%s %s\n", appName, version.Resolve(Version))
		},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// loadCASigner returns the CA signing primitive via the shared signer
// seam (resolveCASigner): CERTD_CA_KMS_KEY selects a KMS-backed key
// (needs a KMS-bound build), CERTD_CA_KEY_FILE a PKCS#8 Ed25519 PEM
// file. When neither is set, certd generates an ephemeral keypair and
// warns that issued certs won't survive a restart.
func loadCASigner(ctx context.Context, log *slog.Logger) (signer.Signer, error) {
	keyPath := os.Getenv("CERTD_CA_KEY_FILE")
	kmsKey := os.Getenv("CERTD_CA_KMS_KEY")
	if keyPath == "" && kmsKey == "" {
		log.Warn("CERTD_CA_KEY_FILE / CERTD_CA_KMS_KEY unset — generating ephemeral CA key (not for production)")
		return signer.NewEphemeralEd25519()
	}
	return resolveCASigner(ctx, keyPath, kmsKey)
}

// loadOIDCVerifier returns a token verifier for inbound bearer tokens
// when CERTD_OIDC_ISSUER + CERTD_OIDC_AUDIENCE are both set. Either
// alone is an error (asymmetric config), and both unset returns nil
// (no OIDC — sign endpoints fall back to body groups).
//
// The returned verifier is lazy: OIDC discovery + JWKS fetch is
// deferred to the first sign request, so certd's bootstrap does not
// block on the IdP's reachability. A transient IdP outage at boot
// surfaces as a 401 on the first sign request and self-heals when
// the IdP comes back.
func loadOIDCVerifier(_ context.Context, log *slog.Logger) (oidc.TokenVerifier, error) {
	issuer := os.Getenv("CERTD_OIDC_ISSUER")
	audience := os.Getenv("CERTD_OIDC_AUDIENCE")
	if issuer == "" && audience == "" {
		log.Warn("CERTD_OIDC_ISSUER + CERTD_OIDC_AUDIENCE unset — token verification disabled; sign endpoints use body groups (not for production)")
		return nil, nil
	}
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("CERTD_OIDC_ISSUER and CERTD_OIDC_AUDIENCE must both be set or both unset")
	}
	v, err := oidc.NewLazyHTTPVerifier(issuer, audience)
	if err != nil {
		return nil, err
	}
	log.Info("oidc verifier configured (lazy)", "issuer", issuer, "audience", audience)
	return v, nil
}

// loadOrGenerateX509Issuer returns the CA cert used as the issuer
// for X.509 / SPIFFE workload issuance. When CERTD_CA_X509_CERT_FILE
// is set, the cert is loaded from PEM at that path; otherwise certd
// self-signs a fresh cert at startup using the existing CA signer.
// The self-signed path is dev-only — production deployments should
// pin trust to a stable, externally-issued cert.
func loadOrGenerateX509Issuer(log *slog.Logger, caSigner signer.Signer) (*x509.Certificate, error) {
	if path := os.Getenv("CERTD_CA_X509_CERT_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s does not contain a CERTIFICATE PEM block", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		log.Info("x509 issuer ready", "source", "file", "path", path, "cn", cert.Subject.CommonName)
		return cert, nil
	}
	cn := envutil.Or("CERTD_CA_X509_CERT_CN", "tokyo3-ca")
	cert, err := x509engine.NewSelfSignedCA(rand.Reader, caSigner, cn)
	if err != nil {
		return nil, err
	}
	log.Warn("CERTD_CA_X509_CERT_FILE unset — generated self-signed CA cert at startup (not for production)",
		"cn", cn, "not_after", cert.NotAfter)
	return cert, nil
}

// loadMTLSStore returns the workload-identity registry parsed from
// CERTD_MTLS_PRINCIPALS_FILE. Returns (nil, nil) when the env var is
// unset, disabling the mTLS auth path. Future slice swaps the
// file-backed implementation for a Postgres-backed Store managed by
// the admin portal — same interface, no API-layer changes.
// loadRoleStore builds the role table and its [*policy.Engine]. Backend
// is chosen by env:
//
//   - CERTD_DATABASE_URL set → the Postgres-backed store (persistent,
//     authoritative). CERTD_ROLES_FILE, when also set, seeds a *fresh*
//     (empty) database via SeedIfEmpty; an already-populated DB is left
//     as-is (the file is a cold-start seed, not a re-import). The engine
//     is built over the DB even when empty, so a configured DB means
//     policy is enforced.
//   - CERTD_DATABASE_URL unset, CERTD_ROLES_FILE set → the in-memory
//     store seeded from the file (existing dev behavior).
//   - both unset → (nil, nil, nil): certd operates permissively and the
//     portal's roles page returns 503.
//
// The returned store may hold a DB handle; the caller closes it via
// envutil.CloseIfCloser (a no-op for the in-memory store). The file
// format is a top-level JSON array of [policy.Role] objects.
func loadRoleStore(db store.Store, log *slog.Logger) (policy.Store, *policy.Engine, error) {
	rolesFile := os.Getenv("CERTD_ROLES_FILE")

	if db != nil {
		rs := db.Roles()
		if rolesFile != "" {
			roles, err := readRolesFile(rolesFile)
			if err != nil {
				return nil, nil, err
			}
			seeded, err := rs.SeedRolesIfEmpty(roles)
			if err != nil {
				return nil, nil, fmt.Errorf("seed role store: %w", err)
			}
			if seeded {
				log.Info("role store seeded from file", "path", rolesFile, "role_count", len(roles))
			}
		}
		engine := policy.NewEngine(rs)
		log.Info("role store ready (database)", "role_count", len(rs.All()))
		return rs, engine, nil
	}

	if rolesFile == "" {
		log.Warn("CERTD_ROLES_FILE and CERTD_DATABASE_URL unset — role table empty; sign endpoints are permissive and the portal roles page returns 503")
		return nil, nil, nil
	}
	roles, err := readRolesFile(rolesFile)
	if err != nil {
		return nil, nil, err
	}
	st := policy.NewInMemoryStore(roles...)
	engine := policy.NewEngine(st)
	log.Info("role store loaded", "path", rolesFile, "role_count", len(roles))
	return st, engine, nil
}

// openStore opens the persistent backend selected by CERTD_DATABASE_URL: a
// "sqlite:<path>" URL uses the pure-Go SQLite backend (dev/test; ":memory:"
// works as "sqlite::memory:"), anything else is a Postgres DSN. Returns
// (nil, nil) when the env var is unset so callers fall back to the
// in-memory/file stores. The returned Store fronts the role, principal, and
// revocation tables over one connection.
func openStore(ctx context.Context, log *slog.Logger) (store.Store, error) {
	url := os.Getenv("CERTD_DATABASE_URL")
	if url == "" {
		return nil, nil
	}
	if path, ok := strings.CutPrefix(url, "sqlite:"); ok {
		return sqlitestore.Open(ctx, path, log)
	}
	// tlsCfg nil for now — DSN sslmode covers TLS; mTLS-to-Postgres using
	// certd's workload identity can be layered in later (Open takes one).
	return pgstore.Open(ctx, url, nil, log)
}

// readRolesFile reads and decodes a CERTD_ROLES_FILE JSON array.
func readRolesFile(path string) ([]policy.Role, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var roles []policy.Role
	if err := json.Unmarshal(data, &roles); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return roles, nil
}

func loadMTLSStore(db store.Store, log *slog.Logger) (mtls.Store, error) {
	path := os.Getenv("CERTD_MTLS_PRINCIPALS_FILE")

	if db != nil {
		ps := db.Principals()
		if path != "" {
			principals, err := readPrincipalsFile(path)
			if err != nil {
				return nil, err
			}
			seeded, err := ps.SeedPrincipalsIfEmpty(principals)
			if err != nil {
				return nil, fmt.Errorf("seed principal store: %w", err)
			}
			if seeded {
				log.Info("principal store seeded from file", "file", path, "principals", len(principals))
			}
		}
		log.Info("mtls store ready (database)", "principals", len(ps.All()))
		return ps, nil
	}

	if path == "" {
		log.Warn("CERTD_MTLS_PRINCIPALS_FILE unset — mTLS caller auth disabled (not for production)")
		return nil, nil
	}
	principals, err := readPrincipalsFile(path)
	if err != nil {
		return nil, err
	}
	log.Info("mtls store ready", "principals", len(principals), "file", path)
	return mtls.NewInMemoryStore(principals...), nil
}

// readPrincipalsFile reads and decodes a CERTD_MTLS_PRINCIPALS_FILE JSON
// array ({name, san, groups}), mapping each entry's san to the registry
// key (mtls.Principal.MatchedSAN).
func readPrincipalsFile(path string) ([]mtls.Principal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw []struct {
		Name   string   `json:"name"`
		SAN    string   `json:"san"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	principals := make([]mtls.Principal, 0, len(raw))
	for _, r := range raw {
		if r.SAN == "" {
			return nil, fmt.Errorf("entry %q in %s has empty san", r.Name, path)
		}
		principals = append(principals, mtls.Principal{
			Name:       r.Name,
			MatchedSAN: r.SAN,
			Groups:     r.Groups,
		})
	}
	return principals, nil
}

// buildServerTLS builds the *tls.Config used for the inbound HTTPS
// listener. Three modes:
//
//  1. CERTD_API_CERT + CERTD_API_KEY files (hot-reload via GetCertificate).
//  2. Auto-generated self-signed cert (dev fallback, logs a warning).
//
// If CERTD_API_CLIENT_CA is set, mTLS client verification is enabled
// in VerifyClientCertIfGiven mode (route-level handlers decide whether
// to require it).
func buildServerTLS(log *slog.Logger) (*tls.Config, error) {
	certFile := os.Getenv("CERTD_API_CERT")
	keyFile := os.Getenv("CERTD_API_KEY")
	// Inbound mTLS clients are mesh workloads, so the trust anchor for
	// their certs is the workload CA — fall back to CERTD_WORKLOAD_CA
	// when no API-specific client CA is set (same pattern as the NATS
	// CA). Both unset ⇒ client-cert verification stays off.
	clientCAFile := envutil.First("CERTD_API_CLIENT_CA", "CERTD_WORKLOAD_CA")

	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("CERTD_API_CERT and CERTD_API_KEY must both be set or both unset")
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certFile != "" {
		log.Info("tls: using certificate files (hot-reload enabled)", "cert", certFile)
		loader := btls.NewCertLoader(certFile, keyFile)
		cfg.GetCertificate = loader.GetCertificate
	} else {
		log.Warn("tls: no certificate configured, using self-signed (not for production)")
		cert, err := btls.SelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if clientCAFile != "" {
		data, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read CERTD_API_CLIENT_CA: %w", err)
		}
		pool, err := btls.CertPoolFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse CERTD_API_CLIENT_CA: %w", err)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		log.Info("tls: mTLS client CA loaded", "ca", clientCAFile)
	}

	return cfg, nil
}

// loadCastStore wires the asciinema cast directory the portal's
// session-detail page replays from. When CERTD_CAST_DIR is unset,
// returns (nil, nil) so the page hides its player and the
// /sessions/{id}/cast endpoint returns 503.
//
// Typical production setup: the proxy writes casts to a directory
// that's mounted into certd at the same absolute path (NFS export,
// shared volume, etc.). The path the proxy embeds in
// recording.completed events must resolve under CERTD_CAST_DIR.
func loadCastStore(log *slog.Logger) (portal.CastStore, error) {
	dir := os.Getenv("CERTD_CAST_DIR")
	if dir == "" {
		log.Warn("CERTD_CAST_DIR unset — /portal/sessions/{id}/cast disabled (player embed hidden)")
		return nil, nil
	}
	store, err := portal.NewLocalCastStore(dir)
	if err != nil {
		return nil, err
	}
	log.Info("portal cast store configured", "root", store.Root())
	return store, nil
}

// openSSHAuditSource attaches to ssh-proxyd's ssh_audit stream and
// returns the journal source. Returns (nil, nil) when no URL is
// configured. Stream + subject are fixed to match ssh-proxyd's audit
// package constants. TLS material reuses the certd NATS env vars by
// default and falls through to SSH_AUDIT-specific overrides for
// split-broker deployments.
func openSSHAuditSource(log *slog.Logger) (journal.Source, error) {
	if os.Getenv("CERTD_SSH_AUDIT_URL") == "" && os.Getenv("CERTD_NATS_URL") == "" {
		log.Warn("CERTD_SSH_AUDIT_URL unset — /portal/sessions and ssh-proxy audit disabled")
		return nil, nil
	}
	url := envutil.First("CERTD_SSH_AUDIT_URL", "CERTD_NATS_URL")
	tlsCfg, err := btls.FromFiles(
		envutil.First("CERTD_SSH_AUDIT_CERT", "CERTD_NATS_CERT"),
		envutil.First("CERTD_SSH_AUDIT_KEY", "CERTD_NATS_KEY"),
		envutil.First("CERTD_SSH_AUDIT_CA", "CERTD_NATS_CA", "CERTD_WORKLOAD_CA"),
	)
	if err != nil {
		return nil, fmt.Errorf("ssh-audit source TLS: %w", err)
	}
	source, err := jetstream.NewSource(jetstream.SourceConfig{
		URL:        url,
		StreamName: "ssh_audit",
		Subject:    "ssh.audit.events",
		TLS:        tlsCfg,
		Log:        log,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh-audit source: %w", err)
	}
	log.Info("ssh-audit source configured", "url", url)
	return source, nil
}

// newSessionTracker wraps source in the portal session tracker. nil
// source short-circuits to nil so callers don't need to nil-check.
func newSessionTracker(log *slog.Logger, source journal.Source) (*portal.SessionTracker, error) {
	if source == nil {
		return nil, nil
	}
	return portal.NewSessionTracker(portal.SessionTrackerConfig{
		Source:       source,
		SubjectLabel: "ssh.audit.events",
		Log:          log,
	})
}

// newAuditTracker wires the portal audit tracker across whichever
// audit sources the operator has provided. nil sources are skipped;
// when none remain, the tracker is also nil so the page renders 503.
func newAuditTracker(log *slog.Logger, certdSrc, sshSrc journal.Source) (*portal.AuditTracker, error) {
	var sources []portal.AuditSource
	// NoopSource has nothing useful to surface — only include real
	// JetStream attachments.
	if _, isNoop := certdSrc.(journal.NoopSource); certdSrc != nil && !isNoop {
		sources = append(sources, portal.AuditSource{Source: certdSrc, Label: "certd"})
	}
	if sshSrc != nil {
		sources = append(sources, portal.AuditSource{Source: sshSrc, Label: "ssh-proxy"})
	}
	if len(sources) == 0 {
		log.Warn("no audit streams wired — /portal/audit disabled")
		return nil, nil
	}
	tracker, err := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Sources: sources,
		Log:     log,
	})
	if err != nil {
		return nil, err
	}
	log.Info("audit tracker configured", "sources", len(sources))
	return tracker, nil
}
