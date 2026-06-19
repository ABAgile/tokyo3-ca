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
//	CERTD_RATE_LIMIT_RPS    Per-source-IP request rate limit, in requests/second. Unset or 0 ⇒
//	                        rate limiting disabled. In-process, per-replica defense-in-depth
//	                        (shields the auth path + CA signer from a single-source flood); not a
//	                        substitute for an upstream LB/WAF against volumetric DoS. /healthz is
//	                        always exempt.
//	CERTD_RATE_LIMIT_BURST  Token-bucket burst — requests absorbed in an instant before
//	                        throttling. Defaults to 1 when CERTD_RATE_LIMIT_RPS is set.
//	CERTD_TRUSTED_PROXIES   Comma-separated CIDRs (or bare IPs) of reverse proxies whose
//	                        X-Forwarded-For is trusted for rate-limit keying. Unset ⇒ X-Forwarded-For
//	                        is ignored and the peer IP is the key, so the header can't be used to
//	                        spoof a source and evade the limit.
//
//	CERTD_API_CERT       Server TLS certificate PEM path. Hot-reloaded (mtime polled at most
//	                     once per second across handshakes, so rotations land within ~1s).
//	CERTD_API_KEY        Server TLS private key PEM path. Required iff CERTD_API_CERT is set. If
//	                     neither is set an ephemeral self-signed cert is generated (dev only).
//	CERTD_API_CLIENT_CA  Optional CA PEM for verifying inbound mTLS client certs (mesh
//	                     workloads); falls back to CERTD_WORKLOAD_CA. When set, client certs are
//	                     validated against the bundle (VerifyClientCertIfGiven mode). Both unset
//	                     ⇒ client-cert verification off. Hot-reloaded: the bundle is re-read
//	                     (mtime-gated, keep-last-good on a bad file) on every handshake, so a CA
//	                     rotation can widen it to old⊕new and later narrow it with no restart.
//
//	CERTD_WORKLOAD_CA  CA PEM that signs every internal workload cert certd connects to. Used as
//	                   the fallback for CERTD_NATS_CA and CERTD_DB_CA when those vars are unset.
//
//	CERTD_DB_CERT  Client certificate PEM path certd presents to Postgres for mTLS. Unset ⇒ no
//	               client cert; the DSN's sslmode governs TLS (server-auth only). cert/key are a
//	               DB-role credential — they do NOT borrow the workload identity; set them
//	               explicitly to use mTLS.
//	CERTD_DB_KEY   Client key PEM path. Required iff CERTD_DB_CERT is set.
//	CERTD_DB_CA    CA PEM for verifying the Postgres server cert; falls back to CERTD_WORKLOAD_CA
//	               (the shared mesh trust root). Honored even when no client cert is set
//	               (server-auth TLS), so a configured CA always verifies the server rather than
//	               leaving it to the DSN's sslmode. The leaf is re-read per handshake and the CA
//	               pool on mtime, so a rotation lands on the next pool dial without a restart.
//
//	CERTD_CA_KEY             The CA signing key, as one scheme-tagged reference:
//	                         "file:<path>" loads a PKCS#8 Ed25519 PEM; anything else is a KMS key
//	                         ref (ARN / GCP resource name / Vault key path) for a key that never
//	                         leaves the HSM. In single-tier this signs BOTH SSH and X.509; in
//	                         two-tier it signs SSH only (X.509 uses the sealed intermediate). The
//	                         AWS KMS binding (cmd/certd/aws_kms.go) is compiled in by default, so a
//	                         KMS ref works on the stock binary; other backends register via
//	                         RegisterKMSClientFactory (see internal/server/signer/kms). The same
//	                         var drives `certd ca`. Unset ⇒ certd generates an ephemeral key at
//	                         startup — dev only; certs are invalidated on every restart.
//	CERTD_CA_X509_CERT_FILE  X.509-only issuer cert for the workload/SPIFFE certs signed by that
//	                         key. SSH needs no issuer cert — clients trust the key's public half
//	                         via TrustedUserCAKeys. When unset, certd self-signs one at startup
//	                         from the CA signing key — dev only; production should pin a stable
//	                         cert so consumers can verify the chain. When set, hot-reloaded:
//	                         a same-key re-mint (expiry refresh) is picked up live. A cert whose
//	                         public key does NOT match the signing key is refused (kept on the
//	                         old issuer + logged) — a signing-KEY rotation still needs a restart.
//	CERTD_CA_TRUST_BUNDLE    PEM served as-is at GET /api/v1/x509/trust-bundle so workloads can
//	                         pull the current trust anchor (old⊕new during a rotation overlap).
//	                         Defaults to CERTD_CA_ROOT_CERT_FILE (the two-tier anchor) when set,
//	                         else CERTD_CA_X509_CERT_FILE (the single-tier issuer = anchor); read
//	                         per request; unauthenticated (CA certs are public). Empty ⇒ 503.
//	CERTD_CA_X509_CERT_CN    Subject CN for the self-signed startup CA cert. Default
//	                         "tokyo3-ca".
//
//	CERTD_CA_SEALED_KEY_FILE Base64 seal-ciphertext of the X.509 intermediate's PKCS#8 private key
//	                         (produced by `certd ca issue-intermediate`). When set (with
//	                         CERTD_CA_SEAL_KEY), certd unseals it into memory at boot and signs
//	                         X.509 leaves with the intermediate — so the asymmetric ROOT key stays
//	                         offline. SSH keeps signing with CERTD_CA_KEY. Unset ⇒
//	                         single-tier: X.509 signs with the same key as SSH.
//	CERTD_CA_SEAL_KEY        Seal key that wraps the sealed intermediate key (Decrypt at boot).
//	                         A bare KMS key ref (alias / uuid / arn) uses KMS; "file:<path>" uses a
//	                         local AES-256 key (DEV ONLY — logs a loud warning). Required iff
//	                         CERTD_CA_SEALED_KEY_FILE is set.
//	CERTD_CA_ROOT_CERT_FILE  Root cert PEM (the trust anchor consumers pin). When set, certd
//	                         verifies at boot that CERTD_CA_X509_CERT_FILE (the intermediate)
//	                         chains to it and is in-validity, failing closed otherwise, and warns
//	                         as the intermediate nears expiry.
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
//	CERTD_PORTAL_OIDC_ISSUER         When set (with the other CERTD_PORTAL_OIDC_* vars +
//	                                 CERTD_PORTAL_SESSION_KEY), the portal runs native browser
//	                                 OIDC login (Authorization-Code + PKCE) instead of HTTP Basic,
//	                                 attributing mutations to the signed-in user. The portal is a
//	                                 SEPARATE OIDC client from the sign path.
//	CERTD_PORTAL_OIDC_CLIENT_ID      The portal's registered OIDC client_id (= ID-token audience).
//	CERTD_PORTAL_OIDC_CLIENT_SECRET  The confidential-client secret (client_secret_post).
//	CERTD_PORTAL_OIDC_REDIRECT_URL   Absolute callback URL — https://<certd>/portal/auth/callback —
//	                                 registered as a redirect URI on the IdP client.
//	CERTD_PORTAL_ADMIN_GROUP         Group claim required for portal access. Default
//	                                 "ca-portal-admin" (mint it as a SCIM group in the IdP and
//	                                 assign admins). Empty ⇒ any authenticated user may access.
//	CERTD_PORTAL_SESSION_KEY         64-hex-char (32-byte) key sealing the portal session + flow
//	                                 cookies (AES-256-GCM). Required to enable OIDC login; generate
//	                                 with crypto.GenerateKEK. Rotating it invalidates live sessions.
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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/cli"
	"github.com/abagile/tokyo3-base/crypto"
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/guard"
	"github.com/abagile/tokyo3-base/httpauth"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/oidc"
	"github.com/abagile/tokyo3-base/run"
	"github.com/abagile/tokyo3-base/tls/reloader"
	"github.com/abagile/tokyo3-base/version"
	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/reconcile"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
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
	root.AddCommand(serveCmd(), versionCmd(), caCmd(), reconcileCmd())
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

	rlRPS, err := envutil.Float("CERTD_RATE_LIMIT_RPS")
	if err != nil {
		return fmt.Errorf("CERTD_RATE_LIMIT_RPS: %w", err)
	}
	rlBurst, err := envutil.Int("CERTD_RATE_LIMIT_BURST")
	if err != nil {
		return fmt.Errorf("CERTD_RATE_LIMIT_BURST: %w", err)
	}
	trustedProxies, err := envutil.CIDRList("CERTD_TRUSTED_PROXIES")
	if err != nil {
		return fmt.Errorf("CERTD_TRUSTED_PROXIES: %w", err)
	}
	if rlRPS > 0 {
		log.Info("rate limiting enabled", "rps", rlRPS, "burst", rlBurst, "trusted_proxies", len(trustedProxies))
	}

	caSigner, err := loadCASigner(ctx, log)
	if err != nil {
		return fmt.Errorf("load CA signer: %w", err)
	}
	log.Info("ca signer ready", "signer", caSigner.Description())

	// X.509 leaves may sign under a separate, in-memory intermediate key
	// (unsealed from KMS) so the asymmetric root stays offline; SSH keeps
	// signing with caSigner. Falls back to caSigner when no sealed key is
	// configured (single-tier).
	x509Signer, err := loadX509Signer(ctx, log, caSigner)
	if err != nil {
		return fmt.Errorf("load X.509 signer: %w", err)
	}

	auditSink, err := cli.AuditSink[audit.Entry](rt, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer guard.Close(auditSink)
	auditSrc, err := cli.AuditSource(rt, audit.StreamName, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit source: %w", err)
	}
	defer guard.Close(auditSrc)

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
	db, err := openStore(ctx, rt.DB, log)
	if err != nil {
		return fmt.Errorf("open store database: %w", err)
	}
	if db != nil {
		defer guard.Close(db)
	}

	mtlsStore, err := loadMTLSStore(db, log)
	if err != nil {
		return fmt.Errorf("mtls store: %w", err)
	}

	x509IssuerCert, x509IssuerReload, err := loadX509Issuer(log, x509Signer)
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

	// AuditTracker tails certd's own audit stream (cert issuance,
	// denial, revocation) for the /portal/audit viewer. The SSH
	// data-plane's own access-audit view lives in ssh-proxyd's portal.
	auditTracker, err := newAuditTracker(log, auditSrc)
	if err != nil {
		return fmt.Errorf("audit tracker: %w", err)
	}
	var auditStore portal.AuditStore
	if auditTracker != nil {
		auditStore = auditTracker
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

	portalOIDC, err := loadPortalOIDC(log)
	if err != nil {
		return fmt.Errorf("portal oidc: %w", err)
	}

	portalSrv, err := portal.New(portal.Config{
		Version:         Version,
		Log:             log,
		RoleStore:       roleStore,
		HostStore:       hostStore,
		AuditStore:      auditStore,
		RevocationStore: krlStore,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: os.Getenv("CERTD_PORTAL_USERNAME"),
			Password: os.Getenv("CERTD_PORTAL_PASSWORD"),
			Realm:    envutil.Or("CERTD_PORTAL_REALM", "certd portal"),
		},
		OIDC: portalOIDC,
	})
	if err != nil {
		return fmt.Errorf("portal: %w", err)
	}

	srv, err := api.New(api.Config{
		Log:              log,
		CASigner:         caSigner,
		X509Signer:       x509Signer,
		X509IssuerCert:   x509IssuerCert,
		X509IssuerReload: x509IssuerReload,
		// Anchor served at /api/v1/x509/trust-bundle: explicit override, else the
		// anchor consumers pin — the ROOT in two-tier (CERTD_CA_ROOT_CERT_FILE),
		// the issuer in single-tier (CERTD_CA_X509_CERT_FILE). Defaulting to the
		// intermediate would make pull-based consumers anchor it instead of the root.
		TrustBundlePath: envutil.First("CERTD_CA_TRUST_BUNDLE", "CERTD_CA_ROOT_CERT_FILE", "CERTD_CA_X509_CERT_FILE"),
		SSHCAKeysPath:   os.Getenv("CERTD_SSH_CA_KEYS_FILE"),
		Policy:          policyEngine,
		OIDCVerifier:    oidcVerifier,
		MTLSStore:       mtlsStore,
		Audit:           auditSink,
		AuditSource:     auditSrc,
		Portal:          portalSrv,
		KRL:             krlStore,
		ActiveCertStore: activeCerts,
		RateLimitRPS:    rlRPS,
		RateLimitBurst:  rlBurst,
		TrustedProxies:  trustedProxies,
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

	if auditTracker != nil {
		guard.Go(log, "audit-tracker", func() {
			if err := auditTracker.Run(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn("audit tracker exited", "err", err)
			}
		})
	}

	log.Info("listening", "addr", addr)
	if err := run.Group(rootCtx, run.HTTPServer(httpSrv, 10*time.Second, true)); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("stopped")
	return nil
}

// ── reconcile ───────────────────────────────────────────────────────────────

type reconcileOpts struct {
	apply          bool
	prune          bool
	rolesOnly      bool
	principalsOnly bool
	adopt          bool
	actor          string
}

func reconcileCmd() *cobra.Command {
	o := reconcileOpts{prune: true}
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Reconcile the role/principal tables to the config files (GitOps)",
		Long: "Diff CERTD_ROLES_FILE / CERTD_MTLS_PRINCIPALS_FILE against the\n" +
			"persistent store (CERTD_DATABASE_URL) and apply the difference.\n\n" +
			"Config is authoritative over rows it owns (source=config): they are\n" +
			"added, updated, and pruned to match the files. Portal-created rows\n" +
			"(source=portal) are never pruned; a name/SAN collision is reported as\n" +
			"a conflict and skipped unless --adopt takes ownership of it.\n\n" +
			"Dry-run by default — prints the plan and changes nothing. Pass --apply\n" +
			"to write. Every applied change lands with its audit entry in the same\n" +
			"transaction (delivered to the ca_audit stream by a running certd serve).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReconcile(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.apply, "apply", false, "apply the changes (default: dry-run, print only)")
	f.BoolVar(&o.prune, "prune", true, "delete config-owned rows absent from the files")
	f.BoolVar(&o.rolesOnly, "roles-only", false, "reconcile only the role table")
	f.BoolVar(&o.principalsOnly, "principals-only", false, "reconcile only the principal registry")
	f.BoolVar(&o.adopt, "adopt", false, "take ownership of portal-created rows that collide with the files")
	f.StringVar(&o.actor, "actor", "", "audit actor for config:<actor> (default: hostname)")
	return cmd
}

func runReconcile(ctx context.Context, o reconcileOpts) error {
	if o.rolesOnly && o.principalsOnly {
		return errors.New("--roles-only and --principals-only are mutually exclusive")
	}
	rt := cli.App{Name: appName, EnvPrefix: "CERTD"}.Setup(ctx)
	defer rt.Shutdown()
	log := rt.Log

	db, err := openStore(ctx, rt.DB, log)
	if err != nil {
		return fmt.Errorf("open store database: %w", err)
	}
	if db == nil {
		return errors.New("reconcile requires CERTD_DATABASE_URL (no persistent store configured)")
	}
	defer guard.Close(db)

	actor := o.actor
	if actor == "" {
		actor, _ = os.Hostname()
		if actor == "" {
			actor = "reconcile"
		}
	}

	var rolePlan reconcile.RolePlan
	var principalPlan reconcile.PrincipalPlan

	if !o.principalsOnly {
		path := os.Getenv("CERTD_ROLES_FILE")
		if path == "" {
			return errors.New("CERTD_ROLES_FILE unset; nothing to reconcile for roles (use --principals-only to skip)")
		}
		roles, err := readRolesFile(path)
		if err != nil {
			return err
		}
		recs, err := db.Roles().AllWithSource()
		if err != nil {
			return fmt.Errorf("read role table: %w", err)
		}
		rolePlan = reconcile.DiffRoles(roles, recs, o.adopt)
	}
	if !o.rolesOnly {
		path := os.Getenv("CERTD_MTLS_PRINCIPALS_FILE")
		if path == "" {
			return errors.New("CERTD_MTLS_PRINCIPALS_FILE unset; nothing to reconcile for principals (use --roles-only to skip)")
		}
		principals, err := readPrincipalsFile(path)
		if err != nil {
			return err
		}
		recs, err := db.Principals().AllWithSource()
		if err != nil {
			return fmt.Errorf("read principal registry: %w", err)
		}
		principalPlan = reconcile.DiffPrincipals(principals, recs, o.adopt)
	}

	printReconcilePlan(os.Stdout, rolePlan, principalPlan, o.prune)
	warnConflicts(log, rolePlan.Conflicts, principalPlan.Conflicts, o.adopt)

	if !o.apply {
		if rolePlan.Empty() && principalPlan.Empty() {
			log.Info("reconcile: already in sync — nothing to apply")
		} else {
			log.Info("reconcile: dry-run — re-run with --apply to write the changes above")
		}
		return nil
	}

	roleApplied, err := rolePlan.ApplyRoles(db.Roles(), o.prune)
	if err != nil {
		return fmt.Errorf("apply roles: %w", err)
	}
	principalApplied, err := principalPlan.ApplyPrincipals(db.Principals(), o.prune)
	if err != nil {
		return fmt.Errorf("apply principals: %w", err)
	}

	// The applied change is recorded in the structured log (shipped to NATS
	// via applog when configured) — the audit trail for reconcile runs.
	log.Info("reconcile: applied",
		"roles_added", roleApplied.Added, "roles_updated", roleApplied.Updated, "roles_pruned", roleApplied.Pruned,
		"principals_added", principalApplied.Added, "principals_updated", principalApplied.Updated, "principals_pruned", principalApplied.Pruned,
		"actor", actor)
	return nil
}

// printReconcilePlan renders the human-readable diff.
func printReconcilePlan(w io.Writer, rp reconcile.RolePlan, pp reconcile.PrincipalPlan, prune bool) {
	line := func(kind string, items []string) {
		for _, it := range items {
			fmt.Fprintf(w, "  %-8s %s\n", kind, it)
		}
	}
	fmt.Fprintln(w, "roles:")
	line("add", roleNames(rp.Add))
	line("update", roleNames(rp.Update))
	if prune {
		line("prune", rp.Prune)
	} else {
		line("orphan", rp.Prune) // would prune, but --prune=false
	}
	line("conflict", rp.Conflicts)
	fmt.Fprintln(w, "principals:")
	line("add", principalSANs(pp.Add))
	line("update", principalSANs(pp.Update))
	if prune {
		line("prune", pp.Prune)
	} else {
		line("orphan", pp.Prune)
	}
	line("conflict", pp.Conflicts)
}

func warnConflicts(log *slog.Logger, roleConflicts, principalConflicts []string, adopt bool) {
	if adopt || (len(roleConflicts) == 0 && len(principalConflicts) == 0) {
		return
	}
	log.Warn("reconcile: skipping portal-owned rows that collide with the config files; re-run with --adopt to take ownership",
		"role_conflicts", roleConflicts, "principal_conflicts", principalConflicts)
}

func roleNames(rs []policy.Role) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

func principalSANs(ps []mtls.Principal) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.MatchedSAN
	}
	return out
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
// seam (resolveCASigner): CERTD_CA_KEY is one scheme-tagged ref — "file:<path>"
// for a PKCS#8 Ed25519 PEM, or a KMS key ref (ARN / resource name) for a
// KMS-backed key (needs a KMS-bound build). When unset, certd generates an
// ephemeral keypair and warns that issued certs won't survive a restart.
func loadCASigner(ctx context.Context, log *slog.Logger) (signer.Signer, error) {
	keyRef := os.Getenv("CERTD_CA_KEY")
	if keyRef == "" {
		log.Warn("CERTD_CA_KEY unset — generating ephemeral CA key (not for production)")
		return signer.NewEphemeralEd25519()
	}
	return resolveCASigner(ctx, keyRef)
}

// loadX509Signer returns the signer certd uses for X.509 leaf issuance. When a
// sealed intermediate key is configured (CERTD_CA_SEALED_KEY_FILE +
// CERTD_CA_SEAL_KEY), it is unsealed into memory and returned — so the
// asymmetric root key never touches the online issuance path and certd signs
// leaves with the intermediate. Otherwise X.509 falls back to caSigner
// (single-tier: one key signs both SSH and X.509).
func loadX509Signer(ctx context.Context, log *slog.Logger, caSigner signer.Signer) (signer.Signer, error) {
	sealedPath := os.Getenv("CERTD_CA_SEALED_KEY_FILE")
	sealKey := os.Getenv("CERTD_CA_SEAL_KEY")
	if sealedPath == "" && sealKey == "" {
		return caSigner, nil // single-tier
	}
	if sealedPath == "" || sealKey == "" {
		return nil, errors.New("two-tier X.509 needs both CERTD_CA_SEALED_KEY_FILE and CERTD_CA_SEAL_KEY (one is set, the other is not)")
	}
	raw, err := os.ReadFile(sealedPath)
	if err != nil {
		return nil, fmt.Errorf("read sealed intermediate key %s: %w", sealedPath, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("sealed intermediate key %s: not base64: %w", sealedPath, err)
	}
	sl, err := resolveSealer(ctx, sealKey)
	if err != nil {
		return nil, err
	}
	keyPEM, err := sl.Decrypt(ctx, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unseal intermediate key: %w", err)
	}
	// The decrypted PKCS#8 PEM is plaintext key material. Wipe the buffer once
	// it's parsed — LoadFromPKCS8PEM copies what it keeps, so the returned
	// signer is unaffected. Best-effort (Go's GC may have already moved the
	// bytes, and the key still lives unprotected on the heap inside the signer
	// — see docs/THREAT_MODEL.md §S2), but it shrinks the window a memory dump can
	// catch the serialized key in.
	defer func() {
		for i := range keyPEM {
			keyPEM[i] = 0
		}
	}()
	sig, err := signer.LoadFromPKCS8PEM(keyPEM, "in-memory intermediate (sealed: "+sealedPath+")")
	if err != nil {
		return nil, fmt.Errorf("load unsealed intermediate key: %w", err)
	}
	log.Info("x509 intermediate signer ready (unsealed from KMS)", "signer", sig.Description())
	return sig, nil
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

// loadPortalOIDC builds the portal's native-OIDC login config from
// CERTD_PORTAL_OIDC_* env. All of issuer / client-id / client-secret /
// redirect-url / session-key must be set to enable it; any unset ⇒ disabled
// (the portal falls back to the Basic-auth gate). The portal client is a
// SEPARATE OIDC client from the sign path, so it gets its own lazy verifier
// keyed to its own audience (client_id).
func loadPortalOIDC(log *slog.Logger) (portal.OIDCConfig, error) {
	issuer := os.Getenv("CERTD_PORTAL_OIDC_ISSUER")
	clientID := os.Getenv("CERTD_PORTAL_OIDC_CLIENT_ID")
	secret := os.Getenv("CERTD_PORTAL_OIDC_CLIENT_SECRET")
	redirect := os.Getenv("CERTD_PORTAL_OIDC_REDIRECT_URL")
	keyHex := os.Getenv("CERTD_PORTAL_SESSION_KEY")
	adminGroup := envutil.Or("CERTD_PORTAL_ADMIN_GROUP", "ca-portal-admin")

	if issuer == "" && clientID == "" && secret == "" && redirect == "" && keyHex == "" {
		return portal.OIDCConfig{}, nil // not configured — Basic-auth path
	}
	if issuer == "" || clientID == "" || secret == "" || redirect == "" || keyHex == "" {
		return portal.OIDCConfig{}, fmt.Errorf("portal OIDC is partially configured: CERTD_PORTAL_OIDC_ISSUER, _CLIENT_ID, _CLIENT_SECRET, _REDIRECT_URL and CERTD_PORTAL_SESSION_KEY must all be set together")
	}
	key, err := crypto.ParseKEK(keyHex)
	if err != nil {
		return portal.OIDCConfig{}, fmt.Errorf("CERTD_PORTAL_SESSION_KEY: %w (want 64 hex chars / 32 bytes — generate with crypto.GenerateKEK)", err)
	}
	v, err := oidc.NewLazyHTTPVerifier(issuer, clientID)
	if err != nil {
		return portal.OIDCConfig{}, err
	}
	log.Info("portal oidc login enabled (lazy)", "issuer", issuer, "client_id", clientID, "admin_group", adminGroup)
	return portal.OIDCConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURL:  redirect,
		AdminGroup:   adminGroup,
		Verifier:     v,
		SessionKey:   key,
	}, nil
}

// issuerRotateWarnWindow is how close to the issuer cert's NotAfter loadX509Issuer
// starts logging a rotate-soon warning at boot. Comfortably larger than the max
// leaf TTL so an operator sees it well before the near-expiry sign refusal bites.
const issuerRotateWarnWindow = 14 * 24 * time.Hour

// loadX509Issuer returns the cert certd signs X.509 leaves under, plus an
// optional hot-reload getter. Its public key must match x509Signer (the
// reloader's issuerLoader enforces this, so a new-key issuer is refused live —
// a signing-key rotation still needs a restart). When CERTD_CA_X509_CERT_FILE
// is unset, certd self-signs a fresh cert at startup (dev only; getter nil).
//
// In a two-tier deployment the issuer is the intermediate and x509Signer is the
// unsealed intermediate key. When CERTD_CA_ROOT_CERT_FILE is also set, certd
// verifies at boot that the intermediate chains to that root and is in-validity,
// failing closed otherwise — so a misconfigured root/intermediate pair is caught
// at startup rather than breaking every leaf at the first handshake.
func loadX509Issuer(log *slog.Logger, x509Signer signer.Signer) (*x509.Certificate, func() *x509.Certificate, error) {
	if path := os.Getenv("CERTD_CA_X509_CERT_FILE"); path != "" {
		rl, err := newPEMReloader(path, "X.509 issuer cert", log, issuerLoader(x509Signer.Public()))
		if err != nil {
			return nil, nil, fmt.Errorf("CERTD_CA_X509_CERT_FILE: %w", err)
		}
		cert := rl.get()
		if rootPath := os.Getenv("CERTD_CA_ROOT_CERT_FILE"); rootPath != "" {
			root, err := loadIssuerCert(rootPath)
			if err != nil {
				return nil, nil, fmt.Errorf("CERTD_CA_ROOT_CERT_FILE: %w", err)
			}
			if err := verifyIssuerChainsToRoot(cert, root); err != nil {
				return nil, nil, err
			}
			warnIfIssuerNearExpiry(log, cert)
			log.Info("x509 issuer ready", "source", "file", "path", path, "cn", cert.Subject.CommonName,
				"chains_to_root", true, "not_after", cert.NotAfter, "hot_reload", true)
			return cert, rl.get, nil
		}
		log.Info("x509 issuer ready", "source", "file", "path", path, "cn", cert.Subject.CommonName, "hot_reload", true)
		return cert, rl.get, nil
	}
	cn := envutil.Or("CERTD_CA_X509_CERT_CN", "tokyo3-ca")
	cert, err := x509engine.NewSelfSignedCA(rand.Reader, x509Signer, cn)
	if err != nil {
		return nil, nil, err
	}
	log.Warn("CERTD_CA_X509_CERT_FILE unset — generated self-signed CA cert at startup (not for production)",
		"cn", cn, "not_after", cert.NotAfter)
	return cert, nil, nil
}

// verifyIssuerChainsToRoot confirms the issuer cert (an intermediate) is signed
// by root and that both are within their validity windows now — a boot-time,
// fail-closed guard against a misconfigured root/intermediate pair.
func verifyIssuerChainsToRoot(issuer, root *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := issuer.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("CERTD_CA_X509_CERT_FILE does not chain to CERTD_CA_ROOT_CERT_FILE (or one is expired): %w", err)
	}
	return nil
}

// warnIfIssuerNearExpiry logs a rotate-soon warning when the issuer is within
// issuerRotateWarnWindow of its NotAfter.
func warnIfIssuerNearExpiry(log *slog.Logger, cert *x509.Certificate) {
	if remaining := time.Until(cert.NotAfter); remaining < issuerRotateWarnWindow {
		log.Warn("X.509 issuer cert nearing expiry — rotate the intermediate soon",
			"not_after", cert.NotAfter, "remaining", remaining.String())
	}
}

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
// guard.Close (a no-op for the in-memory store). The file
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
func openStore(ctx context.Context, db cli.DB, log *slog.Logger) (store.Store, error) {
	if db.URL == "" {
		return nil, nil
	}
	if path, ok := strings.CutPrefix(db.URL, "sqlite:"); ok {
		return sqlitestore.Open(ctx, path, log)
	}
	tlsCfg, err := dbClientTLS(db)
	if err != nil {
		return nil, fmt.Errorf("db client TLS: %w", err)
	}
	return pgstore.Open(ctx, db.URL, tlsCfg, log)
}

// dbClientTLS builds the client-cert TLS config certd presents to Postgres
// from CERTD_DB_CERT/KEY (falling back to the daemon's workload identity,
// CERTD_WORKLOAD_CERT/KEY) and CERTD_DB_CA (→ CERTD_WORKLOAD_CA). With a
// cert+key pair the leaf is re-read on every handshake and the CA pool on
// mtime change, so a cert-agentd rotation of the short-TTL workload cert lands
// on the next pool dial without a restart — no poll loop needed
// (SetConnMaxLifetime recycles pooled conns within its window). When only
// CERTD_DB_CA is set (no client cert), the returned config still verifies the
// Postgres server against that CA (fail-secure); both unset ⇒ (nil, nil), the
// DSN's sslmode then governs TLS.
func dbClientTLS(m cli.DB) (*tls.Config, error) {
	return reloader.ClientTLS(m.CertFile, m.KeyFile, m.CAFile)
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

// loadMTLSStore returns the workload-identity registry parsed from
// CERTD_MTLS_PRINCIPALS_FILE. Returns (nil, nil) when the env var is
// unset, disabling the mTLS auth path. Future slice swaps the
// file-backed implementation for a Postgres-backed Store managed by
// the admin portal — same interface, no API-layer changes.
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
	return reloader.ServerTLS(reloader.ServerTLSConfig{
		CertFile:     os.Getenv("CERTD_API_CERT"),
		KeyFile:      os.Getenv("CERTD_API_KEY"),
		ClientCAFile: envutil.First("CERTD_API_CLIENT_CA", "CERTD_WORKLOAD_CA"),
		MinVersion:   tls.VersionTLS12,
		Log:          log,
	})
}

// newAuditTracker wires the portal audit tracker over certd's own
// audit stream. A nil or NoopSource source (no NATS configured) yields
// a nil tracker so /portal/audit renders 503.
func newAuditTracker(log *slog.Logger, certdSrc journal.Source) (*portal.AuditTracker, error) {
	if _, isNoop := certdSrc.(journal.NoopSource); certdSrc == nil || isNoop {
		log.Warn("no audit stream wired — /portal/audit disabled")
		return nil, nil
	}
	tracker, err := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Source: certdSrc,
		Log:    log,
	})
	if err != nil {
		return nil, err
	}
	log.Info("audit tracker configured")
	return tracker, nil
}
