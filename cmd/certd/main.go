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
//	CERTD_ADDR              HTTPS listen address (default ":8443").
//
//	CERTD_API_CERT          Server TLS certificate PEM path. Hot-reloaded
//	                        (mtime polled at most once per second across
//	                        handshakes, so rotations land within ~1s).
//	CERTD_API_KEY           Server TLS private key PEM path. Required iff
//	                        CERTD_API_CERT is set. If neither is set an
//	                        ephemeral self-signed cert is generated (dev only).
//	CERTD_API_CLIENT_CA     Optional CA PEM for client cert verification (mTLS).
//	                        When set, client certs are validated against this
//	                        bundle (VerifyClientCertIfGiven mode).
//
//	CERTD_WORKLOAD_CA       CA PEM that signs every internal workload cert
//	                        certd connects to (NATS, future DB). Used as the
//	                        fallback for CERTD_NATS_CA when that var is unset.
//
//	CERTD_CA_KEY_FILE       PKCS#8-encoded Ed25519 private key PEM path used
//	                        as the CA signing key. When unset, certd generates
//	                        an ephemeral key at startup — dev only; certs are
//	                        invalidated on every restart.
//
//	CERTD_NATS_URL          NATS server URL (e.g., nats://nats:4222 or
//	                        tls://nats:4222). Empty disables JetStream
//	                        publishing — audit sink becomes [audit.NoopSink],
//	                        audit source becomes [journal.NoopSource].
//	CERTD_NATS_CERT         Publisher client certificate PEM path (mTLS).
//	CERTD_NATS_KEY          Publisher client key PEM path. Required iff
//	                        CERTD_NATS_CERT is set.
//	CERTD_NATS_CA           CA certificate PEM path for verifying the NATS
//	                        server cert. Falls back to CERTD_WORKLOAD_CA.
//
//	CERTD_OIDC_ISSUER       authd public URL (e.g., https://auth.example.com).
//	                        When set together with CERTD_OIDC_AUDIENCE,
//	                        sign endpoints require a valid Authorization:
//	                        Bearer token and derive the caller's groups
//	                        from its claims. When unset, body groups are
//	                        used (for tests and pre-prod).
//	CERTD_OIDC_AUDIENCE     The `aud` claim authd embeds on every token
//	                        minted for certd (the OIDC client_id authd
//	                        registers for this service). Required when
//	                        CERTD_OIDC_ISSUER is set.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-base/applog"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/jetstream"
	bnats "github.com/abagile/tokyo3-base/nats"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

const appName = "certd"

// Version is overridden at build time via -ldflags "-X main.Version=...".
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
	root.AddCommand(serveCmd(), versionCmd())
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
	log, drainLog := newAppLogger()
	defer drainLog()

	addr := envOr("CERTD_ADDR", ":8443")

	caSigner, err := loadCASigner(log)
	if err != nil {
		return fmt.Errorf("load CA signer: %w", err)
	}
	log.Info("ca signer ready", "signer", caSigner.Description())

	auditSink, err := openAuditSink(log)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer closeIfCloser(auditSink)
	auditSrc, err := openAuditSource(log)
	if err != nil {
		return fmt.Errorf("audit source: %w", err)
	}
	defer closeIfCloser(auditSrc)

	tlsCfg, err := buildServerTLS(log)
	if err != nil {
		return fmt.Errorf("server tls: %w", err)
	}

	oidcVerifier, err := loadOIDCVerifier(ctx, log)
	if err != nil {
		return fmt.Errorf("oidc verifier: %w", err)
	}

	srv, err := api.New(api.Config{
		Log:          log,
		CASigner:     caSigner,
		OIDCVerifier: oidcVerifier,
		Audit:        auditSink,
		AuditSource:  auditSrc,
		Version:      Version,
	})
	if err != nil {
		return fmt.Errorf("api server: %w", err)
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	rootCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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
			fmt.Printf("%s %s\n", appName, Version)
		},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envFirst returns the value of the first non-empty env var among keys.
// Used for chained fallbacks (e.g., CERTD_NATS_CA → CERTD_WORKLOAD_CA).
func envFirst(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// openLogNATS dials a plain NATS connection used by applog's
// WithAsyncNats writer to ship operational log lines on subject
// "app_log.certd". Reuses the CERTD_NATS_URL / CERT / KEY / CA env vars
// (CA falls back to CERTD_WORKLOAD_CA). Returns (nil, nil) when the URL
// is unset — log shipping is disabled and applog falls back to
// stdout-only. On dial failure returns (nil, err); callers treat it as
// non-fatal observability and surface a warning.
func openLogNATS() (*nats.Conn, error) {
	url := os.Getenv("CERTD_NATS_URL")
	if url == "" {
		return nil, nil
	}
	nc, err := bnats.Dial(url,
		os.Getenv("CERTD_NATS_CERT"),
		os.Getenv("CERTD_NATS_KEY"),
		envFirst("CERTD_NATS_CA", "CERTD_WORKLOAD_CA"),
		nats.Timeout(1*time.Second),
		nats.DrainTimeout(500*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("log shipping: %w", err)
	}
	return nc, nil
}

// newAppLogger builds the structured logger for a certd subcommand.
// Ships log lines async to NATS subject "app_log.certd" when
// CERTD_NATS_URL is set. Returns the logger and a drain callback the
// caller defers — no-op when log shipping is disabled.
func newAppLogger() (*slog.Logger, func()) {
	logNATS, logNATSErr := openLogNATS()
	drain := func() {}
	if logNATS != nil {
		drain = func() { _ = logNATS.Drain() }
	}
	writerOpts := []applog.WriterOption{applog.WithStdout()}
	if logNATS != nil {
		writerOpts = append(writerOpts, applog.WithAsyncNats(logNATS))
	}
	log, _ := applog.AppLogger(appName, writerOpts...)
	if logNATSErr != nil {
		log.Warn("operational log shipping disabled", "err", logNATSErr)
	} else if logNATS != nil {
		log.Info("operational logs shipping to NATS", "subject", "app_log."+appName)
	}
	return log, drain
}

// loadCASigner returns the CA signing primitive. CERTD_CA_KEY_FILE
// points at a PKCS#8 Ed25519 PEM file; when unset, certd generates an
// ephemeral keypair and warns that issued certs won't survive a restart.
func loadCASigner(log *slog.Logger) (signer.Signer, error) {
	if path := os.Getenv("CERTD_CA_KEY_FILE"); path != "" {
		return signer.LoadEd25519FromPEMFile(path)
	}
	log.Warn("CERTD_CA_KEY_FILE not set — generating ephemeral CA key (not for production)")
	return signer.NewEphemeralEd25519()
}

// loadOIDCVerifier returns a token verifier for inbound bearer tokens
// when CERTD_OIDC_ISSUER + CERTD_OIDC_AUDIENCE are both set. Either
// alone is an error (asymmetric config), and both unset returns nil
// (no OIDC — sign endpoints fall back to body groups).
func loadOIDCVerifier(ctx context.Context, log *slog.Logger) (oidc.TokenVerifier, error) {
	issuer := os.Getenv("CERTD_OIDC_ISSUER")
	audience := os.Getenv("CERTD_OIDC_AUDIENCE")
	if issuer == "" && audience == "" {
		log.Warn("CERTD_OIDC_ISSUER + CERTD_OIDC_AUDIENCE unset — token verification disabled; sign endpoints use body groups (not for production)")
		return nil, nil
	}
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("CERTD_OIDC_ISSUER and CERTD_OIDC_AUDIENCE must both be set or both unset")
	}
	v, err := oidc.NewHTTPVerifier(ctx, issuer, audience)
	if err != nil {
		return nil, err
	}
	log.Info("oidc verifier ready", "issuer", issuer, "audience", audience)
	return v, nil
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
	clientCAFile := os.Getenv("CERTD_API_CLIENT_CA")

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

// openAuditSink builds the JetStream publisher Sink from CERTD_NATS_URL
// and the CERTD_NATS_CERT/KEY/CA env vars. When the URL is empty,
// returns [audit.NoopSink] — keeps the dev/no-NATS path working.
func openAuditSink(log *slog.Logger) (audit.Sink, error) {
	url := os.Getenv("CERTD_NATS_URL")
	if url == "" {
		log.Warn("CERTD_NATS_URL not set — audit sink is no-op; not for production")
		return audit.NoopSink, nil
	}
	tlsCfg, err := btls.FromFiles(
		os.Getenv("CERTD_NATS_CERT"),
		os.Getenv("CERTD_NATS_KEY"),
		envFirst("CERTD_NATS_CA", "CERTD_WORKLOAD_CA"),
	)
	if err != nil {
		return nil, fmt.Errorf("nats audit TLS: %w", err)
	}
	if tlsCfg != nil {
		log.Info("audit sink: NATS JetStream with mTLS", "url", url)
	} else {
		log.Warn("audit sink: CERTD_NATS_CERT not set — connecting without mTLS (not for production)")
	}
	jSink, err := jetstream.NewSink(jetstream.SinkConfig{
		URL:     url,
		Subject: audit.Subject,
		TLS:     tlsCfg,
	})
	if err != nil {
		return nil, err
	}
	return journal.NewJSONSink[audit.Entry](jSink), nil
}

// openAuditSource is the read-side counterpart of openAuditSink:
// returns a journal.Source attached to the same NATS URL + stream +
// subject so the portal admin /portal/admin/audit page can tail the
// audit log live. When CERTD_NATS_URL is empty, returns NoopSource.
func openAuditSource(log *slog.Logger) (journal.Source, error) {
	url := os.Getenv("CERTD_NATS_URL")
	if url == "" {
		log.Warn("CERTD_NATS_URL not set — audit source is no-op; admin audit page will be empty")
		return journal.NoopSource{}, nil
	}
	tlsCfg, err := btls.FromFiles(
		os.Getenv("CERTD_NATS_CERT"),
		os.Getenv("CERTD_NATS_KEY"),
		envFirst("CERTD_NATS_CA", "CERTD_WORKLOAD_CA"),
	)
	if err != nil {
		return nil, fmt.Errorf("nats audit source TLS: %w", err)
	}
	return jetstream.NewSource(jetstream.SourceConfig{
		URL:        url,
		StreamName: audit.StreamName,
		Subject:    audit.Subject,
		TLS:        tlsCfg,
	})
}

// closeIfCloser invokes Close on resources that implement io.Closer,
// silently ignoring values that don't (e.g., NoopSource).
func closeIfCloser(v any) {
	if c, ok := v.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}
