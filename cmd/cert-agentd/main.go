// Command cert-agentd is the tokyo3-ca per-workload credential agent.
//
// Runs on every workload that needs renewable identity credentials.
// Authenticates to certd via the workload's existing mTLS cert, requests
// short-lived SPIFFE X.509 client certs (for mTLS infrastructure),
// writes credentials atomically to known filesystem paths, and renews
// them before expiry. Optionally renders an ssh_config snippet so the
// workload's SSH client picks up newly-issued certificates without
// any external SIGHUP.
//
// Required env vars:
//
//	CERT_AGENTD_CERTD_URL   certd base URL (e.g., https://certd.internal).
//	CERT_AGENTD_CERT        Workload X.509 cert PEM path. Bootstrap cert
//	                        on first run; the renewer overwrites this
//	                        atomically on each successful renewal.
//	CERT_AGENTD_KEY         Matching private key PEM path. Read on
//	                        startup and reused across renewals — only
//	                        the cert rotates, the key is stable.
//	CERT_AGENTD_CA          CA bundle that signs certd's server cert.
//	CERT_AGENTD_SPIFFE_URI  SPIFFE URI to embed in the renewed cert
//	                        (e.g., "spiffe://tokyo3.example/host/db-1").
//	                        certd's role table decides whether the
//	                        caller may obtain it.
//
// Optional env vars:
//
//	CERT_AGENTD_SUBJECT_CN  Optional X.509 Subject CN. Modern verifiers
//	                        ignore CN as identity; populating it just
//	                        makes tooling output friendlier.
//	CERT_AGENTD_TTL_SECONDS Requested validity window. Zero/unset ⇒
//	                        certd's default. Capped by the endpoint's
//	                        hard max and possibly further by policy.
//
// Optional SSH user cert renewal:
//
//	CERT_AGENTD_SSH_USER_CERT       When set together with
//	                                CERT_AGENTD_SSH_USER_KEY and
//	                                CERT_AGENTD_SSH_PRINCIPALS, the
//	                                agent also renews an SSH user
//	                                cert. The key is generated on
//	                                first run (mode 0600); the cert
//	                                lands at this path (mode 0644).
//	CERT_AGENTD_SSH_USER_KEY        Path for the matching SSH private
//	                                key. Reused across renewals once
//	                                generated.
//	CERT_AGENTD_SSH_PRINCIPALS      Comma-separated Unix usernames the
//	                                cert authorizes (e.g.,
//	                                "alice,deployer").
//	CERT_AGENTD_SSH_KEY_ID          KeyID embedded in the cert. Default
//	                                "user:<spiffe-uri-path-tail>".
//	CERT_AGENTD_SSH_TTL_SECONDS     Requested validity window for the
//	                                user cert. Zero ⇒ certd's default.
//
// Optional ssh_config drop-in:
//
//	CERT_AGENTD_SSH_CONFIG_PATH    When set, render an ssh_config
//	                               snippet to this path pointing at
//	                               the SSH user cert/key above. The
//	                               user's main config should Include
//	                               it.
//	CERT_AGENTD_SSH_HOST_PATTERN   Host pattern in the snippet. Default "*".
//	CERT_AGENTD_SSH_PROXY_JUMP     ProxyJump directive (e.g.,
//	                               "alice@proxy.internal:2222").
//	CERT_AGENTD_SSH_USER           SSH login name.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-base/applog"
	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/agent/output"
	"github.com/abagile/tokyo3-ca/internal/agent/renew"
	"github.com/abagile/tokyo3-ca/internal/client"
)

const appName = "cert-agentd"

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
		Short: "tokyo3-ca workload credential agent",
	}
	root.AddCommand(runCmd(), versionCmd())
	return root
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the renewal loop in the foreground",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cmd.Context())
		},
	}
}

func runAgent(ctx context.Context) error {
	log, _ := applog.AppLogger(appName, applog.WithStdout())

	certdURL := mustEnv("CERT_AGENTD_CERTD_URL")
	certPath := mustEnv("CERT_AGENTD_CERT")
	keyPath := mustEnv("CERT_AGENTD_KEY")
	caPath := mustEnv("CERT_AGENTD_CA")
	spiffeURI := mustEnv("CERT_AGENTD_SPIFFE_URI")

	// Bootstrap: load the workload cert + key once for the initial
	// mTLS handshake. The reloader is what TLS actually reads — the
	// renewer's OnRenewed hook calls reloader.Refresh after each
	// successful renewal so the next handshake uses the fresh cert.
	reloader, err := newCertReloader(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("bootstrap cert: %w", err)
	}
	caPool, err := loadCAPool(caPath)
	if err != nil {
		return fmt.Errorf("CA bundle: %w", err)
	}
	tlsCfg := &tls.Config{
		GetClientCertificate: reloader.GetClientCertificate,
		RootCAs:              caPool,
		MinVersion:           tls.VersionTLS12,
	}
	certdClient, err := client.NewClient(certdURL, tlsCfg)
	if err != nil {
		return fmt.Errorf("certd client: %w", err)
	}
	log.Info("certd client configured", "url", certdURL,
		"bootstrap_cert", certPath, "bootstrap_key", keyPath)

	var ttl time.Duration
	if v := os.Getenv("CERT_AGENTD_TTL_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return fmt.Errorf("CERT_AGENTD_TTL_SECONDS %q: must be positive integer", v)
		}
		ttl = time.Duration(n) * time.Second
	}

	renewer, err := renew.New(renew.Config{
		Signer:            certdClient,
		SPIFFEURI:         spiffeURI,
		SubjectCommonName: os.Getenv("CERT_AGENTD_SUBJECT_CN"),
		CertOutputPath:    certPath,
		KeyOutputPath:     keyPath,
		RequestedTTL:      ttl,
		OnRenewed: func(validAfter, validBefore time.Time) {
			if err := reloader.Refresh(); err != nil {
				log.Warn("reload cert into TLS config", "err", err)
				return
			}
			log.Info("workload cert installed for mTLS",
				"valid_after", validAfter, "valid_before", validBefore)
		},
		Log: log,
	})
	if err != nil {
		return fmt.Errorf("renewer: %w", err)
	}

	userRenewer, err := buildUserCertRenewer(certdClient, spiffeURI, log)
	if err != nil {
		return fmt.Errorf("ssh user cert renewer: %w", err)
	}

	// Optional ssh_config drop-in. Written once at startup with the
	// snippet pointing at the cert-agentd-managed user cert/key
	// paths. Atomic + deterministic so a no-op re-render doesn't
	// churn the file.
	if err := writeSSHSnippetIfConfigured(log); err != nil {
		return fmt.Errorf("ssh-config snippet: %w", err)
	}

	rootCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Run the X.509 workload renewer (always) alongside the SSH user
	// renewer (when configured) under one ctx. Either component's
	// exit cancels rootCtx so the other unwinds cleanly.
	errCh := make(chan error, 2)
	expected := 1
	go func() { errCh <- renewer.Run(rootCtx) }()
	if userRenewer != nil {
		expected = 2
		go func() { errCh <- userRenewer.Run(rootCtx) }()
	}
	var firstErr error
	for range expected {
		err := <-errCh
		if firstErr == nil && err != nil && !errors.Is(err, context.Canceled) {
			firstErr = err
		}
		cancel()
	}
	if firstErr != nil {
		return fmt.Errorf("renewer: %w", firstErr)
	}
	log.Info("stopped")
	return nil
}

// buildUserCertRenewer returns a configured SSH user cert renewer
// when the SSH-cert env vars are populated; otherwise nil so the
// caller skips the second renewal goroutine. KeyID defaults to
// "user:<spiffe-uri-path-tail>" — the trailing component of the
// SPIFFE URI is a sensible identity tag when the operator hasn't
// chosen one.
func buildUserCertRenewer(signer renew.UserSigner, spiffeURI string, log *slog.Logger) (*renew.UserCertRenewer, error) {
	certPath := os.Getenv("CERT_AGENTD_SSH_USER_CERT")
	keyPath := os.Getenv("CERT_AGENTD_SSH_USER_KEY")
	principalsRaw := os.Getenv("CERT_AGENTD_SSH_PRINCIPALS")
	if certPath == "" && keyPath == "" && principalsRaw == "" {
		log.Warn("CERT_AGENTD_SSH_USER_* unset — SSH user cert renewer disabled")
		return nil, nil
	}
	if certPath == "" || keyPath == "" || principalsRaw == "" {
		return nil, errors.New("CERT_AGENTD_SSH_USER_CERT, _USER_KEY, and _PRINCIPALS must all be set together")
	}

	principals := make([]string, 0)
	for p := range strings.SplitSeq(principalsRaw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			principals = append(principals, p)
		}
	}
	if len(principals) == 0 {
		return nil, errors.New("CERT_AGENTD_SSH_PRINCIPALS is empty after trimming")
	}

	keyID := os.Getenv("CERT_AGENTD_SSH_KEY_ID")
	if keyID == "" {
		keyID = "user:" + path.Base(strings.TrimRight(spiffeURI, "/"))
	}
	var ttl time.Duration
	if v := os.Getenv("CERT_AGENTD_SSH_TTL_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("CERT_AGENTD_SSH_TTL_SECONDS %q: must be positive integer", v)
		}
		ttl = time.Duration(n) * time.Second
	}

	r, err := renew.NewUserCertRenewer(renew.UserCertConfig{
		Signer:         signer,
		KeyID:          keyID,
		Principals:     principals,
		CertOutputPath: certPath,
		KeyOutputPath:  keyPath,
		RequestedTTL:   ttl,
		Log:            log,
	})
	if err != nil {
		return nil, err
	}
	log.Info("ssh user cert renewer configured",
		"key_id", keyID, "principals", principals,
		"cert_path", certPath, "key_path", keyPath)
	return r, nil
}

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

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s: %s is required\n", appName, key)
		os.Exit(2)
	}
	return v
}

// loadCAPool reads the CA bundle PEM file and returns it as an
// [*x509.CertPool] suitable for [tls.Config.RootCAs]. Rejects bundles
// with zero PEM blocks so a typo'd path doesn't silently disable
// server cert verification.
func loadCAPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s contains no PEM certs", path)
	}
	return pool, nil
}

// certReloader wraps the workload cert+key paths and serves the
// current pair to tls.Config.GetClientCertificate. Refresh is called
// from the renewer's OnRenewed hook to swap in the freshly-issued
// cert; concurrent reads from TLS handshakes are protected by a
// read/write mutex.
type certReloader struct {
	certPath, keyPath string
	mu                sync.RWMutex
	cert              *tls.Certificate
}

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath}
	if err := r.Refresh(); err != nil {
		return nil, err
	}
	return r, nil
}

// Refresh re-reads the cert+key from disk and atomically replaces
// the holder. Called from renewer.OnRenewed after each successful
// renewal.
func (r *certReloader) Refresh() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load %s/%s: %w", r.certPath, r.keyPath, err)
	}
	r.mu.Lock()
	r.cert = &cert
	r.mu.Unlock()
	return nil
}

// GetClientCertificate satisfies the tls.Config callback signature.
// Returns the current workload cert; tls.Config invokes this on
// every handshake so the fresh cert is picked up automatically
// without rebuilding the http.Client.
func (r *certReloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, errors.New("certReloader: no cert loaded yet")
	}
	return r.cert, nil
}

// writeSSHSnippetIfConfigured renders the optional ssh_config drop-in
// when CERT_AGENTD_SSH_CONFIG_PATH is set. Required-when-present env
// vars are validated here so misconfiguration surfaces at startup
// rather than the first SSH attempt.
func writeSSHSnippetIfConfigured(log *slog.Logger) error {
	path := os.Getenv("CERT_AGENTD_SSH_CONFIG_PATH")
	if path == "" {
		return nil
	}
	cert := os.Getenv("CERT_AGENTD_SSH_USER_CERT")
	key := os.Getenv("CERT_AGENTD_SSH_USER_KEY")
	if cert == "" || key == "" {
		return errors.New("CERT_AGENTD_SSH_USER_CERT and CERT_AGENTD_SSH_USER_KEY are required when CERT_AGENTD_SSH_CONFIG_PATH is set (typically the same paths the SSH user cert renewer manages)")
	}
	snippet := output.SSHConfigSnippet{
		HostPattern:     envOr("CERT_AGENTD_SSH_HOST_PATTERN", "*"),
		CertificateFile: cert,
		IdentityFile:    key,
		ProxyJump:       os.Getenv("CERT_AGENTD_SSH_PROXY_JUMP"),
		User:            os.Getenv("CERT_AGENTD_SSH_USER"),
	}
	body, err := snippet.WriteAtomicTo(path)
	if err != nil {
		return err
	}
	log.Info("ssh-config snippet rendered", "path", path, "size_bytes", len(body))
	return nil
}
