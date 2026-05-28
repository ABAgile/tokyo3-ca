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
//
// Optional operational log shipping (cert-agentd runs on every
// workload host, so log lines land on per-instance subjects):
//
//	CERT_AGENTD_NATS_URL    NATS server URL (e.g., tls://nats:4222).
//	                        When set, log lines fan out to subject
//	                        "app_log.cert-agentd.<instance>". Unset
//	                        leaves the logger at stdout only.
//	CERT_AGENTD_NATS_CERT   Publisher client cert PEM (mTLS to NATS).
//	                        Defaults to CERT_AGENTD_CERT so the
//	                        single workload identity covers both
//	                        certd issuance and log shipping.
//	CERT_AGENTD_NATS_KEY    Matching private key. Defaults to
//	                        CERT_AGENTD_KEY.
//	CERT_AGENTD_NATS_CA     CA bundle that signs the NATS server
//	                        cert. Defaults to CERT_AGENTD_CA.
//	CERT_AGENTD_INSTANCE    Per-host identifier appended to the NATS
//	                        subject and added as an "instance" log
//	                        attribute on every line. Defaults to
//	                        os.Hostname(). Operators may override
//	                        when hostnames aren't stable (e.g.,
//	                        Kubernetes pod names) or distinguishable
//	                        across the fleet.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"github.com/abagile/tokyo3-base/envutil"
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
	log, _, drainLog := applog.AppLoggerWithNATS(applog.Config{
		App:      appName,
		Instance: envutil.Or("CERT_AGENTD_INSTANCE", envutil.HostnameOrEmpty()),
	}, applog.NATSConfig{
		URL:      os.Getenv("CERT_AGENTD_NATS_URL"),
		CertFile: envutil.First("CERT_AGENTD_NATS_CERT", "CERT_AGENTD_CERT"),
		KeyFile:  envutil.First("CERT_AGENTD_NATS_KEY", "CERT_AGENTD_KEY"),
		CAFile:   envutil.First("CERT_AGENTD_NATS_CA", "CERT_AGENTD_CA"),
	}, applog.WithStdout())
	defer drainLog()

	certdURL := envutil.MustEnv("CERT_AGENTD_CERTD_URL")
	certPath := envutil.MustEnv("CERT_AGENTD_CERT")
	keyPath := envutil.MustEnv("CERT_AGENTD_KEY")
	caPath := envutil.MustEnv("CERT_AGENTD_CA")
	spiffeURI := envutil.MustEnv("CERT_AGENTD_SPIFFE_URI")

	// Bootstrap: load the workload cert + key + CA bundle once. The
	// reloader is what TLS actually reads on every handshake — the
	// renewer's OnRenewed hook refreshes the cert+key after each
	// successful renewal, and a background mtime poller refreshes
	// the CA bundle when operators drop in a new one (e.g., during
	// a CA-rotation overlap window).
	reloader, err := newCertReloader(certPath, keyPath, caPath, log)
	if err != nil {
		return fmt.Errorf("bootstrap cert: %w", err)
	}
	// InsecureSkipVerify + VerifyConnection so the standard
	// verification path — which freezes RootCAs at config-
	// construction time — doesn't compete with hot-reload semantics.
	// VerifyConnection runs full chain + hostname verification
	// against the current pool snapshot on every handshake.
	tlsCfg := &tls.Config{
		GetClientCertificate: reloader.GetClientCertificate,
		InsecureSkipVerify:   true,
		VerifyConnection:     reloader.VerifyConnection,
		MinVersion:           tls.VersionTLS12,
	}
	certdClient, err := client.NewClient(certdURL, tlsCfg)
	if err != nil {
		return fmt.Errorf("certd client: %w", err)
	}
	log.Info("certd client configured", "url", certdURL,
		"bootstrap_cert", certPath, "bootstrap_key", keyPath)

	// Surface the bootstrap mTLS cert's remaining validity. If it's
	// close to expiry, the first renewal MUST succeed before it dies
	// — once dead, every retry fails at TLS handshake and the agent
	// can't recover without operator intervention. Threshold is
	// deliberately broad (24h) to give ops one warn-level signal
	// before the silent failure window opens.
	if remaining := time.Until(reloader.LeafExpiry()); !reloader.LeafExpiry().IsZero() && remaining < 24*time.Hour {
		log.Warn("bootstrap mTLS cert near expiry — first renewal must succeed before it dies",
			"remaining", remaining.Round(time.Second),
			"not_after", reloader.LeafExpiry())
	}

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
		SignErrorAttrs: func() []any {
			exp := reloader.LeafExpiry()
			if exp.IsZero() {
				return nil
			}
			return []any{"mtls_cert_remaining", time.Until(exp).Round(time.Second)}
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
	// renewer (when configured) and the CA-bundle mtime poller, all
	// under one ctx. Either component's exit cancels rootCtx so the
	// others unwind cleanly. The CA poller exiting is not a fatal
	// condition itself — its return is filtered out below — but we
	// run it under errCh for uniform shutdown semantics.
	errCh := make(chan error, 3)
	expected := 2
	go func() { errCh <- renewer.Run(rootCtx) }()
	go func() { errCh <- reloader.RunCAPoll(rootCtx, DefaultCAPollInterval, log) }()
	if userRenewer != nil {
		expected = 3
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

// certReloader wraps the workload cert+key paths AND the CA bundle
// path so a TLS handshake always sees the current on-disk material.
// The cert+key are refreshed event-driven (by the renewer's
// OnRenewed hook); the CA bundle is refreshed by an mtime-polling
// goroutine ([certReloader.RunCAPoll]) so operators can drop in a
// new bundle (e.g., during a CA rotation overlap window) without
// restarting the agent. Concurrent reads from TLS handshakes are
// protected by a read/write mutex.
//
// log is used to surface bundle reloads at info level — operators
// rely on this line ("CA bundle reloaded") to confirm a rotated
// bundle has propagated to every daemon in the fleet before
// flipping the upstream signing key. nil ⇒ slog.Default().
type certReloader struct {
	certPath, keyPath, caPath string
	log                       *slog.Logger

	mu       sync.RWMutex
	cert     *tls.Certificate
	notAfter time.Time // cached from cert.Leaf so callers don't reparse on every read
	pool     *x509.CertPool
	caMtime  time.Time
}

// DefaultCAPollInterval is the mtime-poll cadence for the CA bundle.
// Cheap (one os.Stat) and a minute-scale upper bound on "I dropped
// in a new bundle, how long until daemons trust it?". 30s is the
// same cadence ssh-proxyd uses for revocation polling — operators
// only have one number to think about.
const DefaultCAPollInterval = 30 * time.Second

func newCertReloader(certPath, keyPath, caPath string, log *slog.Logger) (*certReloader, error) {
	if log == nil {
		log = slog.Default()
	}
	r := &certReloader{certPath: certPath, keyPath: keyPath, caPath: caPath, log: log}
	if err := r.Refresh(); err != nil {
		return nil, err
	}
	if err := r.refreshCABundle(); err != nil {
		return nil, fmt.Errorf("initial CA bundle: %w", err)
	}
	return r, nil
}

// Refresh re-reads the cert+key from disk and atomically replaces
// the holder. Called from renewer.OnRenewed after each successful
// renewal. Parses the leaf cert so [certReloader.LeafExpiry] can
// surface expiry to operators without reparsing per-handshake.
func (r *certReloader) Refresh() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load %s/%s: %w", r.certPath, r.keyPath, err)
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse leaf %s: %w", r.certPath, err)
		}
		cert.Leaf = leaf
	}
	r.mu.Lock()
	r.cert = &cert
	if cert.Leaf != nil {
		r.notAfter = cert.Leaf.NotAfter
	}
	r.mu.Unlock()
	return nil
}

// refreshCABundle reads the CA bundle from disk and atomically
// replaces the pool when the file's mtime has advanced. No-op when
// the mtime is unchanged so the poll path is cheap even when
// operators leave the bundle alone for days at a time. Logs at
// info on every successful swap so operators can confirm a rotated
// bundle has propagated.
func (r *certReloader) refreshCABundle() error {
	stat, err := os.Stat(r.caPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", r.caPath, err)
	}
	r.mu.RLock()
	prev := r.caMtime
	r.mu.RUnlock()
	if !stat.ModTime().After(prev) && r.poolLoaded() {
		return nil
	}
	pem, err := os.ReadFile(r.caPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", r.caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s contains no PEM certs", r.caPath)
	}
	r.mu.Lock()
	r.pool = pool
	r.caMtime = stat.ModTime()
	r.mu.Unlock()
	r.log.Info("CA bundle reloaded",
		"path", r.caPath,
		"mtime", stat.ModTime(),
		"fingerprint", bundleFingerprint(pem))
	return nil
}

// bundleFingerprint is the first 8 bytes of sha256(pem), hex-
// encoded. Short enough for human-friendly log diffing across a
// fleet, long enough that distinct bundles don't collide in
// practice.
func bundleFingerprint(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:8])
}

func (r *certReloader) poolLoaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pool != nil
}

// RunCAPoll ticks every interval and re-reads the CA bundle when
// its mtime advances. Logs at warn on read errors (the previous
// pool stays live; operators can fix the file and the next tick
// picks it up). Returns when ctx is cancelled.
func (r *certReloader) RunCAPoll(ctx context.Context, interval time.Duration, log *slog.Logger) error {
	if interval <= 0 {
		interval = DefaultCAPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.refreshCABundle(); err != nil {
				log.Warn("CA bundle reload failed; keeping previous pool", "path", r.caPath, "err", err)
			}
		}
	}
}

// VerifyConnection runs full chain + hostname verification against
// the current pool snapshot. Wired into tls.Config.VerifyConnection
// (with tls.Config.InsecureSkipVerify = true) so the standard
// verification path — which reads RootCAs at config-construction
// time — doesn't compete with hot-reload semantics. ServerName comes
// from the http.Transport's SNI which mirrors the URL host, so
// hostname-against-cert still matches the standard verifier's check.
func (r *certReloader) VerifyConnection(cs tls.ConnectionState) error {
	r.mu.RLock()
	pool := r.pool
	r.mu.RUnlock()
	if pool == nil {
		return errors.New("certReloader: no CA bundle loaded")
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("certReloader: peer presented no certificates")
	}
	opts := x509.VerifyOptions{
		Roots:         pool,
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}

// LeafExpiry returns the loaded cert's NotAfter. Zero value when no
// cert is loaded yet (which the Refresh path treats as a fatal
// startup error, so the zero only appears in test scaffolding).
func (r *certReloader) LeafExpiry() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.notAfter
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
		HostPattern:     envutil.Or("CERT_AGENTD_SSH_HOST_PATTERN", "*"),
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
