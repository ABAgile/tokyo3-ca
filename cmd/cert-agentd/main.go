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
//	CERT_AGENTD_CERTD_URL      certd base URL (e.g., https://certd.internal).
//	CERT_AGENTD_WORKLOAD_CERT  Workload X.509 cert PEM path — this agent's mTLS identity.
//	                           Bootstrap cert on first run; the renewer overwrites it atomically
//	                           on each successful renewal. Also the default NATS publisher cert
//	                           (see the WORKLOAD_* convention in tokyo3-base/cli).
//	CERT_AGENTD_WORKLOAD_KEY   Matching private key PEM path. Read on startup and reused across
//	                           renewals — only the cert rotates, the key is stable.
//	CERT_AGENTD_WORKLOAD_CA    CA bundle that signs certd's server cert (and, by default, the
//	                           NATS server cert).
//	CERT_AGENTD_SPIFFE_URI     SPIFFE URI to embed in the renewed cert (e.g.,
//	                           "spiffe://tokyo3.example/host/db-1"). certd's role table decides
//	                           whether the caller may obtain it.
//
// Optional env vars:
//
//	CERT_AGENTD_SUBJECT_CN   Optional X.509 Subject CN. Modern verifiers ignore CN as identity;
//	                         populating it just makes tooling output friendlier.
//	CERT_AGENTD_TTL_SECONDS  Requested validity window. Zero/unset ⇒ certd's default. Capped by
//	                         the endpoint's hard max and possibly further by policy.
//	CERT_AGENTD_GROUPS       Comma-separated caller groups sent on every sign request (the
//	                         agent's own renewal and all workload certs) for certd's body-groups
//	                         policy path (dev/test). Empty unless certd enforces a role table;
//	                         ignored under OIDC / mTLS-principal auth.
//	CERT_AGENTD_ROTATE_KEY   When true, the agent's OWN workload key is regenerated on every
//	                         renewal (fresh key+cert each cycle) instead of a stable key. Safe
//	                         here because the consumer is the agent's in-process reloader, which
//	                         verifies the pair. Default false. (Per-workload rotation for the
//	                         extra certs below is the "rotate_key" field, off by default — leave
//	                         it off for file-reading servers like Postgres that can't safely
//	                         reload a rotating pair.)
//
// Optional additional workload client certs:
//
//	CERT_AGENTD_WORKLOADS_FILE  JSON array of extra X.509 client certs the agent renews for
//	                            sibling processes (mTLS to db, nats, …): each {name, spiffe_uri,
//	                            subject_cn, key_type (ecdsa-p256|ed25519), ttl_seconds,
//	                            cert_path, key_path, rotate_key}. rotate_key (default false)
//	                            regenerates the key each renewal — enable only where the
//	                            consumer tolerates a rotating pair. Separate from the agent's own
//	                            identity above; certd's role table must permit each spiffe_uri.
//
// Optional SSH user cert renewal:
//
//	CERT_AGENTD_SSH_USER_CERT    When set together with CERT_AGENTD_SSH_USER_KEY and
//	                             CERT_AGENTD_SSH_PRINCIPALS, the agent also renews an SSH user
//	                             cert. The key is generated on first run (mode 0600); the cert
//	                             lands at this path (mode 0644).
//	CERT_AGENTD_SSH_USER_KEY     Path for the matching SSH private key. Reused across renewals
//	                             once generated.
//	CERT_AGENTD_SSH_PRINCIPALS   Comma-separated Unix usernames the cert authorizes (e.g.,
//	                             "alice,deployer").
//	CERT_AGENTD_SSH_KEY_ID       KeyID embedded in the cert. Default "user:<spiffe-uri-path-
//	                             tail>".
//	CERT_AGENTD_SSH_TTL_SECONDS  Requested validity window for the user cert. Zero ⇒ certd's
//	                             default.
//
// Optional ssh_config drop-in:
//
//	CERT_AGENTD_SSH_CONFIG_PATH   When set, render an ssh_config snippet to this path pointing
//	                              at the SSH user cert/key above. The user's main config should
//	                              Include it.
//	CERT_AGENTD_SSH_HOST_PATTERN  Host pattern in the snippet. Default "*".
//	CERT_AGENTD_SSH_PROXY_JUMP    ProxyJump directive (e.g., "alice@proxy.internal:2222").
//	CERT_AGENTD_SSH_USER          SSH login name.
//
// Optional operational log shipping (cert-agentd runs on every
// workload host, so log lines land on per-instance subjects):
//
//	CERT_AGENTD_NATS_URL    NATS server URL (e.g., tls://nats:4222). When set, log lines fan out
//	                        to subject "app_log.cert-agentd.<instance>". Unset leaves the logger
//	                        at stdout only.
//	CERT_AGENTD_NATS_CERT   Publisher client cert PEM (mTLS to NATS). Defaults to
//	                        CERT_AGENTD_WORKLOAD_CERT so the single workload identity covers
//	                        both certd issuance and log shipping.
//	CERT_AGENTD_NATS_KEY    Matching private key. Defaults to CERT_AGENTD_WORKLOAD_KEY.
//	CERT_AGENTD_NATS_CA     CA bundle that signs the NATS server cert. Defaults to
//	                        CERT_AGENTD_WORKLOAD_CA.
//	CERT_AGENTD_INSTANCE    Per-host identifier appended to the NATS subject and added as an
//	                        "instance" log attribute on every line. Defaults to os.Hostname().
//	                        Operators may override when hostnames aren't stable (e.g.,
//	                        Kubernetes pod names) or distinguishable across the fleet.
//	CERT_AGENTD_DEBUG_ADDR  Optional pprof + runtime-stats listener (e.g. "127.0.0.1:6060");
//	                        unset disables it. Never expose publicly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/cli"
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/tls/reloader"
	"github.com/abagile/tokyo3-base/version"
	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ca/internal/agent/output"
	"github.com/abagile/tokyo3-ca/internal/agent/renew"
	"github.com/abagile/tokyo3-ca/internal/client"
)

const appName = "cert-agentd"

// Version is overridden at build time via -ldflags "-X main.Version=...".
// version.Resolve falls back to runtime/debug.BuildInfo when the ldflags
// injection is absent (e.g. `go install …@vX.Y.Z`).
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
	certdURL := envutil.MustEnv("CERT_AGENTD_CERTD_URL")
	certPath := envutil.MustEnv("CERT_AGENTD_WORKLOAD_CERT")
	keyPath := envutil.MustEnv("CERT_AGENTD_WORKLOAD_KEY")
	caPath := envutil.MustEnv("CERT_AGENTD_WORKLOAD_CA")
	spiffeURI := envutil.MustEnv("CERT_AGENTD_SPIFFE_URI")

	rt := cli.App{
		Name:      appName,
		EnvPrefix: "CERT_AGENTD",
		Instance:  envutil.Or("CERT_AGENTD_INSTANCE", envutil.HostnameOrEmpty()),
	}.Setup(ctx)
	defer rt.Shutdown()
	log := rt.Log

	// Bootstrap: load the workload cert + key + CA bundle once. The
	// reloader is what TLS actually reads on every handshake — the
	// renewer's OnRenewed hook refreshes the cert+key after each
	// successful renewal, and a background mtime poller refreshes
	// the CA bundle when operators drop in a new one (e.g., during
	// a CA-rotation overlap window).
	r, err := reloader.New(reloader.Config{
		CertPath: certPath,
		KeyPath:  keyPath,
		Pools:    map[string]string{"ca": caPath},
		Log:      log,
	})
	if err != nil {
		return fmt.Errorf("bootstrap cert: %w", err)
	}
	certdClient, err := client.NewClient(certdURL, r.TLSConfig("ca"))
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
	r.WarnIfNearExpiry(24*time.Hour, "bootstrap mTLS cert near expiry — first renewal must succeed before it dies")

	var ttl time.Duration
	if v := os.Getenv("CERT_AGENTD_TTL_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return fmt.Errorf("CERT_AGENTD_TTL_SECONDS %q: must be positive integer", v)
		}
		ttl = time.Duration(n) * time.Second
	}

	// Body-groups for certd's policy path (dev/test): the same group set
	// is sent on the agent's own renewal and every workload cert, since
	// they all share one identity. Empty unless CERT_AGENTD_GROUPS is set;
	// certd's permissive / OIDC / mTLS-principal modes ignore it.
	var groups []string
	for g := range strings.SplitSeq(os.Getenv("CERT_AGENTD_GROUPS"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}

	// The agent's own workload cert is consumed by its in-process reloader
	// (OnRenewed → r.Refresh), which verifies the pair on load, so rotating
	// its key is safe. Opt-in via CERT_AGENTD_ROTATE_KEY (default false).
	rotateKey, _ := strconv.ParseBool(os.Getenv("CERT_AGENTD_ROTATE_KEY"))
	renewer, err := renew.New(renew.Config{
		Signer:            certdClient,
		SPIFFEURI:         spiffeURI,
		SubjectCommonName: os.Getenv("CERT_AGENTD_SUBJECT_CN"),
		RotateKey:         rotateKey,
		Groups:            groups,
		CertOutputPath:    certPath,
		KeyOutputPath:     keyPath,
		RequestedTTL:      ttl,
		OnRenewed: func(validAfter, validBefore time.Time) {
			if err := r.Refresh(); err != nil {
				log.Warn("reload cert into TLS config", "err", err)
				return
			}
			log.Info("workload cert installed for mTLS",
				"valid_after", validAfter, "valid_before", validBefore)
		},
		SignErrorAttrs: r.ExpiryAttrs("mtls_cert_remaining"),
		Log:            log,
	})
	if err != nil {
		return fmt.Errorf("renewer: %w", err)
	}

	userRenewer, err := buildUserCertRenewer(certdClient, spiffeURI, log)
	if err != nil {
		return fmt.Errorf("ssh user cert renewer: %w", err)
	}

	// Additional X.509 client certs (mTLS to db, nats, …) the agent
	// provisions for sibling processes — distinct from its own identity
	// above, which authenticates these very requests to certd.
	workloadRenewers, err := buildWorkloadRenewers(certdClient, groups, log)
	if err != nil {
		return fmt.Errorf("workload cert renewers: %w", err)
	}

	// Optional ssh_config drop-in. Written once at startup with the
	// snippet pointing at the cert-agentd-managed user cert/key
	// paths. Atomic + deterministic so a no-op re-render doesn't
	// churn the file.
	if err := writeSSHSnippetIfConfigured(log); err != nil {
		return fmt.Errorf("ssh-config snippet: %w", err)
	}

	// Derive a cancellable child of rt.Ctx so one component's exit
	// unwinds the others (cancel() in the collector loop below); rt.Ctx
	// itself is cancelled on signal/shutdown by rt.Shutdown.
	rootCtx, cancel := context.WithCancel(rt.Ctx)
	defer cancel()

	// Collect every long-lived component into one runnable set: the
	// agent's own X.509 renewer, the CA-bundle mtime poller, the
	// optional SSH user renewer, and any additional workload-cert
	// renewers. They all run under rootCtx; any one's exit cancels it
	// so the others unwind cleanly. The CA poller exiting is not fatal
	// itself — its return is filtered out below — but it runs under the
	// same channel for uniform shutdown semantics.
	runners := []func(context.Context) error{
		renewer.Run,
		func(c context.Context) error { return r.RunPoll(c, reloader.DefaultPollInterval) },
	}
	if userRenewer != nil {
		runners = append(runners, userRenewer.Run)
	}
	for _, wr := range workloadRenewers {
		runners = append(runners, wr.Run)
	}

	errCh := make(chan error, len(runners))
	for _, run := range runners {
		go func() { errCh <- run(rootCtx) }()
	}
	var firstErr error
	for range runners {
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

// workloadSpec is one entry in the CERT_AGENTD_WORKLOADS_FILE JSON
// array: an additional X.509 client cert the agent renews for a sibling
// process to present (mTLS to db, nats, …). Distinct from the agent's
// own bootstrap identity, which authenticates these requests to certd.
type workloadSpec struct {
	Name       string `json:"name"`
	SPIFFEURI  string `json:"spiffe_uri"`
	SubjectCN  string `json:"subject_cn"`
	KeyType    string `json:"key_type"` // ecdsa-p256 | ed25519; empty ⇒ ecdsa-p256
	TTLSeconds int64  `json:"ttl_seconds"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	// RotateKey regenerates the private key on every renewal (a fresh
	// key+cert each cycle). Default false keeps the key stable — leave it
	// off for file-reading servers (e.g. Postgres) that can't safely
	// reload a rotating cert/key pair; enable only where the consumer
	// tolerates it.
	RotateKey bool `json:"rotate_key"`
}

// buildWorkloadRenewers reads CERT_AGENTD_WORKLOADS_FILE (a JSON array
// of workloadSpec) and returns one renewer per spec, all sharing the
// certd client. Returns nil when the env var is unset. certd's role
// table must permit the agent's identity to obtain each spec's
// spiffe_uri.
func buildWorkloadRenewers(signer renew.Signer, groups []string, log *slog.Logger) ([]*renew.Renewer, error) {
	specFile := os.Getenv("CERT_AGENTD_WORKLOADS_FILE")
	if specFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(specFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", specFile, err)
	}
	var specs []workloadSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("decode %s: %w", specFile, err)
	}
	renewers := make([]*renew.Renewer, 0, len(specs))
	for i, s := range specs {
		if s.Name == "" {
			return nil, fmt.Errorf("%s entry %d: name is required", specFile, i)
		}
		rn, err := renew.New(renew.Config{
			Signer:            signer,
			SPIFFEURI:         s.SPIFFEURI,
			SubjectCommonName: s.SubjectCN,
			KeyType:           renew.KeyType(s.KeyType),
			RotateKey:         s.RotateKey,
			Groups:            groups,
			CertOutputPath:    s.CertPath,
			KeyOutputPath:     s.KeyPath,
			RequestedTTL:      time.Duration(s.TTLSeconds) * time.Second,
			Log:               log.With("workload", s.Name),
		})
		if err != nil {
			return nil, fmt.Errorf("%s workload %q: %w", specFile, s.Name, err)
		}
		renewers = append(renewers, rn)
	}
	log.Info("workload cert renewers configured", "count", len(renewers), "file", specFile)
	return renewers, nil
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
			fmt.Printf("%s %s\n", appName, version.Resolve(Version))
		},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

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
