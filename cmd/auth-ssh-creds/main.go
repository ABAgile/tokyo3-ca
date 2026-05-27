// Command auth-ssh-creds is the certd CLI helper that mints
// short-lived SSH user certificates from certd's
// /api/v1/ssh/sign-user endpoint, gated by an OIDC ID token issued
// by an external IdP (typically tokyo3-auth).
//
//	$ go install github.com/abagile/tokyo3-ca/cmd/auth-ssh-creds@latest
//
// Lives in the ca repo because the wire shape it depends on is
// certd's sign-user contract, not the IdP's. SSO is the prerequisite
// (a one-time `login` populates the shared ~/.config/auth-sso/ cache
// via github.com/abagile/tokyo3-base/auth/oidcclient), but the
// helper's compatibility coupling is with certd.
//
// One-time interactive login (opens browser, completes OIDC code
// flow on a loopback redirect, caches the refresh + ID token):
//
//	$ auth-ssh-creds login --issuer https://id.example.com --client-id tokyo3-cli
//
// On-demand cert minting (renews access/ID tokens silently if
// they're stale, generates an ed25519 keypair the first time, POSTs
// the public key to certd along with the ID token as a bearer
// credential, writes the returned cert next to the private key):
//
//	$ auth-ssh-creds get \
//	      --certd https://certd.internal \
//	      --principals alice,deployer \
//	      --ttl 1h
//
// The on-disk cert + key live at
// $XDG_CONFIG_HOME/auth-sso/ssh-creds/keys/ by default. Override
// with --key-out / --cert-out, or point ssh directly at the defaults
// via:
//
//	$ ssh -i ~/.config/auth-sso/ssh-creds/keys/id_ed25519 user@host
//
// Set --proxy-jump to also emit an ssh_config snippet on stdout that
// routes the configured hosts through ssh-proxyd via ProxyJump.
//
// The OIDC code path (browser/device flow, token cache, refresh-
// token rotation) lives in
// github.com/abagile/tokyo3-base/auth/oidcclient and is shared with
// any other SSO CLI in the family — a single `login` populates
// ~/.config/auth-sso/ for all of them. The SSH-specific bits
// (keypair generation, /api/v1/ssh/sign-user POST, on-disk cert
// layout) stay here.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-base/auth/oidcclient"
)

const (
	// appCacheSubdir names this helper's subdir under the shared SSO
	// cache root (~/.config/auth-sso/ssh-creds/). Conventionally
	// matches the binary name minus the "auth-" prefix.
	appCacheSubdir = "ssh-creds"

	// accessTokenSkew buffers the OAuth access token check the same way
	// auth-aws-creds does — refresh proactively before tokens go stale
	// rather than racing the certd request.
	accessTokenSkew = 30 * time.Second

	// defaultCertTTL is the ttl_seconds value requested when --ttl is
	// omitted. certd's per-endpoint maximum and per-role policy may
	// shorten this; the response carries the actual granted window.
	defaultCertTTL = time.Hour

	// httpTimeout bounds the per-request budget for certd calls.
	httpTimeout = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "login":
		os.Exit(cmdLogin(args))
	case "logout":
		os.Exit(cmdLogout(args))
	case "get":
		os.Exit(cmdGet(args))
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "auth-ssh-creds: unknown command %q\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `auth-ssh-creds — SSH credential helper for auth's OIDC federation

Usage:
  auth-ssh-creds login   --issuer URL --client-id ID [--port N]
  auth-ssh-creds login   --issuer URL --client-id ID --device
  auth-ssh-creds get     --certd URL --principals NAME[,NAME...] [--ttl DUR]
                         [--groups eng,sre] [--key-out PATH] [--cert-out PATH]
                         [--key-id ID] [--proxy-jump HOST:PORT]
  auth-ssh-creds logout

login modes:
  default  Opens a browser on this host, loopback redirect captures the
           authorization code (OAuth 2.0 + PKCE).
  --device RFC 8628 device authorization grant: prints a verification
           URL + short code; complete the browser part on any device.
           Required when this host has no browser. The OAuth client must
           have allow_device_grant=true at /portal/admin/clients.

The "get" command sends the cached OIDC ID token to certd as a bearer
credential. certd validates the token against auth's JWKS, applies its
role table to the requested principals, and signs an SSH user cert.

Files (shared SSO cache; same root for all auth-* helpers):
  ~/.config/auth-sso/config.json                       issuer + client_id (non-secret)
  ~/.config/auth-sso/tokens.json                       OAuth refresh + access + id token (0o600)
  ~/.config/auth-sso/ssh-creds/keys/id_ed25519         generated private key (0o600)
  ~/.config/auth-sso/ssh-creds/keys/id_ed25519.pub     public key (0o644)
  ~/.config/auth-sso/ssh-creds/keys/id_ed25519-cert.pub
                                                       certd-signed user cert (0o644)`)
}

// ── login ────────────────────────────────────────────────────────────────────

func cmdLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	issuer := fs.String("issuer", "", "auth issuer URL (e.g. https://id.example.com)")
	clientID := fs.String("client-id", "", "OAuth2 public client id (PKCE)")
	port := fs.Int("port", 0, "loopback redirect port (0 = pick a free one)")
	device := fs.Bool("device", false, "use RFC 8628 device authorization grant instead of opening a browser locally")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *issuer == "" || *clientID == "" {
		fmt.Fprintln(os.Stderr, "--issuer and --client-id are required for login")
		return 2
	}
	if _, err := oidcclient.Login(context.Background(),
		oidcclient.Config{Issuer: *issuer, ClientID: *clientID},
		oidcclient.LoginOptions{Port: *port, Device: *device, Stderr: os.Stderr}); err != nil {
		fmt.Fprintf(os.Stderr, "login: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "auth-ssh-creds: login successful")
	return 0
}

// ── logout ───────────────────────────────────────────────────────────────────

func cmdLogout(_ []string) int {
	// Logout wipes the shared tokens.json plus the per-helper subdir
	// (~/.config/auth-sso/ssh-creds/) — clearing it removes the
	// keypair + signed cert so a fresh login doesn't leave a stale
	// cert next to a new identity.
	if err := oidcclient.Logout(appCacheSubdir); err != nil {
		fmt.Fprintf(os.Stderr, "logout: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "auth-ssh-creds: logged out (tokens + key cache cleared)")
	return 0
}

// ── get ──────────────────────────────────────────────────────────────────────

func cmdGet(args []string) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	certdURL := fs.String("certd", "", "certd base URL (e.g. https://certd.internal)")
	principalsCSV := fs.String("principals", "", "comma-separated Unix usernames the cert may log in as")
	groupsCSV := fs.String("groups", "", "comma-separated groups for certd policy enforcement (optional)")
	ttl := fs.Duration("ttl", defaultCertTTL, "requested cert lifetime; certd may cap shorter")
	keyOut := fs.String("key-out", "", "path for the private key (default: <cache>/keys/id_ed25519)")
	certOut := fs.String("cert-out", "", "path for the signed cert (default: <key-out>-cert.pub)")
	keyID := fs.String("key-id", "", "key_id embedded in the cert (default: derived from id_token email/sub)")
	proxyJump := fs.String("proxy-jump", "", "if set, emit an ssh_config snippet routing through this HOST:PORT")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *certdURL == "" {
		fmt.Fprintln(os.Stderr, "--certd is required")
		return 2
	}
	if *principalsCSV == "" {
		fmt.Fprintln(os.Stderr, "--principals is required")
		return 2
	}

	cfg, err := oidcclient.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v (run `auth-ssh-creds login` first)\n", err)
		return 1
	}
	tokens, err := oidcclient.EnsureFreshTokens(context.Background(), *cfg, accessTokenSkew)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if tokens.IDToken == "" {
		fmt.Fprintln(os.Stderr, "no id_token cached — re-run `auth-ssh-creds login`")
		return 1
	}

	keyPath, certPath, err := resolveOutPaths(*keyOut, *certOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve output paths: %v\n", err)
		return 1
	}
	pubKey, err := ensureKeypair(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ensure keypair: %v\n", err)
		return 1
	}

	resolvedKeyID := *keyID
	if resolvedKeyID == "" {
		resolvedKeyID = deriveKeyID(tokens.IDToken)
	}
	if resolvedKeyID == "" {
		fmt.Fprintln(os.Stderr, "could not derive key_id from id_token; pass --key-id explicitly")
		return 1
	}

	resp, err := signUserCert(*certdURL, tokens.IDToken, signUserRequest{
		PublicKey:  pubKey,
		KeyID:      resolvedKeyID,
		Principals: splitCSV(*principalsCSV),
		Groups:     splitCSV(*groupsCSV),
		TTLSeconds: int64(ttl.Seconds()),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign user cert: %v\n", err)
		return 1
	}

	if err := writeCert(certPath, resp.Certificate); err != nil {
		fmt.Fprintf(os.Stderr, "write cert: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "auth-ssh-creds: cert written\n  key:  %s\n  cert: %s\n  ttl:  %s (valid_before %s)\n  principals: %s\n",
		keyPath, certPath, time.Until(resp.ValidBefore).Round(time.Second),
		resp.ValidBefore.Format(time.RFC3339), strings.Join(resp.Principals, ","))

	if *proxyJump != "" {
		fmt.Print(buildSSHConfigSnippet(keyPath, certPath, *proxyJump, resp.Principals))
	}
	return 0
}

// ── certd HTTP shapes ────────────────────────────────────────────────────────

// signUserRequest mirrors ca/internal/server/api.signUserRequest. We
// define it here instead of importing ca/ so this helper stays a leaf
// repo dependency — pulling in ca/ would invert the dependency arrow.
type signUserRequest struct {
	PublicKey  string   `json:"public_key"`
	KeyID      string   `json:"key_id"`
	Principals []string `json:"principals"`
	Groups     []string `json:"groups,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
}

type signResponse struct {
	Certificate string    `json:"certificate"`
	Serial      uint64    `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

func signUserCert(certdURL, idToken string, req signUserRequest) (*signResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(certdURL, "/")+"/api/v1/ssh/sign-user",
		strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+idToken)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/api/v1/ssh/sign-user %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out signResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// ── keypair management ──────────────────────────────────────────────────────

// resolveOutPaths derives the private-key and cert paths. When both
// flags are empty, they default to <cache>/keys/id_ed25519 and
// <key>-cert.pub. When --key-out is set, the cert path follows the
// OpenSSH convention of adding "-cert.pub" unless --cert-out is also
// provided.
func resolveOutPaths(keyOut, certOut string) (string, string, error) {
	if keyOut == "" {
		dir, err := oidcclient.AppCacheDir(appCacheSubdir)
		if err != nil {
			return "", "", err
		}
		keysDir := filepath.Join(dir, "keys")
		if err := os.MkdirAll(keysDir, 0o700); err != nil {
			return "", "", err
		}
		keyOut = filepath.Join(keysDir, "id_ed25519")
	}
	if certOut == "" {
		certOut = keyOut + "-cert.pub"
	}
	return keyOut, certOut, nil
}

// ensureKeypair guarantees a usable ed25519 keypair on disk and
// returns the public key in authorized_keys format ready to ship to
// certd. If the private key already exists, it's loaded (and the .pub
// re-derived from it); otherwise a fresh keypair is generated.
//
// On-disk: private key as OpenSSH PEM (0o600), public key as
// authorized_keys (0o644). Compatible with `ssh -i <key>` without
// further conversion.
func ensureKeypair(keyPath string) (string, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return "", fmt.Errorf("parse existing key %s: %w (delete the file to regenerate)", keyPath, err)
		}
		return strings.TrimRight(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n"), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", err
	}
	if err := oidcclient.WriteFileAtomic(keyPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return "", err
	}
	if err := oidcclient.WriteFileAtomic(keyPath+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		return "", err
	}
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n"), nil
}

func writeCert(path, certLine string) error {
	// Certs are not secret, but the cert+key pair lives in the same
	// dir and OpenSSH expects the .pub to be world-readable so an
	// agent or remote sshd can read it during forwarding.
	if !strings.HasSuffix(certLine, "\n") {
		certLine += "\n"
	}
	return oidcclient.WriteFileAtomic(path, []byte(certLine), 0o644)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// deriveKeyID picks a human-readable key_id from the cached ID token
// — email preferred, sub as fallback. Empty when the token doesn't
// parse or carries neither claim; the caller falls back to --key-id.
func deriveKeyID(idToken string) string {
	c := oidcclient.IDTokenClaims(idToken)
	switch {
	case c.Email != "":
		return c.Email
	case c.Subject != "":
		return c.Subject
	default:
		return ""
	}
}

// splitCSV splits comma-separated input, trims whitespace, drops
// empties. Returns nil (not []string{}) when the input is blank so
// the resulting JSON omits the field via omitempty semantics where
// applicable.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildSSHConfigSnippet generates a drop-in ~/.ssh/config block that
// routes traffic through ssh-proxyd via ProxyJump. Operators usually
// `cat` this into `~/.ssh/config.d/abagile` and `Include` it from
// their main config.
func buildSSHConfigSnippet(keyPath, certPath, proxyJump string, principals []string) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# auth-ssh-creds: drop-in ssh_config snippet")
	fmt.Fprintln(&b, "# Append this to ~/.ssh/config (or to a file Include'd from it).")
	fmt.Fprintln(&b, "Host *.internal")
	if len(principals) > 0 {
		fmt.Fprintf(&b, "    User %s\n", principals[0])
	}
	fmt.Fprintf(&b, "    IdentityFile %s\n", keyPath)
	fmt.Fprintf(&b, "    CertificateFile %s\n", certPath)
	fmt.Fprintf(&b, "    ProxyJump %s\n", proxyJump)
	fmt.Fprintln(&b, "    IdentitiesOnly yes")
	return b.String()
}
