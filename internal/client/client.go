// Package client is the exported Go client for the certd HTTP API.
// Consumed by cert-agentd in this repo and (in a separate copy) by
// ssh-proxy/ for SSH-cert minting calls.
//
// Authentication to certd is mTLS: the caller presents its workload
// identity cert; certd applies its role table to decide what the
// caller may obtain. The TLS material is supplied by the caller —
// this package does no key loading on its own.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/api"
)

// DefaultTimeout caps each HTTP call. certd is on the same private
// network as its callers; 5s is generous for everything except a
// cold start.
const DefaultTimeout = 5 * time.Second

// Client is a thin wrapper around base/api's Resty client tailored
// to certd's signing endpoints. Safe for concurrent use.
type Client struct {
	api *api.RestyClient
}

// NewClient builds a client for certd at baseURL ("https://certd.example.com").
// tlsCfg supplies the mTLS material — the caller's client cert + the
// CA bundle that signs certd's server cert. Pass nil tlsCfg to skip
// TLS (test only; production must always use mTLS).
func NewClient(baseURL string, tlsCfg *tls.Config) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL is required")
	}
	baseURL = strings.TrimRight(baseURL, "/")
	opts := []api.RestyClientOption{api.CO.WithTimeout(DefaultTimeout)}
	if tlsCfg != nil {
		opts = append(opts, api.CO.WithTransport(&http.Transport{TLSClientConfig: tlsCfg}))
	}
	return &Client{api: api.NewRestClient(baseURL, opts...)}, nil
}

// SignWorkloadRequest mirrors certd's POST /api/v1/x509/sign-workload
// body. Keep in sync with the certd handler — fields drift here
// silently turn into 400s.
type SignWorkloadRequest struct {
	// PublicKey is the workload's public key, PEM-encoded as a
	// SubjectPublicKeyInfo block ("-----BEGIN PUBLIC KEY-----").
	PublicKey string `json:"public_key"`
	// SPIFFEURI is the requested URI SAN. Must use the spiffe://
	// scheme; role policy decides whether the caller may obtain it.
	SPIFFEURI string `json:"spiffe_uri"`
	// SubjectCommonName is an optional CN. Modern verifiers ignore
	// CN as identity; this is for human-friendly tooling only.
	SubjectCommonName string `json:"subject_common_name,omitempty"`
	// Groups carry the caller's authenticated group membership for
	// policy enforcement when certd is in body-groups fallback mode.
	// Production uses OIDC or mTLS attribution and ignores this.
	Groups []string `json:"groups,omitempty"`
	// TTLSeconds is the requested validity window. Zero ⇒ certd's
	// default. Capped by the endpoint's hard max and possibly
	// further by role policy.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
	// CurrentSerial is the decimal serial of the cert the workload is
	// rotating from (empty on first issuance). certd's renewal/anti-theft
	// guard accepts it only when it is the identity's current or
	// one-step-previous serial; a stale/unknown serial is rejected as a
	// possible clone. Ignored when the guard is off (no persistent store).
	CurrentSerial string `json:"current_serial,omitempty"`
}

// SignWorkloadResponse mirrors certd's reply shape. Certificate is
// PEM-encoded ("-----BEGIN CERTIFICATE-----"). Serial is a decimal
// big-int string — X.509 serials don't fit uint64.
type SignWorkloadResponse struct {
	Certificate string `json:"certificate"`
	// Chain is the issuer chain (intermediate CA cert(s)) the workload must
	// present alongside the leaf so peers can build a path to the pinned root.
	// Empty in a single-tier deployment (the issuer is the root anchor).
	Chain       string    `json:"chain,omitempty"`
	Serial      string    `json:"serial"`
	SPIFFEURI   string    `json:"spiffe_uri"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// SignWorkloadCert calls certd's /api/v1/x509/sign-workload endpoint
// and returns the signed cert + validity envelope. Non-2xx responses
// surface as wrapped *[api.ApiError] values whose Error() string
// includes the response body so upstream policy denial messages
// land in operator logs without further plumbing.
func (c *Client) SignWorkloadCert(ctx context.Context, req SignWorkloadRequest) (*SignWorkloadResponse, error) {
	var out SignWorkloadResponse
	if err := c.api.R(ctx, http.MethodPost, "/api/v1/x509/sign-workload", &out,
		api.RO.WithBody(req)); err != nil {
		return nil, fmt.Errorf("sign-workload: %w", err)
	}
	return &out, nil
}

// AdoptRequest is the body of POST /api/v1/x509/adopt — a workload telling
// certd it has durably persisted the cert with Serial so certd can collapse
// the one-step rotation grace (drop previous) for SPIFFEURI.
type AdoptRequest struct {
	SPIFFEURI string `json:"spiffe_uri"`
	Serial    string `json:"serial"`
}

// AdoptResponse reports whether the grace was collapsed (false is benign —
// the serial wasn't current, or the identity is unknown/locked).
type AdoptResponse struct {
	Adopted bool `json:"adopted"`
}

// AdoptCert acks adoption of a freshly-persisted cert: certd drops the
// rotated-from serial from the acceptance window for spiffeURI when serial is
// its current serial. Best-effort — a non-2xx surfaces as an error the caller
// can log and ignore (the grace simply stays one step wider).
func (c *Client) AdoptCert(ctx context.Context, spiffeURI, serial string) (bool, error) {
	var out AdoptResponse
	if err := c.api.R(ctx, http.MethodPost, "/api/v1/x509/adopt", &out,
		api.RO.WithBody(AdoptRequest{SPIFFEURI: spiffeURI, Serial: serial})); err != nil {
		return false, fmt.Errorf("adopt: %w", err)
	}
	return out.Adopted, nil
}

// TrustBundleResponse mirrors certd's GET /api/v1/x509/trust-bundle reply.
// Bundle is PEM and may hold multiple CERTIFICATE blocks (old⊕new during a
// CA rotation overlap).
type TrustBundleResponse struct {
	Bundle string `json:"trust_bundle"`
}

// FetchTrustBundle pulls certd's current X.509 trust bundle (the anchor
// workloads verify certd-issued peers against). Lets an agent refresh the
// bundle on a schedule instead of waiting for an out-of-band push — the
// endpoint is unauthenticated public material, but the call still rides the
// client's TLS channel to certd.
func (c *Client) FetchTrustBundle(ctx context.Context) (string, error) {
	var out TrustBundleResponse
	if err := c.api.R(ctx, http.MethodGet, "/api/v1/x509/trust-bundle", &out); err != nil {
		return "", fmt.Errorf("trust-bundle: %w", err)
	}
	return out.Bundle, nil
}

// SSHCAKeysResponse mirrors certd's GET /api/v1/ssh/ca-keys reply.
// TrustedUserCAKeys is one or more SSH CA pubkeys in TrustedUserCAKeys format
// (old⊕new during a CA-rotation overlap).
type SSHCAKeysResponse struct {
	TrustedUserCAKeys string `json:"trusted_user_ca_keys"`
}

// FetchSSHCAKeys pulls certd's current trusted SSH CA key set, letting a
// verifier refresh its TrustedUserCAKeys on a schedule instead of waiting for
// an out-of-band push. Unauthenticated public material, but the call still
// rides the client's TLS channel to certd (the SSH counterpart to
// [Client.FetchTrustBundle]).
func (c *Client) FetchSSHCAKeys(ctx context.Context) (string, error) {
	var out SSHCAKeysResponse
	if err := c.api.R(ctx, http.MethodGet, "/api/v1/ssh/ca-keys", &out); err != nil {
		return "", fmt.Errorf("ssh ca-keys: %w", err)
	}
	return out.TrustedUserCAKeys, nil
}

// SignUserRequest mirrors certd's POST /api/v1/ssh/sign-user body.
// Keep in sync with the certd handler — fields drift here silently
// turn into 400s.
type SignUserRequest struct {
	// PublicKey is the subject's SSH public key in authorized_keys
	// format (e.g., "ssh-ed25519 AAAA…").
	PublicKey string `json:"public_key"`
	// KeyID is the human-readable identifier embedded in the cert
	// (also surfaces in certd's audit log). Required.
	KeyID string `json:"key_id"`
	// Principals are the Unix usernames the bearer may log in as.
	// At least one entry required. When policy is active, principals
	// not authorized for the caller are silently dropped; the full
	// set being denied is a 403.
	Principals []string `json:"principals"`
	// Groups carry the caller's authenticated group membership for
	// policy enforcement when certd is in body-groups fallback mode.
	Groups []string `json:"groups,omitempty"`
	// Extensions are SSH cert extensions (e.g., permit-pty,
	// permit-port-forwarding). Merged with role default extensions
	// (request-level wins).
	Extensions map[string]string `json:"extensions,omitempty"`
	// CriticalOptions are strictly-enforced sshd options (e.g.,
	// force-command, source-address).
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	// TTLSeconds is the requested validity window. Zero ⇒ certd's
	// default. Capped at the endpoint's max and possibly further by
	// role policy.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// SignUserResponse mirrors certd's response. Certificate is in the
// authorized_keys-format cert line ("ssh-ed25519-cert-v01@openssh.com
// AAAA…").
type SignUserResponse struct {
	Certificate string    `json:"certificate"`
	Serial      uint64    `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// SignUserCert calls certd's /api/v1/ssh/sign-user endpoint and
// returns the signed user cert + validity envelope. Behaves
// identically to [Client.SignWorkloadCert] regarding context,
// timeouts, and error surfacing.
func (c *Client) SignUserCert(ctx context.Context, req SignUserRequest) (*SignUserResponse, error) {
	var out SignUserResponse
	if err := c.api.R(ctx, http.MethodPost, "/api/v1/ssh/sign-user", &out,
		api.RO.WithBody(req)); err != nil {
		return nil, fmt.Errorf("sign-user: %w", err)
	}
	return &out, nil
}
