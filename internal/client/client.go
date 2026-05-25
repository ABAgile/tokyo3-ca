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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout caps each HTTP call. certd is on the same private
// network as its callers; 5s is generous for everything except a
// cold start.
const DefaultTimeout = 5 * time.Second

// Client is a thin wrapper around [http.Client] tailored to certd's
// signing endpoints. Safe for concurrent use.
type Client struct {
	baseURL string
	http    *http.Client
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
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Transport: transport,
			Timeout:   DefaultTimeout,
		},
	}, nil
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
}

// SignWorkloadResponse mirrors certd's reply shape. Certificate is
// PEM-encoded ("-----BEGIN CERTIFICATE-----"). Serial is a decimal
// big-int string — X.509 serials don't fit uint64.
type SignWorkloadResponse struct {
	Certificate string    `json:"certificate"`
	Serial      string    `json:"serial"`
	SPIFFEURI   string    `json:"spiffe_uri"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// SignWorkloadCert calls certd's /api/v1/x509/sign-workload endpoint
// and returns the signed cert + validity envelope. Non-2xx responses
// are returned as errors with the response body surfaced so debugging
// upstream config issues doesn't require breaking out tcpdump.
func (c *Client) SignWorkloadCert(ctx context.Context, req SignWorkloadRequest) (*SignWorkloadResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal sign-workload request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/x509/sign-workload", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sign-workload http call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read sign-workload response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("sign-workload returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out SignWorkloadResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode sign-workload response: %w", err)
	}
	return &out, nil
}
