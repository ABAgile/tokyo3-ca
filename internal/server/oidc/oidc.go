// Package oidc verifies inbound OIDC ID tokens — specifically the ones
// authd issues — so certd can derive a caller's groups from a
// cryptographically-signed assertion rather than a self-declared
// request field.
//
// The verifier is consumed by the API layer through a small interface
// ([TokenVerifier]) so tests can inject a deterministic stub instead
// of spinning up a real issuer. The production implementation
// ([HTTPVerifier]) wraps [github.com/coreos/go-oidc/v3], which handles
// the OIDC discovery doc and JWKS fetch/refresh.
package oidc

import (
	"context"
	"errors"
	"fmt"

	goidc "github.com/coreos/go-oidc/v3/oidc"
)

// Claims is the subset of OIDC + custom claims certd cares about. New
// fields are additive; downstream code reads through this struct so
// claim renames in the underlying token format are absorbed here.
type Claims struct {
	// Subject is the OIDC `sub` claim — the stable user identifier
	// from authd (UUID).
	Subject string
	// Email is the verified email of the user, when authd surfaces it.
	Email string
	// Name is the user's display name, when present.
	Name string
	// Groups is the authoritative group-membership list. authd derives
	// this from SCIM group records.
	Groups []string
}

// TokenVerifier is the abstraction certd's API layer talks to.
// Implementations must validate signature, issuer, audience, and
// expiry, and return [Claims] only for fully-validated tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*Claims, error)
}

// HTTPVerifier wraps go-oidc with discovery + JWKS auto-refresh. Built
// for a single (issuer, audience) pair; create a separate instance per
// authd cluster certd should trust.
type HTTPVerifier struct {
	verifier *goidc.IDTokenVerifier
	issuer   string
	audience string
}

// NewHTTPVerifier discovers issuer's OIDC metadata, fetches its JWKS,
// and returns a verifier configured for audience. The returned
// verifier transparently refreshes the JWKS when authd rotates keys —
// no manual reload needed.
//
// issuer is the authd public URL (e.g., "https://auth.example.com").
// audience matches the `aud` claim on every token authd issues for
// certd.
//
// Errors at this stage mean the issuer is unreachable, the discovery
// doc is malformed, or the JWKS can't be fetched — surface them as
// fatal startup errors.
func NewHTTPVerifier(ctx context.Context, issuer, audience string) (*HTTPVerifier, error) {
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		return nil, errors.New("audience is required")
	}
	provider, err := goidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider %q: %w", issuer, err)
	}
	v := provider.Verifier(&goidc.Config{
		ClientID: audience,
	})
	return &HTTPVerifier{verifier: v, issuer: issuer, audience: audience}, nil
}

// Verify satisfies [TokenVerifier]. Returns sentinel errors via the
// underlying go-oidc library; callers should treat any error as a 401.
func (v *HTTPVerifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	if rawIDToken == "" {
		return nil, errors.New("empty token")
	}
	tok, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decode token claims: %w", err)
	}
	return &Claims{
		Subject: tok.Subject,
		Email:   raw.Email,
		Name:    raw.Name,
		Groups:  raw.Groups,
	}, nil
}

// Issuer / Audience accessors so the API layer can include them in
// /healthz and audit events for operator visibility.
func (v *HTTPVerifier) Issuer() string   { return v.issuer }
func (v *HTTPVerifier) Audience() string { return v.audience }
