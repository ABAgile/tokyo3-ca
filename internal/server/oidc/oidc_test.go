package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/oidc"
)

// fakeIssuer is a minimal in-process OIDC issuer that serves the
// metadata + JWKS documents [HTTPVerifier] needs, and signs tokens
// with a matching RSA key.
type fakeIssuer struct {
	server  *httptest.Server
	priv    *rsa.PrivateKey
	kid     string
	issuer  string
	jwksURL string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	fi := &fakeIssuer{priv: priv, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fi.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", fi.handleJWKS)
	fi.server = httptest.NewServer(mux)
	fi.issuer = fi.server.URL
	fi.jwksURL = fi.server.URL + "/.well-known/jwks.json"
	t.Cleanup(fi.server.Close)
	return fi
}

func (fi *fakeIssuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                fi.issuer,
		"jwks_uri":                              fi.jwksURL,
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (fi *fakeIssuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": fi.kid,
				"alg": "RS256",
				"use": "sig",
				"n":   b64url(fi.priv.N.Bytes()),
				"e":   b64url(intToBytes(fi.priv.E)),
			},
		},
	})
}

// signToken builds an RS256-signed JWT with the given claims and the
// issuer's signing key. Caller fills iss/aud/exp/iat themselves —
// kept minimal so tests can exercise each validation path.
func (fi *fakeIssuer) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": fi.kid, "typ": "JWT"}
	hdrJSON, _ := json.Marshal(header)
	payJSON, _ := json.Marshal(claims)
	signingInput := b64url(hdrJSON) + "." + b64url(payJSON)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, fi.priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + b64url(sig)
}

// b64url is JWS-flavored base64 (URL-safe, no padding).
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// intToBytes returns the minimal big-endian byte slice for e — RSA
// public exponents are conventionally small (65537 = 0x010001).
func intToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	// Trim leading zeros.
	for i, x := range b {
		if x != 0 {
			return b[i:]
		}
	}
	return b[:]
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestNewHTTPVerifier_RejectsEmptyArgs(t *testing.T) {
	_, err := oidc.NewHTTPVerifier(context.Background(), "", "audience")
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("empty issuer: err = %v, want 'issuer' message", err)
	}
	_, err = oidc.NewHTTPVerifier(context.Background(), "https://example.com", "")
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Errorf("empty audience: err = %v, want 'audience' message", err)
	}
}

func TestHTTPVerifier_Verify_HappyPath(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, err := oidc.NewHTTPVerifier(context.Background(), fi.issuer, "certd")
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}

	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{
		"iss":    fi.issuer,
		"aud":    "certd",
		"sub":    "user-uuid-123",
		"email":  "alice@example.com",
		"name":   "Alice",
		"groups": []string{"eng", "sre"},
		"iat":    now,
		"exp":    now + 300,
	})

	claims, err := ver.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-uuid-123" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("Email = %q", claims.Email)
	}
	if claims.Name != "Alice" {
		t.Errorf("Name = %q", claims.Name)
	}
	if want := []string{"eng", "sre"}; fmt.Sprint(claims.Groups) != fmt.Sprint(want) {
		t.Errorf("Groups = %v, want %v", claims.Groups, want)
	}
}

func TestHTTPVerifier_Verify_RejectsExpiredToken(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, "certd")

	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{
		"iss": fi.issuer,
		"aud": "certd",
		"sub": "u",
		"iat": now - 3600,
		"exp": now - 300, // expired 5 min ago
	})

	_, err := ver.Verify(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %q, want to mention 'expired'", err)
	}
}

func TestHTTPVerifier_Verify_RejectsWrongAudience(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, "certd")

	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{
		"iss": fi.issuer,
		"aud": "some-other-app",
		"sub": "u",
		"iat": now,
		"exp": now + 300,
	})

	_, err := ver.Verify(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "audience") {
		t.Errorf("err = %q, want 'audience'", err)
	}
}

func TestHTTPVerifier_Verify_RejectsWrongIssuer(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, "certd")

	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{
		"iss": "https://attacker.example.com",
		"aud": "certd",
		"sub": "u",
		"iat": now,
		"exp": now + 300,
	})

	_, err := ver.Verify(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestHTTPVerifier_Verify_RejectsBadSignature(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, "certd")

	now := time.Now().Unix()
	tok := fi.signToken(t, map[string]any{
		"iss": fi.issuer,
		"aud": "certd",
		"sub": "u",
		"iat": now,
		"exp": now + 300,
	})

	// Tamper with the last byte of the signature.
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[len(sig)-1] ^= 0xff
	parts[2] = b64url(sig)
	tampered := strings.Join(parts, ".")

	_, err := ver.Verify(context.Background(), tampered)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestHTTPVerifier_Verify_RejectsEmptyToken(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, "certd")

	_, err := ver.Verify(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("err = %v, want 'empty'", err)
	}
}

func TestHTTPVerifier_IssuerAudienceAccessors(t *testing.T) {
	fi := newFakeIssuer(t)
	ver, _ := oidc.NewHTTPVerifier(context.Background(), fi.issuer, "certd")
	if got := ver.Issuer(); got != fi.issuer {
		t.Errorf("Issuer() = %q, want %q", got, fi.issuer)
	}
	if got := ver.Audience(); got != "certd" {
		t.Errorf("Audience() = %q, want %q", got, "certd")
	}
}

// Avoid an unused import flake when the helper above is only used in
// signToken — math/big is referenced via fi.priv.N but the linter
// still occasionally flags it across Go versions.
var _ = big.NewInt
