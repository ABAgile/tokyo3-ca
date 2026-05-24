package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// makeClientCert builds a leaf cert with the given URI/email SANs —
// the simulated workload identity certd sees on the request.
func makeClientCert(t *testing.T, uris []string, emails []string) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "workload"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: emails,
	}
	for _, u := range uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parse uri: %v", err)
		}
		tmpl.URIs = append(tmpl.URIs, p)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// doSignWithCert builds a sign-user request and attaches a verified
// peer cert to r.TLS — simulating what mTLS termination upstream
// would populate.
func doSignWithCert(srv *api.Server, cert *x509.Certificate, authHeader string, body map[string]any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/sign-user", &buf)
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// newMTLSServer builds a Server with the given mTLS store and
// optional OIDC verifier + policy roles.
func newMTLSServer(t *testing.T, store mtls.Store, ver oidc.TokenVerifier, roles ...policy.Role) (*api.Server, string) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	_, _, subjectAuthKey, _ := newSignServer(t)

	cfg := api.Config{
		Log:          silentLogger(),
		CASigner:     caSig,
		MTLSStore:    store,
		OIDCVerifier: ver,
	}
	if len(roles) > 0 {
		cfg.Policy = policy.NewEngine(policy.NewInMemoryStore(roles...))
	}
	srv, err := api.New(cfg)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return srv, subjectAuthKey
}

// ── /healthz ──────────────────────────────────────────────────────────────────

func TestMTLS_HealthzReportsActive(t *testing.T) {
	store := mtls.NewInMemoryStore()
	srv, _ := newMTLSServer(t, store, nil)
	body := getJSON(t, srv, "/healthz")
	if got := body["mtls_active"]; got != true {
		t.Errorf("mtls_active = %v, want true", got)
	}
}

// ── mTLS-only path ────────────────────────────────────────────────────────────

func TestMTLS_OnlyPath_HappyCertMatchesPrincipal(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	srv, subjectAuthKey := newMTLSServer(t, store, nil, policy.Role{
		Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
		AllowedPrincipals: []string{"alice"},
	})

	cert := makeClientCert(t, []string{"spiffe://corp/svc/ssh-proxyd"}, nil)
	rec := doSignWithCert(srv, cert, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestMTLS_OnlyPath_NoCertReturns401(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	srv, subjectAuthKey := newMTLSServer(t, store, nil, policy.Role{
		Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
		AllowedPrincipals: []string{"alice"},
	})

	rec := doSignWithCert(srv, nil, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestMTLS_OnlyPath_UnknownSANReturns401(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	srv, subjectAuthKey := newMTLSServer(t, store, nil, policy.Role{
		Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
		AllowedPrincipals: []string{"alice"},
	})

	cert := makeClientCert(t, []string{"spiffe://corp/svc/stranger"}, nil)
	rec := doSignWithCert(srv, cert, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "unknown cert principal") {
		t.Errorf("error = %q, want 'unknown cert principal'", msg)
	}
}

func TestMTLS_CertGroupsOverrideBodyGroups(t *testing.T) {
	// Cert grants groups=[ssh-proxy-service] which gives access to
	// "alice". Body lies about being in groups=[unrelated]. Cert
	// must win.
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	srv, subjectAuthKey := newMTLSServer(t, store, nil,
		policy.Role{Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
			AllowedPrincipals: []string{"alice"}},
		policy.Role{Name: "unrelated", GroupClaim: "unrelated",
			AllowedPrincipals: []string{"root"}},
	)

	cert := makeClientCert(t, []string{"spiffe://corp/svc/ssh-proxyd"}, nil)
	rec := doSignWithCert(srv, cert, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
		"groups":     []string{"unrelated"}, // lies
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Principals []string `json:"principals"`
	}
	decodeJSON(t, rec, &resp)
	if !slices.Equal(resp.Principals, []string{"alice"}) {
		t.Errorf("principals = %v, want [alice]", resp.Principals)
	}
}

func TestMTLS_EmailSANMatches(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ops-bot",
		MatchedSAN: "ops@corp.com",
		Groups:     []string{"ops"},
	})
	srv, subjectAuthKey := newMTLSServer(t, store, nil, policy.Role{
		Name: "ops", GroupClaim: "ops",
		AllowedPrincipals: []string{"deploy"},
	})

	cert := makeClientCert(t, nil, []string{"ops@corp.com"})
	rec := doSignWithCert(srv, cert, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:deploy",
		"principals": []string{"deploy"},
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// ── OIDC + mTLS composition ───────────────────────────────────────────────────

func TestMTLS_PlusOIDC_BearerWinsWhenPresent(t *testing.T) {
	// Both paths wired. Cert maps to [ssh-proxy-service], bearer
	// claims [admins]. Bearer should win — its groups end up in
	// policy evaluation.
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	ver := stubVerifier{claims: &oidc.Claims{Groups: []string{"admins"}}}
	srv, subjectAuthKey := newMTLSServer(t, store, ver,
		policy.Role{Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
			AllowedPrincipals: []string{"alice"}},
		policy.Role{Name: "admins", GroupClaim: "admins",
			AllowedPrincipals: []string{"root"}},
	)

	cert := makeClientCert(t, []string{"spiffe://corp/svc/ssh-proxyd"}, nil)
	// Request principal=root which only admins permits — proves
	// bearer-derived groups won.
	rec := doSignWithCert(srv, cert, "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:root",
		"principals": []string{"root"},
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestMTLS_PlusOIDC_FallsThroughToCertWhenNoBearer(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	ver := stubVerifier{claims: &oidc.Claims{Groups: []string{"admins"}}}
	srv, subjectAuthKey := newMTLSServer(t, store, ver, policy.Role{
		Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
		AllowedPrincipals: []string{"alice"},
	})

	cert := makeClientCert(t, []string{"spiffe://corp/svc/ssh-proxyd"}, nil)
	// No bearer → mTLS path runs, returning cert groups.
	rec := doSignWithCert(srv, cert, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestMTLS_PlusOIDC_InvalidBearerDoesNotFallThrough(t *testing.T) {
	// Bearer present but invalid → 401 with no fallback to mTLS,
	// even though a valid cert is also presented. Explicit auth
	// attempt failure must not be silently rescued.
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	ver := stubVerifier{err: errInvalidToken{}}
	srv, subjectAuthKey := newMTLSServer(t, store, ver, policy.Role{
		Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
		AllowedPrincipals: []string{"alice"},
	})

	cert := makeClientCert(t, []string{"spiffe://corp/svc/ssh-proxyd"}, nil)
	rec := doSignWithCert(srv, cert, "Bearer bad", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestMTLS_PlusOIDC_NoBearerNoCert_401(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name: "x", MatchedSAN: "spiffe://corp/x", Groups: []string{"g"},
	})
	ver := stubVerifier{claims: &oidc.Claims{Groups: []string{"g"}}}
	srv, subjectAuthKey := newMTLSServer(t, store, ver, policy.Role{
		Name: "g", GroupClaim: "g", AllowedPrincipals: []string{"alice"},
	})

	rec := doSignWithCert(srv, nil, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// errInvalidToken is a sentinel error for the stub verifier — its
// concrete type doesn't matter, only that Verify returns an error.
type errInvalidToken struct{}

func (errInvalidToken) Error() string { return "invalid token (test stub)" }
