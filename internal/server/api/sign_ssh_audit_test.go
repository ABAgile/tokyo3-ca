package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// doSignUserWithHeaders issues a sign-user POST with the given
// headers applied to the request.
func doSignUserWithHeaders(srv *api.Server, subjectAuthKey string, headers map[string]string) *httptest.ResponseRecorder {
	body := map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/sign-user", &buf)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// captureSink implements journal.Sink by retaining every published
// payload in memory. Wrap with journal.NewJSONSink[audit.Entry] to
// get an audit.Sink the API layer can call.
type captureSink struct {
	mu  sync.Mutex
	raw [][]byte
}

func (s *captureSink) Append(_ context.Context, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	s.raw = append(s.raw, cp)
	return nil
}

func (s *captureSink) Close() error { return nil }

func (s *captureSink) entries(t *testing.T) []audit.Entry {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.Entry, 0, len(s.raw))
	for _, b := range s.raw {
		var e audit.Entry
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatalf("decode captured entry: %v; raw=%s", err, string(b))
		}
		out = append(out, e)
	}
	return out
}

// newAuditServer builds a Server with an audit capture sink plus
// any extra config knobs the test cares about.
func newAuditServer(t *testing.T, ver oidc.TokenVerifier, store mtls.Store, roles ...policy.Role) (*api.Server, *captureSink, string) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	_, _, subjectAuthKey, _ := newSignServer(t)

	cap := &captureSink{}
	sink := journal.NewJSONSink[audit.Entry](cap)

	cfg := api.Config{
		Log:          silentLogger(),
		CASigner:     caSig,
		OIDCVerifier: ver,
		MTLSStore:    store,
		Audit:        sink,
	}
	if len(roles) > 0 {
		cfg.Policy = policy.NewEngine(policy.NewInMemoryStore(roles...))
	}
	srv, err := api.New(cfg)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return srv, cap, subjectAuthKey
}

// ── happy-path emission ───────────────────────────────────────────────────────

func TestAudit_SignUserCert_EmitsSignedEvent(t *testing.T) {
	srv, cap, subjectAuthKey := newAuditServer(t,
		stubVerifier{claims: &oidc.Claims{Subject: "user-uuid", Email: "alice@example.com", Groups: []string{"eng"}}},
		nil,
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignWithToken(srv, "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice@example.com",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	entries := cap.entries(t)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1; got=%v", len(entries), entries)
	}
	e := entries[0]
	if e.Action != audit.ActionSSHUserCertSigned {
		t.Errorf("Action = %q, want %q", e.Action, audit.ActionSSHUserCertSigned)
	}
	if e.Subject != "user:user:alice@example.com" {
		t.Errorf("Subject = %q", e.Subject)
	}
	if e.Caller != "oidc:alice@example.com" {
		t.Errorf("Caller = %q, want oidc:alice@example.com", e.Caller)
	}
	if e.Serial == 0 {
		t.Errorf("Serial = 0; want the cert serial")
	}
	if e.OccurredAt.IsZero() {
		t.Errorf("OccurredAt unset")
	}
	if e.ID == "" {
		t.Errorf("ID empty")
	}

	// Metadata round-trips the structured fields.
	var md map[string]any
	if err := json.Unmarshal([]byte(e.Metadata), &md); err != nil {
		t.Fatalf("decode metadata: %v; raw=%s", err, e.Metadata)
	}
	if got := md["principals"]; got == nil {
		t.Errorf("metadata.principals missing")
	}
	if got := md["ttl_seconds"]; got == nil {
		t.Errorf("metadata.ttl_seconds missing")
	}
}

func TestAudit_SignHostCert_EmitsSignedEvent(t *testing.T) {
	srv, cap, subjectAuthKey := newAuditServer(t,
		stubVerifier{claims: &oidc.Claims{Subject: "tunneld-id", Groups: []string{"tunnel"}}},
		nil,
		policy.Role{Name: "tunnel", GroupClaim: "tunnel", HostPatterns: []string{"db-*.prod.internal"}},
	)

	rec := postJSON(srv, "/api/v1/ssh/sign-host", "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "host:db-1.prod.internal",
		"principals": []string{"db-1.prod.internal"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	entries := cap.entries(t)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d", len(entries))
	}
	if entries[0].Action != audit.ActionSSHHostCertSigned {
		t.Errorf("Action = %q, want %q", entries[0].Action, audit.ActionSSHHostCertSigned)
	}
	if entries[0].Subject != "host:host:db-1.prod.internal" {
		t.Errorf("Subject = %q", entries[0].Subject)
	}
}

// postJSON issues a generic POST to path with optional Authorization
// header. Used by audit tests that hit /sign-host instead of the
// /sign-user default baked into doSignWithToken.
func postJSON(srv *api.Server, path, authHeader string, body map[string]any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// ── denial emission ───────────────────────────────────────────────────────────

func TestAudit_SignUserCert_EmitsDeniedEvent_NoRole(t *testing.T) {
	srv, cap, subjectAuthKey := newAuditServer(t,
		stubVerifier{claims: &oidc.Claims{Email: "alice@example.com", Groups: []string{"random"}}},
		nil,
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignWithToken(srv, "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	entries := cap.entries(t)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1 (denied event)", len(entries))
	}
	if entries[0].Action != audit.ActionSSHUserCertDenied {
		t.Errorf("Action = %q, want %q", entries[0].Action, audit.ActionSSHUserCertDenied)
	}
	if entries[0].Serial != 0 {
		t.Errorf("Serial = %d, want 0 on denial", entries[0].Serial)
	}
	if entries[0].Caller != "oidc:alice@example.com" {
		t.Errorf("Caller = %q", entries[0].Caller)
	}

	var md map[string]any
	if err := json.Unmarshal([]byte(entries[0].Metadata), &md); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if md["reason"] == nil {
		t.Errorf("metadata.reason missing on denial")
	}
}

func TestAudit_SignHostCert_EmitsDeniedEvent(t *testing.T) {
	srv, cap, subjectAuthKey := newAuditServer(t,
		stubVerifier{claims: &oidc.Claims{Email: "alice@example.com", Groups: []string{"staging-admin"}}},
		nil,
		policy.Role{Name: "staging", GroupClaim: "staging-admin", HostPatterns: []string{"*.staging"}},
	)

	// db-1.prod.internal does not match *.staging → 403 denial.
	rec := postJSON(srv, "/api/v1/ssh/sign-host", "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "host:db-1",
		"principals": []string{"db-1.prod.internal"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	entries := cap.entries(t)
	if len(entries) != 1 || entries[0].Action != audit.ActionSSHHostCertDenied {
		t.Errorf("entries = %v, want one ssh.host_cert.denied", entries)
	}
}

// ── caller identity formats ───────────────────────────────────────────────────

func TestAudit_OIDCCallerUsesSubjectWhenEmailEmpty(t *testing.T) {
	srv, cap, subjectAuthKey := newAuditServer(t,
		stubVerifier{claims: &oidc.Claims{Subject: "user-uuid", Groups: []string{"eng"}}}, // no Email
		nil,
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignWithToken(srv, "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := cap.entries(t)[0].Caller; got != "oidc:user-uuid" {
		t.Errorf("Caller = %q, want oidc:user-uuid (sub fallback)", got)
	}
}

func TestAudit_MTLSCallerUsesPrincipalName(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ssh-proxyd-prod",
		MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
		Groups:     []string{"ssh-proxy-service"},
	})
	srv, cap, subjectAuthKey := newAuditServer(t, nil, store,
		policy.Role{Name: "ssh-proxy-service", GroupClaim: "ssh-proxy-service",
			AllowedPrincipals: []string{"alice"}},
	)

	cert := makeClientCert(t, []string{"spiffe://corp/svc/ssh-proxyd"}, nil)
	rec := doSignWithCert(srv, cert, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if got := cap.entries(t)[0].Caller; got != "mtls:ssh-proxyd-prod" {
		t.Errorf("Caller = %q, want mtls:ssh-proxyd-prod", got)
	}
}

func TestAudit_MTLSCallerUsesSANWhenNameEmpty(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		// No Name set; should fall back to MatchedSAN for caller string.
		MatchedSAN: "spiffe://corp/svc/x",
		Groups:     []string{"g"},
	})
	srv, cap, subjectAuthKey := newAuditServer(t, nil, store,
		policy.Role{Name: "g", GroupClaim: "g", AllowedPrincipals: []string{"alice"}},
	)

	cert := makeClientCert(t, []string{"spiffe://corp/svc/x"}, nil)
	rec := doSignWithCert(srv, cert, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := cap.entries(t)[0].Caller; got != "mtls:spiffe://corp/svc/x" {
		t.Errorf("Caller = %q, want SAN fallback", got)
	}
}

func TestAudit_AnonymousCallerWhenNoAuthWired(t *testing.T) {
	// No OIDC, no mTLS — body-groups fallback mode. Caller string
	// should be the anonymous sentinel.
	harness, subjectAuthKey := newSignServerWithCapture(t)

	rec := doJSON(t, harness.srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:k",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	entries := harness.cap.entries(t)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d", len(entries))
	}
	if entries[0].Caller != audit.CallerAnonymous {
		t.Errorf("Caller = %q, want %q", entries[0].Caller, audit.CallerAnonymous)
	}
}

// noAuthServer is the harness for the body-groups-fallback caller
// test: no OIDC or mTLS, no policy — just a server with a capture
// sink and a known subject key.
type noAuthServer struct {
	srv *api.Server
	cap *captureSink
}

func newSignServerWithCapture(t *testing.T) (noAuthServer, string) {
	t.Helper()
	caSig, _ := signer.NewEphemeralEd25519()
	_, _, subjectAuthKey, _ := newSignServer(t)
	cap := &captureSink{}
	sink := journal.NewJSONSink[audit.Entry](cap)
	srv, err := api.New(api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		Audit:    sink,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return noAuthServer{srv: srv, cap: cap}, subjectAuthKey
}

// ── IP capture ───────────────────────────────────────────────────────────────

func TestAudit_IPAndUserAgentCaptured(t *testing.T) {
	srv, cap, subjectAuthKey := newAuditServer(t,
		stubVerifier{claims: &oidc.Claims{Email: "alice@example.com", Groups: []string{"eng"}}},
		nil,
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignWithToken(srv, "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	e := cap.entries(t)[0]
	if e.IP == "" {
		t.Errorf("IP empty; want httptest's default 192.0.2.1")
	}
	// User-Agent is unset by httptest; allow empty but not nil-panicking.
	_ = e.UserAgent
}

func TestAudit_XForwardedForIsUsed(t *testing.T) {
	srv, cap, subjectAuthKey := newAuditServer(t,
		stubVerifier{claims: &oidc.Claims{Email: "alice@example.com", Groups: []string{"eng"}}},
		nil,
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignUserWithHeaders(srv, subjectAuthKey, map[string]string{
		"Authorization":   "Bearer x",
		"X-Forwarded-For": "203.0.113.7, 10.0.0.1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if got := cap.entries(t)[0].IP; got != "203.0.113.7" {
		t.Errorf("IP = %q, want 203.0.113.7 (first XFF entry)", got)
	}
}
