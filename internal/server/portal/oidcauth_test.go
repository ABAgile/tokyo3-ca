package portal

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/oidc"
)

type fakeVerifier struct {
	claims *oidc.Claims
	err    error
}

func (f *fakeVerifier) Verify(_ context.Context, _ string) (*oidc.Claims, error) {
	return f.claims, f.err
}

func testKey() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

var fixedNow = time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)

func newOIDCServer(t *testing.T, v oidc.TokenVerifier, issuer, adminGroup string) *Server {
	t.Helper()
	s, err := New(Config{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return fixedNow },
		OIDC: OIDCConfig{
			Issuer:       issuer,
			ClientID:     "portal",
			ClientSecret: "secret",
			RedirectURL:  "https://certd.example/portal/auth/callback",
			AdminGroup:   adminGroup,
			Verifier:     v,
			SessionKey:   testKey(),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func (s *Server) sessionCookieFor(t *testing.T, groups []string) *http.Cookie {
	t.Helper()
	v, err := s.sealValue(session{Email: "a@example.com", Groups: groups, Expiry: fixedNow.Add(time.Hour)})
	if err != nil {
		t.Fatalf("seal session: %v", err)
	}
	return &http.Cookie{Name: sessionCookie, Value: v}
}

func TestRequirePortalAuthGate(t *testing.T) {
	s := newOIDCServer(t, &fakeVerifier{}, "https://idp.example", "ca-portal-admin")
	h := s.Routes()

	// No session: GET redirects to login, non-GET is 401.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/roles", nil))
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/auth/login") {
		t.Errorf("GET no session = %d loc=%q, want 303 → /auth/login", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/roles/new", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST no session = %d, want 401", rec.Code)
	}

	// Authenticated but NOT in the admin group → 403.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(s.sessionCookieFor(t, []string{"other"}))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin session = %d, want 403", rec.Code)
	}

	// Admin group → passes the gate (landing page renders).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(s.sessionCookieFor(t, []string{"ca-portal-admin"}))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("admin session = %d, want 200", rec.Code)
	}

	// /healthz is exempt from the gate.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200 (exempt)", rec.Code)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	s := newOIDCServer(t, &fakeVerifier{}, "https://idp.example", "")
	v, _ := s.sealValue(session{Email: "a@example.com", Expiry: fixedNow.Add(-time.Minute)})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: v})
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("expired session GET = %d, want 303 redirect to login", rec.Code)
	}
}

func TestLoginRedirect(t *testing.T) {
	s := newOIDCServer(t, &fakeVerifier{}, "https://idp.example", "ca-portal-admin")
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/roles", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != "https://idp.example/authorize" {
		t.Errorf("authorize endpoint = %q", loc.Scheme+"://"+loc.Host+loc.Path)
	}
	q := loc.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "portal" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("authorize params wrong: %v", q)
	}
	if !strings.Contains(q.Get("scope"), "groups") {
		t.Errorf("scope %q missing groups", q.Get("scope"))
	}
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Error("authorize missing state/nonce/code_challenge")
	}
	// Flow cookie is set so the callback can validate state/nonce.
	if findCookie(rec.Result().Cookies(), flowCookie) == nil {
		t.Error("login did not set the flow cookie")
	}
}

func TestCallbackBadState(t *testing.T) {
	s := newOIDCServer(t, &fakeVerifier{}, "https://idp.example", "")
	// Forge a flow cookie with a known state, then send a mismatched state.
	flowVal, _ := s.sealValue(oidcFlow{State: "right", Nonce: "n", Verifier: "v", ReturnTo: "/"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=WRONG", nil)
	req.AddCookie(&http.Cookie{Name: flowCookie, Value: flowVal})
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("callback bad state = %d, want 400", rec.Code)
	}
}

// TestFullLoginFlow drives login → IdP token exchange (faked) → callback →
// authenticated request, asserting the admin-group session is established.
func TestFullLoginFlow(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "id_token": "idtok", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer tokenSrv.Close()

	fv := &fakeVerifier{claims: &oidc.Claims{Subject: "u1", Email: "admin@example.com", Groups: []string{"ca-portal-admin"}}}
	s := newOIDCServer(t, fv, tokenSrv.URL, "ca-portal-admin")
	h := s.Routes()

	// 1) Login → grab the flow cookie + decrypt it (the test owns the key) to
	//    learn the per-login state + nonce.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	fc := findCookie(rec.Result().Cookies(), flowCookie)
	if fc == nil {
		t.Fatal("no flow cookie from login")
	}
	var flow oidcFlow
	if err := s.openValue(fc.Value, &flow); err != nil {
		t.Fatalf("open flow cookie: %v", err)
	}
	fv.claims.Nonce = flow.Nonce // IdP echoes the nonce into the ID token

	// 2) Callback with the matching state + the flow cookie.
	rec = httptest.NewRecorder()
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=xyz&state="+url.QueryEscape(flow.State), nil)
	cb.AddCookie(fc)
	h.ServeHTTP(rec, cb)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback = %d, want 303 (body: %s)", rec.Code, rec.Body.String())
	}
	sc := findCookie(rec.Result().Cookies(), sessionCookie)
	if sc == nil {
		t.Fatal("callback did not set a session cookie")
	}

	// 3) The session authenticates a subsequent request through the gate.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sc)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("authenticated GET / = %d, want 200", rec.Code)
	}
}

func findCookie(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}
