package portal_test

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

	"github.com/abagile/tokyo3-base/oidc"

	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

// The Authorization-Code + PKCE flow, the encrypted session/flow cookies, and
// the admin-group gate now live in github.com/abagile/tokyo3-base/oidc and are
// unit-tested there. These tests assert certd's portal wiring of that
// Authenticator: the gate is mounted, /healthz is exempt, the login redirect
// requests the groups scope, and a full login establishes a gated session.

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

var oidcFixedNow = time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)

func newOIDCPortal(t *testing.T, v oidc.TokenVerifier, issuer, adminGroup string) *portal.Server {
	t.Helper()
	s, err := portal.New(portal.Config{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return oidcFixedNow },
		OIDC: portal.OIDCConfig{
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

func TestRequirePortalAuthGate(t *testing.T) {
	s := newOIDCPortal(t, &fakeVerifier{}, "https://idp.example", "ca-portal-admin")
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

	// /healthz is exempt from the gate.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200 (exempt)", rec.Code)
	}
}

func TestLoginRedirect(t *testing.T) {
	s := newOIDCPortal(t, &fakeVerifier{}, "https://idp.example", "ca-portal-admin")
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
	if findCookie(rec.Result().Cookies(), "certd_portal_flow") == nil {
		t.Error("login did not set the flow cookie")
	}
}

func TestCallbackBadState(t *testing.T) {
	s := newOIDCPortal(t, &fakeVerifier{}, "https://idp.example", "")
	h := s.Routes()
	// Obtain a valid flow cookie via /auth/login, then replay the callback
	// with a mismatched state — the Authenticator must reject it.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	fc := findCookie(rec.Result().Cookies(), "certd_portal_flow")
	if fc == nil {
		t.Fatal("no flow cookie from login")
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=WRONG", nil)
	req.AddCookie(fc)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("callback bad state = %d, want 400", rec.Code)
	}
}

// TestFullLoginFlow drives login → IdP token exchange (faked) → callback →
// authenticated request, asserting the admin-group session is established and
// a non-admin session is rejected by the gate.
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
	s := newOIDCPortal(t, fv, tokenSrv.URL, "ca-portal-admin")
	h := s.Routes()

	// 1) Login → grab the flow cookie.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	fc := findCookie(rec.Result().Cookies(), "certd_portal_flow")
	if fc == nil {
		t.Fatal("no flow cookie from login")
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")
	fv.claims.Nonce = loc.Query().Get("nonce") // IdP echoes the nonce into the ID token

	// 2) Callback with the matching state + the flow cookie.
	rec = httptest.NewRecorder()
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=xyz&state="+url.QueryEscape(state), nil)
	cb.AddCookie(fc)
	h.ServeHTTP(rec, cb)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback = %d, want 303 (body: %s)", rec.Code, rec.Body.String())
	}
	sc := findCookie(rec.Result().Cookies(), "certd_portal_session")
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
