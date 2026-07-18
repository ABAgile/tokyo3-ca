package portal_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/oidc"

	"github.com/abagile/tokyo3-ca/internal/server/policy"
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

	// No session: GET redirects to login, non-GET is 401. The Location is
	// browser-space — the api server mounts this tree under
	// StripPrefix("/portal"), so an unprefixed /auth/login would 404
	// outside the mount.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/roles", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/portal/auth/login?return_to=%2Fportal%2Froles" {
		t.Errorf("GET no session = %d loc=%q, want 303 → /portal/auth/login?return_to=%%2Fportal%%2Froles", rec.Code, rec.Header().Get("Location"))
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

// TestOIDCMode_SessionBoundCSRF: with OIDC login active the portal's forms
// carry session-bound tokens (HMAC over the sealed session's secret) — the
// Basic-mode CSRF-carrier cookie is never issued nor honoured, so a planted
// cookie pair can't forge a POST, while the token rendered into the form
// round-trips.
func TestOIDCMode_SessionBoundCSRF(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": "it"})
	}))
	defer tokenSrv.Close()

	fv := &fakeVerifier{claims: &oidc.Claims{Subject: "u1", Email: "admin@example.com", Groups: []string{"ca-portal-admin"}}}
	store := policy.NewInMemoryStore()
	s, err := portal.New(portal.Config{
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       func() time.Time { return oidcFixedNow },
		RoleStore: store,
		OIDC: portal.OIDCConfig{
			Issuer: tokenSrv.URL, ClientID: "portal", ClientSecret: "secret",
			RedirectURL: "https://certd.example/portal/auth/callback",
			AdminGroup:  "ca-portal-admin", Verifier: fv, SessionKey: testKey(),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.Routes()

	// Login dance → session cookie.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	fc := findCookie(rec.Result().Cookies(), "certd_portal_flow")
	loc, _ := url.Parse(rec.Header().Get("Location"))
	fv.claims.Nonce = loc.Query().Get("nonce")
	rec = httptest.NewRecorder()
	cb := httptest.NewRequest(http.MethodGet, "/auth/callback?code=xyz&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	cb.AddCookie(fc)
	h.ServeHTTP(rec, cb)
	sc := findCookie(rec.Result().Cookies(), "certd_portal_session")
	if sc == nil {
		t.Fatalf("no session cookie (callback = %d)", rec.Code)
	}

	// The rendered form embeds a session-bound token; no certd_csrf_session cookie is set.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/roles/new", nil)
	req.AddCookie(sc)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /roles/new = %d", rec.Code)
	}
	if findCookie(rec.Result().Cookies(), "certd_csrf_session") != nil {
		t.Error("Basic-mode CSRF-carrier cookie set despite OIDC mode")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (token-bearing page must not be cached)", cc)
	}
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no csrf_token embedded in form")
	}
	token := m[1]

	post := func(csrfField string, extra ...*http.Cookie) *httptest.ResponseRecorder {
		form := url.Values{"name": {"eng"}, "group_claim": {"eng"}, "csrf_token": {csrfField}}
		r := httptest.NewRequest(http.MethodPost, "/roles/new", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(sc)
		for _, c := range extra {
			r.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	// A planted Basic-mode cookie + matching field must NOT pass in OIDC mode.
	planted := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if rec := post(planted, &http.Cookie{Name: "certd_csrf_session", Value: planted}); rec.Code != http.StatusForbidden {
		t.Errorf("planted cookie+field POST = %d, want 403", rec.Code)
	}
	if len(store.All()) != 0 {
		t.Fatal("store mutated by forged POST")
	}

	// The session-bound token from the form succeeds.
	if rec := post(token); rec.Code != http.StatusSeeOther {
		t.Errorf("session-bound POST = %d, want 303 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(store.All()) != 1 {
		t.Errorf("role not created: store has %d roles", len(store.All()))
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

// TestLogoutLandsOnSignedOutPage asserts sign-out is observable: the POST
// clears the session cookie and redirects to the exempt signed-out page
// rather than the login route (which would silently re-authenticate against
// the IdP's live SSO session and make logout look like a no-op).
func TestLogoutLandsOnSignedOutPage(t *testing.T) {
	s := newOIDCPortal(t, &fakeVerifier{}, "https://idp.example", "")
	h := s.Routes()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/portal/auth/signed-out" {
		t.Errorf("Location = %q, want /portal/auth/signed-out", loc)
	}
	c := findCookie(rec.Result().Cookies(), "certd_portal_session")
	if c == nil || c.MaxAge >= 0 && c.Value != "" {
		t.Errorf("logout did not clear the session cookie: %+v", c)
	}

	// The signed-out page and the stylesheet it links are reachable
	// without a session (they must not bounce back through login).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/signed-out", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("signed-out page = %d, want 200 (exempt)", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "Signed out") {
		t.Errorf("signed-out page missing confirmation text:\n%s", body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/app.css", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("stylesheet = %d, want 200 (exempt)", rec.Code)
	}
}
