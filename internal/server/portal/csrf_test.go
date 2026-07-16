package portal_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/crypto"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

// TestCSRF_SharedSessionKeySurvivesRestart: OIDCConfig.SessionKey, when
// set without the rest of OIDC, seals the Basic-auth mode's anonymous
// CSRF-carrier session cookie too —
// two independently constructed Servers (standing in for two process
// lifetimes across a restart) sharing that key accept each other's
// cookie+token pairs. Without a configured key, each Server's ephemeral
// key differs, so a cookie from one is rejected by the other.
func TestCSRF_SharedSessionKeySurvivesRestart(t *testing.T) {
	key, err := crypto.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, err := crypto.ParseKEK(key)
	if err != nil {
		t.Fatal(err)
	}

	newServerWithKey := func(k []byte) *portal.Server {
		p, err := portal.New(portal.Config{Version: "v", RoleStore: policy.NewInMemoryStore(), Now: time.Now, OIDC: portal.OIDCConfig{SessionKey: k}})
		if err != nil {
			t.Fatalf("portal.New: %v", err)
		}
		return p
	}
	mintCookieAndField := func(p *portal.Server) (*http.Cookie, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		p.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/roles/new", nil))
		m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(rec.Body.Bytes())
		if m == nil {
			t.Fatal("no csrf_token field in rendered form")
		}
		var cookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == "certd_csrf_session" {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatal("no certd_csrf_session cookie set")
		}
		return cookie, string(m[1])
	}
	validateOn := func(p *portal.Server, cookie *http.Cookie, field string) bool {
		form := url.Values{"name": {"eng"}, "group_claim": {"eng"}, "csrf_token": {field}}
		req := httptest.NewRequest(http.MethodPost, "/roles/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		p.Routes().ServeHTTP(rec, req)
		return rec.Code == http.StatusSeeOther
	}

	// Same configured key across two independent Servers: a "restart"
	// survives — a cookie minted on the first is accepted by the second.
	first := newServerWithKey(parsedKey)
	cookie, field := mintCookieAndField(first)
	second := newServerWithKey(parsedKey)
	if !validateOn(second, cookie, field) {
		t.Error("cookie minted under a shared configured key rejected by a second Server instance")
	}

	// No configured key: each Server's ephemeral key differs, so the same
	// cookie+field pair from one is rejected by the other.
	ephemeralA := newServerWithKey(nil)
	cookieA, fieldA := mintCookieAndField(ephemeralA)
	ephemeralB := newServerWithKey(nil)
	if validateOn(ephemeralB, cookieA, fieldA) {
		t.Error("cookie minted under one ephemeral key accepted by a Server with a different ephemeral key")
	}
}

func TestCSRF_GetIssuesCookie(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version:         "v",
		RoleStore:       policy.NewInMemoryStore(),
		RevocationStore: krl.NewInMemoryStore(),
		Now:             time.Now,
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/roles/new")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got string
	for _, c := range resp.Cookies() {
		if c.Name == "certd_csrf_session" {
			got = c.Value
		}
	}
	if got == "" {
		t.Fatal("expected certd_csrf_session cookie")
	}
	if len(got) < 32 {
		t.Errorf("token length = %d, want >= 32", len(got))
	}
}

func TestCSRF_ReusesCookieAcrossRequests(t *testing.T) {
	// A second GET with the existing cookie should keep the same
	// token — rotation only happens when the cookie is missing or
	// malformed. Stable tokens let a long-running tab submit
	// multiple forms.
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: policy.NewInMemoryStore(), Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	jar := newClient() // refuses redirects but keeps cookies off
	resp1, err := jar.Get(srv.URL + "/roles/new")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	resp1.Body.Close()
	var first string
	for _, c := range resp1.Cookies() {
		if c.Name == "certd_csrf_session" {
			first = c.Value
		}
	}
	if first == "" {
		t.Fatal("no cookie on first GET")
	}

	// Second GET with the cookie attached: server should not rotate.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/roles/new", nil)
	req.AddCookie(&http.Cookie{Name: "certd_csrf_session", Value: first})
	resp2, err := jar.Do(req)
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	resp2.Body.Close()
	for _, c := range resp2.Cookies() {
		if c.Name == "certd_csrf_session" && c.Value != first {
			t.Errorf("token rotated on second GET; first=%q, second=%q", first, c.Value)
		}
	}
}

func TestCSRF_RejectsPostWithoutToken(t *testing.T) {
	store := policy.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	// POST without doing the prefetch — no cookie, no field.
	form := url.Values{"name": {"eng"}, "group_claim": {"eng"}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/roles/new",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := newClient().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if len(store.All()) != 0 {
		t.Errorf("store should not have been mutated")
	}
}

func TestCSRF_RejectsPostWithMismatchedToken(t *testing.T) {
	store := policy.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	// Acquire a real cookie via the prefetch.
	client := newClient()
	g, _ := client.Get(srv.URL + "/roles/new")
	g.Body.Close()
	var cookieValue string
	for _, c := range g.Cookies() {
		if c.Name == "certd_csrf_session" {
			cookieValue = c.Value
		}
	}
	if cookieValue == "" {
		t.Fatal("prefetch did not set cookie")
	}
	// Submit with a DIFFERENT csrf_token in the form body — not derived
	// from the session cookie's CSRF secret, so validation must fail.
	const tampered = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	form := url.Values{
		"name":        {"eng"},
		"group_claim": {"eng"},
		"csrf_token":  {tampered},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/roles/new",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "certd_csrf_session", Value: cookieValue})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (mismatched tokens)", resp.StatusCode)
	}
	if len(store.All()) != 0 {
		t.Errorf("store mutated on mismatched-token POST")
	}
}

func TestCSRF_RejectsRevocationPostWithoutToken(t *testing.T) {
	// Same coverage but for the revocations form — confirms the
	// CSRF gate is universal across mutation endpoints.
	store := krl.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RevocationStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	form := url.Values{"serial": {"42"}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/revocations",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := newClient().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if len(store.Snapshot().Entries) != 0 {
		t.Errorf("revocation store mutated without CSRF")
	}
}

func TestCSRF_RejectsTokenWithBadShape(t *testing.T) {
	// Cookie + form value match, but the shape is too short. The
	// validator should reject before constant-time compare.
	store := policy.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	form := url.Values{
		"name":        {"eng"},
		"group_claim": {"eng"},
		"csrf_token":  {"tooshort"},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/roles/new",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "certd_csrf_session", Value: "tooshort"})
	resp, err := newClient().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (malformed token)", resp.StatusCode)
	}
}

// Compile-time keep-imports
var _ = httptest.NewServer
