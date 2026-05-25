package portal_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

// stubRoleStore is the portal.RoleStore test double.
type stubRoleStore struct{ roles []policy.Role }

func (s *stubRoleStore) All() []policy.Role { return s.roles }

func newTestPortal(t *testing.T) *portal.Server {
	t.Helper()
	p, err := portal.New(portal.Config{
		Version: "v0.0.1-test",
		Now:     func() time.Time { return time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("portal.New: %v", err)
	}
	return p
}

func TestPortal_Index_RendersLandingPage(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := readAll(t, resp)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"certd admin portal",
		"<title>home · certd</title>",
		"v0.0.1-test",
		"2026-05-26T12:00:00Z", // RFC3339 from the fixed clock
		"Roles",
		"Sessions",
		"Audit",
		"Hosts",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
	// Planned pages do NOT get clickable links — only "ready" ones do.
	// Every entry on the scaffold is "planned", so no anchors should
	// appear pointing at the page paths.
	for _, planned := range []string{`href="/roles"`, `href="/sessions"`, `href="/audit"`, `href="/hosts"`} {
		if strings.Contains(body, planned) {
			t.Errorf("planned page has clickable link: %s", planned)
		}
	}
}

func TestPortal_Healthz_ReturnsPlainOK(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if body := readAll(t, resp); strings.TrimSpace(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}
}

func TestPortal_UnknownRoute_404(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/no-such-page")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPortal_Index_FlipsRolesToReadyWhenRoleStoreWired(t *testing.T) {
	p, err := portal.New(portal.Config{
		Version:   "v",
		Now:       func() time.Time { return time.Now() },
		RoleStore: &stubRoleStore{},
	})
	if err != nil {
		t.Fatalf("portal.New: %v", err)
	}
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/")
	if !strings.Contains(body, `<a href="/roles">Roles</a>`) {
		t.Errorf("Roles entry not clickable when RoleStore is wired:\n%s", body)
	}
}

func TestPortal_RolesIndex_ListsConfiguredRoles(t *testing.T) {
	store := &stubRoleStore{roles: []policy.Role{
		{
			Name:              "eng-prod",
			GroupClaim:        "eng",
			AllowedPrincipals: []string{"alice", "deployer"},
			HostPatterns:      []string{"*.prod.internal"},
			MaxUserCertTTL:    4 * time.Hour,
		},
		{
			Name:           "sre",
			GroupClaim:     "sre",
			HostPatterns:   []string{"*.internal"},
			MaxHostCertTTL: 30 * 24 * time.Hour,
		},
	}}
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/roles")
	for _, want := range []string{
		`<h1>Roles</h1>`,
		`<a href="/roles/eng-prod">eng-prod</a>`,
		`<a href="/roles/sre">sre</a>`,
		`<code>eng</code>`,
		`<code>alice</code>`,
		`<code>deployer</code>`,
		`<code>*.prod.internal</code>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_RolesIndex_EmptyStore(t *testing.T) {
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: &stubRoleStore{}, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/roles")
	if !strings.Contains(body, "<em>No roles configured.</em>") {
		t.Errorf("expected empty-state message:\n%s", body)
	}
}

func TestPortal_RolesIndex_503WhenNoRoleStore(t *testing.T) {
	p := newTestPortal(t) // no RoleStore
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/roles")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestPortal_RoleDetail_FoundRole(t *testing.T) {
	store := &stubRoleStore{roles: []policy.Role{
		{
			Name:              "eng-prod",
			GroupClaim:        "eng",
			AllowedPrincipals: []string{"alice"},
			HostPatterns:      []string{"*.prod.internal"},
			SPIFFEPatterns:    []string{"spiffe://corp/svc/*"},
			MaxUserCertTTL:    4 * time.Hour,
			DefaultExtensions: map[string]string{"permit-pty": ""},
		},
	}}
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/roles/eng-prod")
	for _, want := range []string{
		`<h1>Role: eng-prod</h1>`,
		`<code>eng</code>`,
		`<code>alice</code>`,
		`<code>*.prod.internal</code>`,
		`<code>spiffe://corp/svc/*</code>`,
		`4h0m0s`,
		`<code>permit-pty</code>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_RoleDetail_404ForUnknownRole(t *testing.T) {
	store := &stubRoleStore{roles: []policy.Role{{Name: "exists"}}}
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/roles/ghost")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "No role named") {
		t.Errorf("body missing 'No role named':\n%s", body)
	}
}

func TestPortal_New_DefaultsClockAndLogger(t *testing.T) {
	// nil Log + Now should be filled in without panicking, and
	// subsequent renders must succeed.
	p, err := portal.New(portal.Config{Version: "v"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// getBody dials path and returns the response body, failing the
// test on any non-2xx status. Useful for the happy-path assertions
// that just want the rendered HTML.
func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	return readAll(t, resp)
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}
