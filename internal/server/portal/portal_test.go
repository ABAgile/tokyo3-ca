package portal_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

// stubHostStore is the portal.HostStore test double.
type stubHostStore struct{ hosts []mtls.Principal }

func (s *stubHostStore) All() []mtls.Principal { return s.hosts }

// stubRoleStore is the read-only portal.RoleStore test double — used
// to confirm the CRUD-write routes return 405 when the store is
// read-only.
type stubRoleStore struct{ roles []policy.Role }

func (s *stubRoleStore) All() []policy.Role { return s.roles }

// newClient returns an *http.Client that refuses to follow redirects.
// The CRUD-write routes return 303 redirects on success; tests want
// to assert on the Location header rather than the destination body.
func newClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// postForm runs a GET against the form's typical entry page to
// acquire a CSRF cookie + token, then submits the POST with the
// matching csrf_token field + cookie. Tests calling postForm don't
// need to know about the CSRF wiring — adding a new POST route's
// happy path keeps working.
func postForm(t *testing.T, postURL string, form url.Values) *http.Response {
	t.Helper()
	client := newClient()

	// The GET page corresponding to this POST. /edit + /delete map
	// to the detail page (/roles/{name}); /new and /revocations use
	// the same URL for both methods (the form is rendered on the
	// page the POST targets). Strip only the read-on-different-URL
	// suffixes so /roles/{name}/edit and /roles/{name}/delete both
	// hit /roles/{name} (which now sets a CSRF cookie).
	getURL := postURL
	for _, suffix := range []string{"/edit", "/delete"} {
		if before, ok := strings.CutSuffix(getURL, suffix); ok {
			getURL = before
			break
		}
	}
	getResp, err := client.Get(getURL)
	if err != nil {
		t.Fatalf("CSRF prefetch GET %s: %v", getURL, err)
	}
	defer getResp.Body.Close()
	_, _ = io.Copy(io.Discard, getResp.Body)

	var token string
	for _, c := range getResp.Cookies() {
		if c.Name == "certd_csrf" {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatalf("CSRF prefetch returned no cookie for %s", getURL)
	}
	// Insert the token into the form. Caller-supplied values win
	// (for tests that want to deliberately submit a bad token).
	if _, present := form["csrf_token"]; !present {
		if form == nil {
			form = url.Values{}
		}
		form.Set("csrf_token", token)
	}

	req, err := http.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "certd_csrf", Value: token})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", postURL, err)
	}
	return resp
}

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
	for _, planned := range []string{`href="/portal/roles"`, `href="/portal/audit"`, `href="/portal/hosts"`} {
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
	if !strings.Contains(body, `<a href="/portal/roles">Roles</a>`) {
		t.Errorf("Roles entry not clickable when RoleStore is wired:\n%s", body)
	}
}

func TestPortal_RolesIndex_ListsConfiguredRoles(t *testing.T) {
	store := &stubRoleStore{roles: []policy.Role{
		{
			Name:                  "eng-prod",
			GroupClaim:            "eng",
			AllowedPrincipals:     []string{"alice", "deployer"},
			HostPatterns:          []string{"*.prod.internal"},
			MaxUserCertTTLSeconds: int64((4 * time.Hour).Seconds()),
		},
		{
			Name:                  "sre",
			GroupClaim:            "sre",
			HostPatterns:          []string{"*.internal"},
			MaxHostCertTTLSeconds: int64((30 * 24 * time.Hour).Seconds()),
		},
	}}
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/roles")
	for _, want := range []string{
		`<h1>Roles</h1>`,
		`<a href="/portal/roles/eng-prod">eng-prod</a>`,
		`<a href="/portal/roles/sre">sre</a>`,
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
			Name:                  "eng-prod",
			GroupClaim:            "eng",
			AllowedPrincipals:     []string{"alice"},
			HostPatterns:          []string{"*.prod.internal"},
			SPIFFEPatterns:        []string{"spiffe://corp/svc/*"},
			MaxUserCertTTLSeconds: int64((4 * time.Hour).Seconds()),
			DefaultExtensions:     map[string]string{"permit-pty": ""},
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

func TestPortal_RoleNewForm_RendersEmpty(t *testing.T) {
	store := policy.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/roles/new")
	for _, want := range []string{
		`<h1>New role</h1>`,
		`name="name"`,
		`name="group_claim"`,
		`name="allowed_principals"`,
		`Create role`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_RoleCreate_AddsRoleAndRedirects(t *testing.T) {
	store := policy.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/roles/new", url.Values{
		"name":                      {"eng-prod"},
		"group_claim":               {"eng"},
		"allowed_principals":        {"alice\nbob"},
		"host_patterns":             {"*.prod.internal"},
		"max_user_cert_ttl_seconds": {"14400"},
		"default_extensions":        {"permit-pty\npermit-port-forwarding=yes"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", resp.StatusCode, readAll(t, resp))
	}
	if loc := resp.Header.Get("Location"); loc != "/portal/roles/eng-prod" {
		t.Errorf("Location = %q, want /portal/roles/eng-prod", loc)
	}

	// Store now holds the role with parsed fields.
	r, ok := store.ByName("eng-prod")
	if !ok {
		t.Fatal("role not added to store")
	}
	if len(r.AllowedPrincipals) != 2 || r.AllowedPrincipals[1] != "bob" {
		t.Errorf("AllowedPrincipals = %v", r.AllowedPrincipals)
	}
	if r.MaxUserCertTTLSeconds != int64((4 * time.Hour).Seconds()) {
		t.Errorf("MaxUserCertTTLSeconds = %v", r.MaxUserCertTTLSeconds)
	}
	if r.DefaultExtensions["permit-pty"] != "" || r.DefaultExtensions["permit-port-forwarding"] != "yes" {
		t.Errorf("DefaultExtensions = %v", r.DefaultExtensions)
	}
}

func TestPortal_RoleCreate_ValidationErrorRendersForm(t *testing.T) {
	store := policy.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	// Missing required name field → 400 with the form re-rendered
	// and the typed group_claim preserved.
	resp := postForm(t, srv.URL+"/roles/new", url.Values{
		"group_claim": {"eng"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "name is required") {
		t.Errorf("body missing error banner:\n%s", body)
	}
	if !strings.Contains(body, `value="eng"`) {
		t.Errorf("body should preserve typed group_claim:\n%s", body)
	}
	if len(store.All()) != 0 {
		t.Errorf("nothing should have been added to the store")
	}
}

func TestPortal_RoleCreate_DuplicateName_400(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{Name: "eng", GroupClaim: "eng"})
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/roles/new", url.Values{
		"name":        {"eng"},
		"group_claim": {"eng"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if body := readAll(t, resp); !strings.Contains(body, "already exists") {
		t.Errorf("body missing ErrRoleExists message:\n%s", body)
	}
}

func TestPortal_RoleEditForm_PreFillsFromStore(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name:                  "eng",
		GroupClaim:            "eng",
		AllowedPrincipals:     []string{"alice"},
		MaxUserCertTTLSeconds: int64((4 * time.Hour).Seconds()),
		DefaultExtensions:     map[string]string{"permit-pty": ""},
	})
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/roles/eng/edit")
	for _, want := range []string{
		`<h1>Edit role: eng</h1>`,
		`value="eng"`,
		`>alice<`,
		`value="14400"`,
		`>permit-pty<`,
		`Save changes`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_RoleUpdate_SavesAndRedirects(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{Name: "eng", GroupClaim: "eng"})
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/roles/eng/edit", url.Values{
		"name":               {"eng"},
		"group_claim":        {"eng"},
		"allowed_principals": {"alice\nbob"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	r, _ := store.ByName("eng")
	if len(r.AllowedPrincipals) != 2 {
		t.Errorf("AllowedPrincipals = %v", r.AllowedPrincipals)
	}
}

func TestPortal_RoleUpdate_AllowsRename(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{Name: "eng", GroupClaim: "eng"})
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/roles/eng/edit", url.Values{
		"name":        {"engineering"},
		"group_claim": {"eng"},
	})
	defer resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/portal/roles/engineering" {
		t.Errorf("Location = %q, want /portal/roles/engineering", loc)
	}
	if _, ok := store.ByName("eng"); ok {
		t.Error("old name still present")
	}
	if _, ok := store.ByName("engineering"); !ok {
		t.Error("renamed role missing")
	}
}

func TestPortal_RoleDelete_RemovesAndRedirects(t *testing.T) {
	store := policy.NewInMemoryStore(
		policy.Role{Name: "eng", GroupClaim: "eng"},
		policy.Role{Name: "sre", GroupClaim: "sre"},
	)
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/roles/eng/delete", url.Values{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/portal/roles" {
		t.Errorf("Location = %q, want /portal/roles", loc)
	}
	if _, ok := store.ByName("eng"); ok {
		t.Error("eng still present after delete")
	}
}

func TestPortal_RoleCRUD_ReadOnlyStoreReturns405(t *testing.T) {
	// Stub store implements RoleStore but not MutableRoleStore.
	store := &stubRoleStore{roles: []policy.Role{{Name: "eng", GroupClaim: "eng"}}}
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/roles/new"},
		{http.MethodPost, "/roles/new"},
		{http.MethodGet, "/roles/eng/edit"},
		{http.MethodPost, "/roles/eng/edit"},
		{http.MethodPost, "/roles/eng/delete"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, srv.URL+tc.path, nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := newClient().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405", resp.StatusCode)
			}
		})
	}
}

func TestPortal_Index_FlipsHostsToReadyWhenHostStoreWired(t *testing.T) {
	p, err := portal.New(portal.Config{
		Version:   "v",
		Now:       func() time.Time { return time.Now() },
		HostStore: &stubHostStore{},
	})
	if err != nil {
		t.Fatalf("portal.New: %v", err)
	}
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/")
	if !strings.Contains(body, `<a href="/portal/hosts">Hosts</a>`) {
		t.Errorf("Hosts entry not clickable when HostStore is wired:\n%s", body)
	}
}

func TestPortal_HostsIndex_ListsRegisteredPrincipals(t *testing.T) {
	store := &stubHostStore{hosts: []mtls.Principal{
		{Name: "ssh-proxyd", MatchedSAN: "spiffe://corp/svc/ssh-proxyd", Groups: []string{"ssh-proxy-service"}},
		{Name: "ops-bot", MatchedSAN: "ops@corp.com", Groups: []string{"ops", "engineering"}},
	}}
	p, _ := portal.New(portal.Config{Version: "v", HostStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/hosts")
	for _, want := range []string{
		`<h1>Hosts</h1>`,
		`<code>spiffe://corp/svc/ssh-proxyd</code>`,
		`<code>ops@corp.com</code>`,
		`ssh-proxyd`,
		`ops-bot`,
		`<code>ssh-proxy-service</code>`,
		`<code>ops</code>`,
		`<code>engineering</code>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_HostsIndex_SortsBySAN(t *testing.T) {
	// Intentionally insert in non-alphabetic order; the page must
	// render them sorted by MatchedSAN so the output is stable
	// across refreshes regardless of the underlying store's
	// iteration order.
	store := &stubHostStore{hosts: []mtls.Principal{
		{Name: "z-svc", MatchedSAN: "spiffe://corp/zzz", Groups: []string{"z"}},
		{Name: "a-svc", MatchedSAN: "spiffe://corp/aaa", Groups: []string{"a"}},
		{Name: "m-svc", MatchedSAN: "spiffe://corp/mmm", Groups: []string{"m"}},
	}}
	p, _ := portal.New(portal.Config{Version: "v", HostStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/hosts")
	aIdx := strings.Index(body, "spiffe://corp/aaa")
	mIdx := strings.Index(body, "spiffe://corp/mmm")
	zIdx := strings.Index(body, "spiffe://corp/zzz")
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Errorf("hosts not sorted by SAN; idx a=%d m=%d z=%d", aIdx, mIdx, zIdx)
	}
}

func TestPortal_HostsIndex_EmptyStore(t *testing.T) {
	p, _ := portal.New(portal.Config{Version: "v", HostStore: &stubHostStore{}, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/hosts")
	if !strings.Contains(body, "<em>No hosts registered.</em>") {
		t.Errorf("expected empty-state message:\n%s", body)
	}
}

func TestPortal_HostsIndex_503WhenNoHostStore(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/hosts")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestPortal_RoleUpdate_InvalidTTL_PreservesInputs(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{Name: "eng", GroupClaim: "eng"})
	p, _ := portal.New(portal.Config{Version: "v", RoleStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/roles/eng/edit", url.Values{
		"name":                      {"eng"},
		"group_claim":               {"eng"},
		"max_user_cert_ttl_seconds": {"not-a-number"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "max_user_cert_ttl_seconds") {
		t.Errorf("body should name the bad field:\n%s", body)
	}
	if !strings.Contains(body, `value="not-a-number"`) {
		t.Errorf("body should preserve invalid input:\n%s", body)
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
