package portal_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

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
