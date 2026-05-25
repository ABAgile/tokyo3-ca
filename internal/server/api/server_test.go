package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/portal"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// silentLogger returns a slog.Logger that discards all output, suitable
// for use in tests that don't need to assert on log content.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustNewServer(t *testing.T, cfg api.Config) *api.Server {
	t.Helper()
	s, err := api.New(cfg)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return s
}

func TestNew_RejectsMissingDependencies(t *testing.T) {
	s, _ := signer.NewEphemeralEd25519()

	tests := []struct {
		name    string
		cfg     api.Config
		wantMsg string
	}{
		{
			name:    "missing log",
			cfg:     api.Config{CASigner: s},
			wantMsg: "Log is required",
		},
		{
			name:    "missing CA signer",
			cfg:     api.Config{Log: silentLogger()},
			wantMsg: "CASigner is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := api.New(tc.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q should contain %q", err, tc.wantMsg)
			}
		})
	}
}

func TestNew_DefaultsAuditToNoop(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		// Audit + AuditSource omitted — should default to noop.
	})

	// /healthz reports audit_active=false when defaulted to noop.
	resp := getJSON(t, srv, "/healthz")
	if got := resp["audit_active"]; got != false {
		t.Errorf("audit_active = %v, want false", got)
	}
}

func TestHealthz_ReturnsExpectedFields(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		Audit:    audit.NoopSink,
		Version:  "v0.0.1-test",
	})

	resp := getJSON(t, srv, "/healthz")

	if got := resp["status"]; got != "ok" {
		t.Errorf("status = %v, want ok", got)
	}
	if got := resp["version"]; got != "v0.0.1-test" {
		t.Errorf("version = %v, want v0.0.1-test", got)
	}
	if got, ok := resp["ca_signer"].(string); !ok || !strings.Contains(got, "ed25519") {
		t.Errorf("ca_signer = %v, want a string mentioning ed25519", resp["ca_signer"])
	}
	if got, ok := resp["ca_public_key"].(string); !ok || !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("ca_public_key = %v, want SHA256: prefix", resp["ca_public_key"])
	}
}

func TestRoutes_UnknownPathReturns404(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRoutes_PortalMountedUnderPrefix(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	p, err := portal.New(portal.Config{Version: "test"})
	if err != nil {
		t.Fatalf("portal.New: %v", err)
	}
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		Portal:   p,
	})

	// GET /portal/ resolves to the portal index.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/portal/", nil)
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /portal/: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "certd admin portal") {
		t.Errorf("portal body missing header: %s", body)
	}

	// GET /portal/healthz works too — confirms the StripPrefix is wired.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/portal/healthz", nil)
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /portal/healthz: status = %d, want 200", rec.Code)
	}
}

func TestRoutes_PortalAbsentWhenNotConfigured(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		// Portal omitted — /portal/* must 404.
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/portal/", nil)
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /portal/: status = %d, want 404 (no portal configured)", rec.Code)
	}
}

func TestRoutes_HealthzWrongMethodReturns405(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz status = %d, want 405", rec.Code)
	}
}

// getJSON drives Routes() with a GET to path, decodes the JSON body,
// and returns it. Fails the test on any non-200 or decode error.
func getJSON(t *testing.T, srv *api.Server, path string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200; body=%s", path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return out
}
