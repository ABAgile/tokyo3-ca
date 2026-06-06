package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

func TestTrustBundle_ServesConfiguredFile(t *testing.T) {
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	bundle := "-----BEGIN CERTIFICATE-----\nZHVtbXk=\n-----END CERTIFICATE-----\n"
	path := filepath.Join(t.TempDir(), "bundle.crt")
	if err := os.WriteFile(path, []byte(bundle), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	srv, err := api.New(api.Config{Log: silentLogger(), CASigner: sig, TrustBundlePath: path})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x509/trust-bundle", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Errorf("body missing PEM: %s", rec.Body.String())
	}
}

func TestTrustBundle_503WhenUnconfigured(t *testing.T) {
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	srv, err := api.New(api.Config{Log: silentLogger(), CASigner: sig})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x509/trust-bundle", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
