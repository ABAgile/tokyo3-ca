package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

func TestRoutes_Revoke_RecordsEntryAndAppearsInSnapshot(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	store := krl.NewInMemoryStore()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		KRL:      store,
	})

	body, _ := json.Marshal(map[string]any{
		"serial": 42,
		"key_id": "user:alice@example.com",
		"reason": "key compromised",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/ssh/revoke: status = %d body=%s", rec.Code, rec.Body.String())
	}

	if !store.IsRevoked(42, "") {
		t.Error("store missing serial 42")
	}
	if !store.IsRevoked(0, "user:alice@example.com") {
		t.Error("store missing key_id user:alice@example.com")
	}

	// GET /api/v1/ssh/revocations returns the same entry.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/ssh/revocations", nil)
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET revocations: status = %d", rec.Code)
	}
	var snap struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if len(snap.Entries) != 1 {
		t.Fatalf("entries len = %d, want 1; body=%s", len(snap.Entries), rec.Body.String())
	}
	got := snap.Entries[0]
	if got["serial"].(float64) != 42 {
		t.Errorf("serial = %v, want 42", got["serial"])
	}
	if got["key_id"] != "user:alice@example.com" {
		t.Errorf("key_id = %v", got["key_id"])
	}
	if got["reason"] != "key compromised" {
		t.Errorf("reason = %v", got["reason"])
	}
}

func TestRoutes_Revoke_RejectsEmptyRequest(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		KRL:      krl.NewInMemoryStore(),
	})

	body, _ := json.Marshal(map[string]any{"reason": "test"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "serial or key_id") {
		t.Errorf("body should mention missing fields: %s", rec.Body.String())
	}
}

func TestRoutes_Revoke_503WhenKRLNotConfigured(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		// KRL omitted
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/revoke", strings.NewReader(`{"serial":1}`))
	req.Header.Set("Content-Type", "application/json")
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestRoutes_Revocations_503WhenKRLNotConfigured(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		// KRL omitted
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/revocations", nil)
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestRoutes_Revoke_EmitsAuditEvent(t *testing.T) {
	caSig, _ := signer.NewEphemeralEd25519()
	cap := &captureSink{}
	srv := mustNewServer(t, api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		KRL:      krl.NewInMemoryStore(),
		Audit:    journal.NewJSONSink[audit.Entry](cap),
	})

	body, _ := json.Marshal(map[string]any{
		"serial": 99, "reason": "test revoke",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	entries := cap.entries(t)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Action != "ssh.cert.revoked" {
		t.Errorf("Action = %q", entries[0].Action)
	}
	if entries[0].Serial != 99 {
		t.Errorf("Serial = %d, want 99", entries[0].Serial)
	}
	if !strings.Contains(entries[0].Metadata, "test revoke") {
		t.Errorf("Metadata missing reason: %q", entries[0].Metadata)
	}
}
