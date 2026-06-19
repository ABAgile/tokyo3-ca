package portal_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

func TestPortal_Revocations_503WhenStoreUnconfigured(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, _ := http.NewRequest(method, srv.URL+"/revocations", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := newClient().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s status = %d, want 503", method, resp.StatusCode)
		}
	}
}

func TestPortal_RevocationsIndex_ListsEntries(t *testing.T) {
	store := krl.NewInMemoryStore()
	_ = store.Revoke(krl.Revocation{Serial: 42, Reason: "compromised"})
	_ = store.Revoke(krl.Revocation{KeyID: "user:eve@example.com", Reason: "left team"})

	p, _ := portal.New(portal.Config{Version: "v", RevocationStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/revocations")
	for _, want := range []string{
		`<h1>Revocations</h1>`,
		`<code>42</code>`,
		`<code>user:eve@example.com</code>`,
		`compromised`,
		`left team`,
		`<form method="post" action="/portal/revocations">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_RevocationsCreate_AddsEntryAndRedirects(t *testing.T) {
	store := krl.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RevocationStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/revocations", url.Values{
		"serial": {"99"},
		"key_id": {"user:test"},
		"reason": {"unit test"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if !store.IsRevoked(99, "") {
		t.Error("serial 99 not in store")
	}
	if !store.IsRevoked(0, "user:test") {
		t.Error("key_id user:test not in store")
	}
	// Revoker was auto-set to "portal".
	got, _ := store.Snapshot().Entries[0], 0
	if got.Revoker != "portal" {
		t.Errorf("Revoker = %q, want portal", got.Revoker)
	}
	if got.Reason != "unit test" {
		t.Errorf("Reason = %q", got.Reason)
	}
}

func TestPortal_RevocationsCreate_RejectsEmpty(t *testing.T) {
	store := krl.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RevocationStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/revocations", url.Values{"reason": {"empty test"}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "serial or key_id is required") {
		t.Errorf("body missing error message:\n%s", body)
	}
	if !strings.Contains(body, `value="empty test"`) {
		t.Errorf("body should preserve typed reason:\n%s", body)
	}
	if len(store.Snapshot().Entries) != 0 {
		t.Errorf("nothing should have been added to the store")
	}
}

func TestPortal_RevocationsCreate_RejectsNonNumericSerial(t *testing.T) {
	store := krl.NewInMemoryStore()
	p, _ := portal.New(portal.Config{Version: "v", RevocationStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp := postForm(t, srv.URL+"/revocations", url.Values{
		"serial": {"abc"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(readAll(t, resp), "not a valid unsigned integer") {
		t.Errorf("body missing parse error")
	}
}

func TestPortal_Index_FlipsRevocationsToReadyWhenStoreWired(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version:         "v",
		Now:             func() time.Time { return time.Now() },
		RevocationStore: krl.NewInMemoryStore(),
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/")
	if !strings.Contains(body, `<a href="/portal/revocations">Revocations</a>`) {
		t.Errorf("Revocations nav entry not clickable when store wired:\n%s", body)
	}
}
