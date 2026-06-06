package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/client"
)

func TestClient_FetchTrustBundle(t *testing.T) {
	want := "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/x509/trust-bundle" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(client.TrustBundleResponse{Bundle: want})
	}))
	defer srv.Close()

	c, err := client.NewClient(srv.URL, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := c.FetchTrustBundle(context.Background())
	if err != nil {
		t.Fatalf("FetchTrustBundle: %v", err)
	}
	if got != want {
		t.Errorf("bundle = %q, want %q", got, want)
	}
}
