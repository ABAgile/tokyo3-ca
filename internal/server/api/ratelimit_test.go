package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// The per-source-IP token-bucket mechanics (bucket isolation, refill,
// X-Forwarded-For keying, idle sweep) now live in
// github.com/abagile/tokyo3-base/ratelimit and are covered by that package's
// tests. These tests assert certd's Routes() wiring: the limiter is wired with
// the configured RPS/Burst, /healthz is exempt, and the limiter is off by
// default.

func rlTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRoutes_RateLimit429AndRetryAfter(t *testing.T) {
	s, err := New(Config{
		Log:            rlTestLogger(),
		CASigner:       mustSigner(t),
		RateLimitRPS:   1,
		RateLimitBurst: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.Routes()

	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/x509/trust-bundle", nil)
		req.RemoteAddr = "192.0.2.1:5555"
		h.ServeHTTP(rec, req)
		return rec
	}

	first := do()
	if first.Code == http.StatusTooManyRequests {
		t.Fatalf("first request must not be throttled (got 429)")
	}
	second := do()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from same IP should be 429, got %d", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatalf("429 response must set Retry-After")
	}
	// base ratelimit emits a plain-text 429 via http.Error (certd's prior
	// writeError emitted JSON); Retry-After is preserved.
	if ct := second.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("429 Content-Type = %q, want text/plain; charset=utf-8", ct)
	}
}

func TestRoutes_RateLimitExemptsHealthz(t *testing.T) {
	s, err := New(Config{
		Log:            rlTestLogger(),
		CASigner:       mustSigner(t),
		RateLimitRPS:   1,
		RateLimitBurst: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.Routes()
	for i := range 3 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "192.0.2.2:5555"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz request %d should never be throttled, got %d", i, rec.Code)
		}
	}
}

func TestRoutes_NoRateLimitByDefault(t *testing.T) {
	s, err := New(Config{Log: rlTestLogger(), CASigner: mustSigner(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.Routes()
	for i := range 5 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/x509/trust-bundle", nil)
		req.RemoteAddr = "192.0.2.3:5555"
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("rate limiting must be off by default; request %d got 429", i)
		}
	}
}

func mustSigner(t *testing.T) signer.Signer {
	t.Helper()
	s, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}
