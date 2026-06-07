package api

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

func rlTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c, err)
		}
		out = append(out, n)
	}
	return out
}

func TestNewRateLimiter_DisabledWhenRPSZero(t *testing.T) {
	if rl := newRateLimiter(0, 5, nil); rl != nil {
		t.Fatalf("rps=0 should disable rate limiting (got %v)", rl)
	}
	if rl := newRateLimiter(-1, 5, nil); rl != nil {
		t.Fatalf("negative rps should disable rate limiting")
	}
	if rl := newRateLimiter(10, 0, nil); rl == nil || rl.burst != 1 {
		t.Fatalf("burst < 1 should be coerced to 1, got %+v", rl)
	}
}

func TestRateLimiter_BurstThenThrottleThenRefill(t *testing.T) {
	rl := newRateLimiter(1, 2, nil) // 1 rps, burst 2
	t0 := time.Unix(1_000_000, 0)

	if !rl.allow("a", t0) {
		t.Fatalf("1st request (within burst) should be allowed")
	}
	if !rl.allow("a", t0) {
		t.Fatalf("2nd request (within burst) should be allowed")
	}
	if rl.allow("a", t0) {
		t.Fatalf("3rd request in the same instant should be throttled")
	}
	// One token refills after 1s at 1 rps.
	if !rl.allow("a", t0.Add(time.Second)) {
		t.Fatalf("a request 1s later should be allowed after refill")
	}
	if rl.allow("a", t0.Add(time.Second)) {
		t.Fatalf("only one token should have refilled")
	}
}

func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	rl := newRateLimiter(1, 1, nil)
	t0 := time.Unix(1_000_000, 0)
	if !rl.allow("a", t0) {
		t.Fatalf("first request for key a should pass")
	}
	if rl.allow("a", t0) {
		t.Fatalf("key a should now be throttled")
	}
	if !rl.allow("b", t0) {
		t.Fatalf("key b must be unaffected by key a's bucket")
	}
}

func TestRateLimiter_Key_IgnoresXFFWithoutTrustedProxies(t *testing.T) {
	rl := newRateLimiter(1, 1, nil)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/x509/trust-bundle", nil)
	r.RemoteAddr = "198.51.100.4:4444"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := rl.key(r); got != "198.51.100.4" {
		t.Fatalf("without trusted proxies the key must be the peer IP, got %q", got)
	}
}

func TestRateLimiter_Key_TrustedProxyUsesRightmostUntrustedXFF(t *testing.T) {
	rl := newRateLimiter(1, 1, mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/x509/trust-bundle", nil)
	r.RemoteAddr = "10.0.0.1:4444" // peer is a trusted proxy
	// chain: real client, then two internal proxies.
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.1.2.3, 10.0.0.1")
	if got := rl.key(r); got != "203.0.113.7" {
		t.Fatalf("trusted peer should key on rightmost untrusted XFF hop, got %q", got)
	}
}

func TestRateLimiter_Key_UntrustedPeerIgnoresSpoofedXFF(t *testing.T) {
	rl := newRateLimiter(1, 1, mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/x509/trust-bundle", nil)
	r.RemoteAddr = "8.8.8.8:4444"               // not a trusted proxy
	r.Header.Set("X-Forwarded-For", "10.0.0.5") // attempted spoof
	if got := rl.key(r); got != "8.8.8.8" {
		t.Fatalf("untrusted peer must be keyed on its real IP, got %q", got)
	}
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
