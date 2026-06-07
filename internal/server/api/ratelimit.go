package api

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiter is a per-source-IP token-bucket limiter guarding the API
// surface. It is keyed on the IP of the immediate TCP peer (r.RemoteAddr),
// NOT X-Forwarded-For — so it cannot be bypassed by spoofing that header.
// X-Forwarded-For is consulted only when the peer is itself a configured
// trusted proxy, in which case the rightmost hop that is not trusted is
// used as the key (the real client as seen by infrastructure we control).
//
// This is per-instance, in-process defense-in-depth: it shields the
// expensive auth path (OIDC/mTLS verification) and the CA signer from a
// single-source flood. It is NOT a substitute for an upstream LB/WAF
// against volumetric DoS, and under active-active certd the effective
// limit applies per replica.
type rateLimiter struct {
	rps     rate.Limit
	burst   int
	trusted []*net.IPNet

	mu        sync.Mutex
	buckets   map[string]*ipBucket
	lastSweep time.Time
}

// ipBucket is one source's token bucket plus its last-seen time, used to
// evict idle entries so a stream of distinct keys can't grow the map without
// bound.
type ipBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

const (
	// rlIdleTTL is how long an idle bucket survives before a sweep evicts
	// it — long enough to span a cert-agentd renewal gap, short enough to
	// bound memory.
	rlIdleTTL = 15 * time.Minute
	// rlSweepInterval throttles the opportunistic GC: at most one pass per
	// interval, run lazily when a new key is first seen. No background
	// goroutine, so there is nothing to start, stop, or leak in tests.
	rlSweepInterval = 5 * time.Minute
)

// newRateLimiter builds a limiter allowing rps requests/second per source
// with the given burst. Returns nil when rps <= 0, which disables rate
// limiting entirely (the [Server.rateLimit] wrapper then passes through).
func newRateLimiter(rps float64, burst int, trusted []*net.IPNet) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rps:     rate.Limit(rps),
		burst:   burst,
		trusted: trusted,
		buckets: make(map[string]*ipBucket),
	}
}

// allow reports whether a request from key may proceed, consuming a token.
// now is passed in (rather than read internally) so tests can drive time.
func (rl *rateLimiter) allow(key string, now time.Time) bool {
	rl.mu.Lock()
	b, ok := rl.buckets[key]
	if !ok {
		rl.sweepLocked(now)
		b = &ipBucket{lim: rate.NewLimiter(rl.rps, rl.burst)}
		rl.buckets[key] = b
	}
	b.seen = now
	rl.mu.Unlock()
	return b.lim.AllowN(now, 1)
}

// sweepLocked drops idle buckets. The caller holds rl.mu. It is rate-limited
// to one pass per rlSweepInterval so it stays O(1) amortized on the hot path.
func (rl *rateLimiter) sweepLocked(now time.Time) {
	if !rl.lastSweep.IsZero() && now.Sub(rl.lastSweep) < rlSweepInterval {
		return
	}
	rl.lastSweep = now
	for k, b := range rl.buckets {
		if now.Sub(b.seen) > rlIdleTTL {
			delete(rl.buckets, k)
		}
	}
}

// key returns the rate-limit key for r: the immediate peer IP, or — when
// that peer is a trusted proxy — the rightmost X-Forwarded-For hop that is
// not itself trusted (the real client as seen by our own edge). Walking
// right-to-left and stopping at the first untrusted hop defeats a client
// that pre-seeds X-Forwarded-For to spoof its source.
func (rl *rateLimiter) key(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if len(rl.trusted) == 0 || !rl.isTrusted(peer) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip != "" && !rl.isTrusted(ip) {
			return ip
		}
	}
	return peer
}

func (rl *rateLimiter) isTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range rl.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// retryAfter is a coarse Retry-After hint (whole seconds, ≥1): the time for
// one token to refill.
func (rl *rateLimiter) retryAfter() string {
	secs := max(int(math.Ceil(1/float64(rl.rps))), 1)
	return strconv.Itoa(secs)
}

func hostOnly(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// rateLimit wraps next with per-source-IP token-bucket limiting. It returns
// next unchanged when the limiter is disabled (nil), so non-rate-limited
// deployments and tests are unaffected. GET /healthz is always exempt so
// monitoring probes are never throttled.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	rl := s.rateLimiter
	if rl == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		key := rl.key(r)
		if !rl.allow(key, time.Now()) {
			w.Header().Set("Retry-After", rl.retryAfter())
			s.log.Warn("rate limit exceeded", "source", key, "path", r.URL.Path)
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
