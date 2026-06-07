// Package mtls authenticates inbound HTTPS callers by their TLS client
// certificate. It complements the OIDC bearer-token path in
// [github.com/abagile/tokyo3-ca/internal/server/oidc]: human users
// authenticate with tokens, workloads (cert-agentd, ssh-proxyd,
// ssh-tunneld) authenticate with their workload mTLS identity.
//
// A [Store] maps the SAN values certd should recognize (SPIFFE URIs
// or email addresses) to a [Principal] that carries the caller's
// effective group claims — the same primitive policy operates on,
// regardless of which auth path produced it.
//
// This slice ships only [InMemoryStore]; the admin portal will add
// the Postgres-backed equivalent.
package mtls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// Principal is a workload identity certd knows about. Name is the
// audit-friendly handle (e.g., "ssh-proxyd-prod-us-east-1"). MatchedSAN
// is whichever SAN value caused the registration to fire, set by
// [Store.Lookup] for downstream audit attribution. Groups carries the
// effective group claims — what policy sees, regardless of whether
// the caller arrived via OIDC or mTLS.
type Principal struct {
	Name       string   `json:"name"`
	MatchedSAN string   `json:"matched_san,omitempty"`
	Groups     []string `json:"groups"`
}

// Store backs the cert-principal registry. Implementations must be
// safe for concurrent use; the engine calls Lookup on every sign
// request that traverses the mTLS path.
type Store interface {
	// Lookup matches the SANs presented by the caller's TLS cert
	// against the registry and returns the registered [Principal].
	// Returns [ErrUnknownPrincipal] if no SAN matches; nil error
	// implies a populated *Principal.
	Lookup(sans []string) (*Principal, error)

	// All returns a snapshot of every registered principal — used by
	// the admin portal and by tests. Order is not specified; callers
	// that need a stable view should sort the result.
	All() []Principal
}

// ErrUnknownPrincipal signals that the caller's TLS cert presented
// SANs none of which are registered. Surfaced as 401 at the API edge.
var ErrUnknownPrincipal = errors.New("no registered cert principal matches the client cert SANs")

// ErrNoClientCert signals that the request did not carry a verified
// TLS peer certificate. Surfaced as 401 only when mTLS is the only
// auth path configured; the API layer uses it to fall through to
// other paths when present.
var ErrNoClientCert = errors.New("no verified client certificate on request")

// ErrPrincipalExists is returned by the persistent store's Add when a
// principal is already registered under the same SAN. Mirrors
// [github.com/abagile/tokyo3-ca/internal/server/policy.ErrRoleExists].
var ErrPrincipalExists = errors.New("principal with that SAN already exists")

// ErrPrincipalNotFound is returned by the persistent store's Replace and
// Delete when no principal is registered under the target SAN.
var ErrPrincipalNotFound = errors.New("principal not found")

// InMemoryStore is a thread-safe in-memory [Store]. Seeded at
// startup; mutate via ReplaceAll for hot-reload when the registry is
// rewritten by the admin API.
type InMemoryStore struct {
	mu    sync.RWMutex
	bySAN map[string]Principal
}

// NewInMemoryStore builds a store from principals. Each principal's
// SANs are registered exactly as given — no normalization — so the
// caller controls match semantics (e.g., "spiffe://corp/host/db-1"
// vs trailing slash, etc.).
//
// To register one principal under multiple SANs (URI + email, or
// alternate URIs), pass it multiple times with each MatchedSAN set
// to the SAN to register under. The MatchedSAN field becomes the
// registry key; the rest of the [Principal] payload is what Lookup
// returns to callers.
func NewInMemoryStore(entries ...Principal) *InMemoryStore {
	s := &InMemoryStore{}
	s.replace(entries)
	return s
}

// ReplaceAll atomically swaps the entire registry.
func (s *InMemoryStore) ReplaceAll(entries []Principal) {
	s.replace(entries)
}

func (s *InMemoryStore) replace(entries []Principal) {
	idx := make(map[string]Principal, len(entries))
	for _, p := range entries {
		if p.MatchedSAN == "" {
			continue // ignore entries without a registration key
		}
		idx[p.MatchedSAN] = p
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bySAN = idx
}

// Lookup satisfies [Store]. Returns the first registered principal
// whose SAN appears in sans, after copying it so callers can't mutate
// shared registry state.
func (s *InMemoryStore) Lookup(sans []string) (*Principal, error) {
	if len(sans) == 0 {
		return nil, ErrNoClientCert
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, san := range sans {
		if p, ok := s.bySAN[san]; ok {
			p.MatchedSAN = san
			return &p, nil
		}
	}
	return nil, fmt.Errorf("%w: presented=%v", ErrUnknownPrincipal, sans)
}

// All satisfies [Store]. Returns a snapshot of every registered
// principal with its MatchedSAN populated from the registry key.
// Order is map-iteration order — callers that need stable output
// (admin portal listings, tests) should sort the result themselves.
func (s *InMemoryStore) All() []Principal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Principal, 0, len(s.bySAN))
	for san, p := range s.bySAN {
		p.MatchedSAN = san
		out = append(out, p)
	}
	return out
}

// ExtractSANs reads the verified leaf certificate from r.TLS and
// returns its URI SANs (stringified) followed by its email SANs.
// Returns nil when no TLS state or no verified peer certs are present
// — the API layer treats nil as "no mTLS identity to consider" and
// falls through to alternative auth paths.
//
// Only the *leaf* cert is inspected — intermediate cert SANs are
// never considered, matching what every standards-conforming mTLS
// validator does.
func ExtractSANs(r *http.Request) []string {
	if r == nil || r.TLS == nil {
		return nil
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return sansFromCert(r.TLS.PeerCertificates[0])
}

// sansFromCert returns the URI and email SANs from a single cert.
// Exposed (lowercase) for unit testing without an http.Request.
func sansFromCert(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	out := make([]string, 0, len(cert.URIs)+len(cert.EmailAddresses))
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	out = append(out, cert.EmailAddresses...)
	return out
}
