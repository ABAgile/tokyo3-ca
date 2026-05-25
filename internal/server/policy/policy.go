// Package policy owns the role table — mappings from OIDC group claims
// to allowed Unix principals (user-cert) and host-name patterns
// (host-cert) — and enforces those mappings at sign time inside certd.
//
// The resulting decisions are encoded directly into the issued
// certificate (ValidPrincipals + Permissions.Extensions for user certs,
// ValidPrincipals for host certs), so downstream services that consume
// the cert never need to consult the role table themselves. ssh-proxyd
// in particular re-validates what the cert says at session time as
// defense in depth, but it's a credential-driven enforcer — no policy
// DB lookups on the hot path.
//
// Storage is pluggable behind the [Store] interface. This slice ships
// only [InMemoryStore]; a Postgres-backed implementation will land when
// the role-admin portal goes in later pharse.
package policy

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"sort"
	"sync"
	"time"
)

// Role binds an OIDC group to a set of SSH capabilities.
//
// User and host capabilities are independent: a role may grant
// user-cert principals only, host-cert patterns only, or both. A role
// with neither set is permitted by [InMemoryStore] but rejects every
// sign request it might match — useful as a deliberate placeholder
// during config rollout.
//
// MaxUserCertTTL / MaxHostCertTTL act as the maximum a single role
// permits. A value of zero means "no per-role cap; the endpoint-level
// cap applies." When a caller is in multiple roles, the engine takes
// the *most permissive* cap across them (union semantics — more roles
// give you more capability, not less).
type Role struct {
	Name              string   `json:"name"`
	GroupClaim        string   `json:"group_claim"`
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	HostPatterns      []string `json:"host_patterns,omitempty"`
	// SPIFFEPatterns are path.Match-style globs the requested SPIFFE
	// URI is matched against for X.509 workload-cert issuance. Same
	// glob syntax as HostPatterns; the URI is matched as a single
	// string ("spiffe://corp/svc/billing").
	SPIFFEPatterns    []string          `json:"spiffe_patterns,omitempty"`
	MaxUserCertTTL    time.Duration     `json:"max_user_cert_ttl,omitempty"`
	MaxHostCertTTL    time.Duration     `json:"max_host_cert_ttl,omitempty"`
	MaxX509CertTTL    time.Duration     `json:"max_x509_cert_ttl,omitempty"`
	DefaultExtensions map[string]string `json:"default_extensions,omitempty"`
}

// Store backs the role table. The engine consults it on every sign
// request; implementations must be safe for concurrent use.
type Store interface {
	// RolesForGroups returns every role whose GroupClaim appears in the
	// caller's groups list. Order is not specified.
	RolesForGroups(groups []string) []Role
	// All returns every configured role (for the admin portal / tests).
	All() []Role
}

// InMemoryStore is a thread-safe in-memory [Store]. Seeded from a
// static slice at startup (typically populated from config) and
// mutated through ReplaceAll for hot-reload scenarios. A
// Postgres-backed Store with the same interface will arrive with the
// admin portal.
type InMemoryStore struct {
	mu      sync.RWMutex
	byGroup map[string][]Role
	all     []Role
}

// NewInMemoryStore constructs a store seeded with roles. Duplicate
// names across the slice are not enforced here — the admin layer
// validates uniqueness before it inserts.
func NewInMemoryStore(roles ...Role) *InMemoryStore {
	s := &InMemoryStore{}
	s.replace(roles)
	return s
}

// ReplaceAll atomically swaps the entire role set. Use for hot-reload
// after the admin API rewrites the configuration.
func (s *InMemoryStore) ReplaceAll(roles []Role) {
	s.replace(roles)
}

func (s *InMemoryStore) replace(roles []Role) {
	idx := make(map[string][]Role, len(roles))
	for _, r := range roles {
		idx[r.GroupClaim] = append(idx[r.GroupClaim], r)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byGroup = idx
	s.all = append([]Role(nil), roles...)
}

// RolesForGroups satisfies [Store].
func (s *InMemoryStore) RolesForGroups(groups []string) []Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Role
	seen := make(map[string]bool, len(groups))
	for _, g := range groups {
		if seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, s.byGroup[g]...)
	}
	return out
}

// All satisfies [Store].
func (s *InMemoryStore) All() []Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Role(nil), s.all...)
}

// ByName returns the role registered under name. ok is false when no
// role matches; the zero Role is returned in that case. Caller is
// safe to mutate the returned value — it's a copy of the stored entry.
func (s *InMemoryStore) ByName(name string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.all {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

// ErrRoleExists is returned by [InMemoryStore.Add] when a role with
// the same Name is already registered. Distinct from generic
// validation errors so the admin layer can surface "name taken" in
// a form-friendly way.
var ErrRoleExists = errors.New("role with that name already exists")

// ErrRoleNotFound is returned by [InMemoryStore.Replace] and
// [InMemoryStore.Delete] when the target role is absent.
var ErrRoleNotFound = errors.New("role not found")

// Add inserts role. Returns [ErrRoleExists] when the name collides
// with an existing entry. Name must be non-empty; the policy layer
// requires it for lookup.
func (s *InMemoryStore) Add(role Role) error {
	if role.Name == "" {
		return errors.New("role name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.all {
		if r.Name == role.Name {
			return ErrRoleExists
		}
	}
	next := append(append([]Role(nil), s.all...), role)
	s.replaceLocked(next)
	return nil
}

// Replace swaps the role registered as oldName for newRole. oldName
// and newRole.Name may differ — that's a rename. Returns
// [ErrRoleNotFound] when oldName is absent and [ErrRoleExists] when
// renaming would collide with another existing role.
func (s *InMemoryStore) Replace(oldName string, newRole Role) error {
	if newRole.Name == "" {
		return errors.New("role name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, r := range s.all {
		if r.Name == oldName {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrRoleNotFound
	}
	if newRole.Name != oldName {
		for i, r := range s.all {
			if i != idx && r.Name == newRole.Name {
				return ErrRoleExists
			}
		}
	}
	next := append([]Role(nil), s.all...)
	next[idx] = newRole
	s.replaceLocked(next)
	return nil
}

// Delete removes the role registered as name. Returns
// [ErrRoleNotFound] when the role is absent.
func (s *InMemoryStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, r := range s.all {
		if r.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrRoleNotFound
	}
	next := append(append([]Role(nil), s.all[:idx]...), s.all[idx+1:]...)
	s.replaceLocked(next)
	return nil
}

// replaceLocked is the shared mutation primitive. Caller must hold
// the write lock; rebuilds both the by-group index and the canonical
// slice. Mirrors [replace] but skips the lock acquire so the higher-
// level helpers can hold it across validation + commit.
func (s *InMemoryStore) replaceLocked(roles []Role) {
	idx := make(map[string][]Role, len(roles))
	for _, r := range roles {
		idx[r.GroupClaim] = append(idx[r.GroupClaim], r)
	}
	s.byGroup = idx
	s.all = roles
}

// ── Engine ────────────────────────────────────────────────────────────────────

// Engine applies role-table policy to incoming sign requests.
type Engine struct {
	store Store
}

// NewEngine constructs an Engine over the given store.
func NewEngine(store Store) *Engine {
	if store == nil {
		panic("policy.NewEngine: store is required")
	}
	return &Engine{store: store}
}

// ErrNoRole signals that the caller's groups did not match any
// configured role — i.e., they have no authorization to sign anything.
// Surfaced as 403 at the API edge.
var ErrNoRole = errors.New("no role matches the caller's groups")

// ErrEmptyDecision signals that role policy filtered out every
// requested principal — the caller is in roles, but none of them
// authorize what they asked for. Surfaced as 403.
var ErrEmptyDecision = errors.New("role policy denies every requested principal")

// UserCertDecision is the authoritative output of [Engine.EvaluateUserCert].
// Embed these values into the cert; do not re-derive them.
type UserCertDecision struct {
	Principals []string          // Subset of the request, filtered by role union.
	TTL        time.Duration     // min(requested, max across matching roles).
	Extensions map[string]string // Merge of role defaults; caller may layer per-request opts on top.
}

// HostCertDecision is the authoritative output of [Engine.EvaluateHostCert].
type HostCertDecision struct {
	Principals []string      // Subset of the request, filtered by host-pattern glob.
	TTL        time.Duration // min(requested, max across matching roles).
}

// UserCertRequest captures what the caller asked for, normalized.
type UserCertRequest struct {
	RequestedPrincipals []string
	RequestedTTL        time.Duration
	EndpointMaxTTL      time.Duration // ceiling from the endpoint (e.g., 24h for user).
}

// HostCertRequest mirrors [UserCertRequest] for host certs.
type HostCertRequest struct {
	RequestedPrincipals []string
	RequestedTTL        time.Duration
	EndpointMaxTTL      time.Duration
}

// EvaluateUserCert applies role policy. Returns the (possibly narrowed)
// decision or one of [ErrNoRole] / [ErrEmptyDecision] for denial cases.
// The caller is responsible for surfacing those as 403s.
//
// Groups must already be the authenticated set — the engine does not
// validate identity. In later phases the API layer derives groups
// from a verified OIDC token or mTLS cert; currently the call site is
// pre-auth and the slice marks groups as untrusted in its docstring.
func (e *Engine) EvaluateUserCert(groups []string, req UserCertRequest) (UserCertDecision, error) {
	roles := e.store.RolesForGroups(groups)
	if len(roles) == 0 {
		return UserCertDecision{}, fmt.Errorf("%w: groups=%v", ErrNoRole, groups)
	}

	// Union of allowed principals across matching roles.
	allowed := make(map[string]struct{})
	for _, r := range roles {
		for _, p := range r.AllowedPrincipals {
			allowed[p] = struct{}{}
		}
	}

	// Filter requested principals through the allowed set.
	out := make([]string, 0, len(req.RequestedPrincipals))
	denied := make([]string, 0)
	for _, p := range req.RequestedPrincipals {
		if _, ok := allowed[p]; ok {
			out = append(out, p)
		} else {
			denied = append(denied, p)
		}
	}
	if len(out) == 0 {
		return UserCertDecision{}, fmt.Errorf("%w: requested=%v allowed=%v",
			ErrEmptyDecision, req.RequestedPrincipals, sortedKeys(allowed))
	}

	// TTL: maximum across matching roles' MaxUserCertTTL, then capped
	// at endpoint max. Zero MaxUserCertTTL means "no per-role cap"; in
	// that case the endpoint max applies for this role.
	maxTTL := ttlCap(roles, req.EndpointMaxTTL, userCapField)
	ttl := min(req.RequestedTTL, maxTTL)

	// Merge default extensions from every matching role. Later writes
	// win (deterministic via role-order iteration in the union).
	exts := make(map[string]string)
	for _, r := range roles {
		maps.Copy(exts, r.DefaultExtensions)
	}

	_ = denied // available for richer error reporting later
	return UserCertDecision{Principals: out, TTL: ttl, Extensions: exts}, nil
}

// EvaluateHostCert applies role policy for host certs. Each requested
// principal is glob-matched (via path.Match) against the union of
// HostPatterns across the caller's matching roles; non-matching
// principals are dropped.
func (e *Engine) EvaluateHostCert(groups []string, req HostCertRequest) (HostCertDecision, error) {
	roles := e.store.RolesForGroups(groups)
	if len(roles) == 0 {
		return HostCertDecision{}, fmt.Errorf("%w: groups=%v", ErrNoRole, groups)
	}

	// Collect patterns from matching roles. Skip patterns that fail
	// path.Match's syntax check up-front so they don't quietly mask
	// a typo (e.g., a stray "[" in a pattern).
	var patterns []string
	for _, r := range roles {
		for _, p := range r.HostPatterns {
			if _, err := path.Match(p, ""); err != nil {
				return HostCertDecision{}, fmt.Errorf("role %q has invalid host pattern %q: %w", r.Name, p, err)
			}
			patterns = append(patterns, p)
		}
	}

	// Filter requested host principals.
	out := make([]string, 0, len(req.RequestedPrincipals))
	for _, p := range req.RequestedPrincipals {
		if matchesAny(p, patterns) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return HostCertDecision{}, fmt.Errorf("%w: requested=%v patterns=%v",
			ErrEmptyDecision, req.RequestedPrincipals, patterns)
	}

	maxTTL := ttlCap(roles, req.EndpointMaxTTL, hostCapField)
	ttl := min(req.RequestedTTL, maxTTL)

	return HostCertDecision{Principals: out, TTL: ttl}, nil
}

// X509CertRequest captures what the caller asked for, normalized for
// the X.509 / SPIFFE issuance path.
type X509CertRequest struct {
	RequestedSPIFFEURI string
	RequestedTTL       time.Duration
	EndpointMaxTTL     time.Duration
}

// X509CertDecision is the authoritative output of [Engine.EvaluateX509Cert].
type X509CertDecision struct {
	SPIFFEURI string
	TTL       time.Duration
}

// EvaluateX509Cert applies role policy for X.509 workload certs. The
// requested SPIFFE URI is glob-matched (via path.Match) against the
// union of SPIFFEPatterns across the caller's matching roles; a single
// URI is requested per cert (workloads have one identity at a time),
// so this returns the requested URI verbatim on approval or an error
// on denial.
func (e *Engine) EvaluateX509Cert(groups []string, req X509CertRequest) (X509CertDecision, error) {
	roles := e.store.RolesForGroups(groups)
	if len(roles) == 0 {
		return X509CertDecision{}, fmt.Errorf("%w: groups=%v", ErrNoRole, groups)
	}

	var patterns []string
	for _, r := range roles {
		for _, p := range r.SPIFFEPatterns {
			if _, err := path.Match(p, ""); err != nil {
				return X509CertDecision{}, fmt.Errorf("role %q has invalid spiffe pattern %q: %w", r.Name, p, err)
			}
			patterns = append(patterns, p)
		}
	}

	if !matchesAny(req.RequestedSPIFFEURI, patterns) {
		return X509CertDecision{}, fmt.Errorf("%w: requested=%s patterns=%v",
			ErrEmptyDecision, req.RequestedSPIFFEURI, patterns)
	}

	maxTTL := ttlCap(roles, req.EndpointMaxTTL, x509CapField)
	ttl := min(req.RequestedTTL, maxTTL)

	return X509CertDecision{SPIFFEURI: req.RequestedSPIFFEURI, TTL: ttl}, nil
}

// capField identifies which Role TTL ceiling [ttlCap] should consult.
type capField int

const (
	userCapField capField = iota
	hostCapField
	x509CapField
)

// ttlCap returns the most-permissive per-role TTL ceiling across roles
// (zero on a role → endpoint cap applies), itself bounded by endpoint.
// Union semantics — more roles widens the ceiling, never narrows it.
func ttlCap(roles []Role, endpoint time.Duration, field capField) time.Duration {
	var out time.Duration
	for _, r := range roles {
		var eff time.Duration
		switch field {
		case userCapField:
			eff = r.MaxUserCertTTL
		case hostCapField:
			eff = r.MaxHostCertTTL
		case x509CapField:
			eff = r.MaxX509CertTTL
		}
		if eff == 0 || eff > endpoint {
			eff = endpoint
		}
		if eff > out {
			out = eff
		}
	}
	return out
}

// matchesAny returns true when host matches at least one pattern.
// Patterns are path.Match-style globs (* and ? with the usual escaping
// rules), same convention OpenSSH uses in known_hosts and sshd_config.
func matchesAny(host string, patterns []string) bool {
	for _, p := range patterns {
		ok, err := path.Match(p, host)
		if err == nil && ok {
			return true
		}
	}
	return false
}

// sortedKeys returns m's keys in lexicographic order — used so error
// messages are reproducible across map-iteration ordering.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
