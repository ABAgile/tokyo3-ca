// Package krl tracks revoked SSH certificates. certd exposes the
// revocation snapshot via HTTP so ssh-proxyd (and any other
// consumer) can poll for the current revoked set and refuse certs
// that appear in it via a [gossh.CertChecker.IsRevoked] callback.
//
// This first slice ships an in-memory store and the snapshot shape.
// OpenSSH's binary KRL format (the file ssh-keygen -k produces and
// sshd consumes via RevokedKeys) is a follow-up — every proxy in
// this deployment terminates SSH itself, so the JSON snapshot
// suffices for now. A KRL-binary publisher slots in here later
// without changing the store surface.
package krl

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// Revocation records one revoked cert. Serial is the SSH cert's
// serial number; KeyID is its KeyID field. Either-or — operators
// revoke by whichever attribute is convenient (audit records
// usually surface both). Time records when the entry was added.
//
// Reason is a human-readable annotation surfaced in audit
// attributions and the admin portal. Empty is acceptable.
type Revocation struct {
	Serial  uint64    `json:"serial,omitempty"`
	KeyID   string    `json:"key_id,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Revoker string    `json:"revoker,omitempty"`
	Revoked time.Time `json:"revoked_at"`
}

// Snapshot is the canonical wire form: separated sets of revoked
// serials and revoked key IDs so consumers can lookup in O(1)
// against either field. CapturedAt is the server-side timestamp the
// snapshot was assembled — useful for monitoring staleness on the
// consumer side.
type Snapshot struct {
	CapturedAt time.Time    `json:"captured_at"`
	Entries    []Revocation `json:"entries"`
}

// Store backs the revocation registry. Safe for concurrent use.
type Store interface {
	// Revoke adds a [Revocation]. Returns [ErrEmptyRevocation] when
	// both Serial and KeyID are zero/empty; the caller must populate
	// at least one. Re-revoking the same Serial or KeyID is
	// idempotent — the Reason / Revoker / Revoked fields are
	// overwritten with the latest values so operators can refine
	// the annotation without removing-then-adding.
	Revoke(r Revocation) error

	// Snapshot returns the current set, sorted by Revoked ascending
	// for stable wire output.
	Snapshot() Snapshot

	// IsRevoked reports whether a cert with the given Serial or
	// KeyID has been revoked. Either argument may be zero/empty.
	IsRevoked(serial uint64, keyID string) bool
}

// ErrEmptyRevocation is returned by [Store.Revoke] when neither
// Serial nor KeyID is populated. Distinct from generic validation
// errors so the API layer can map it to 400 cleanly.
var ErrEmptyRevocation = errors.New("revocation must include serial or key_id")

// InMemoryStore is a thread-safe in-memory [Store]. Operators wire
// initial entries via a JSON file at startup; per-request mutations
// arrive through the API. Persistence (Postgres-backed Store) is a
// follow-up — for v1 the audit stream is the durable log of every
// Revoke call, so a restart re-loads from there if needed.
type InMemoryStore struct {
	mu       sync.RWMutex
	bySerial map[uint64]Revocation
	byKeyID  map[string]Revocation
}

// NewInMemoryStore returns an empty store. Seed with [Store.Revoke]
// or via the JSON file loader in cmd/certd.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		bySerial: make(map[uint64]Revocation),
		byKeyID:  make(map[string]Revocation),
	}
}

// Revoke satisfies [Store].
func (s *InMemoryStore) Revoke(r Revocation) error {
	if r.Serial == 0 && r.KeyID == "" {
		return ErrEmptyRevocation
	}
	if r.Revoked.IsZero() {
		r.Revoked = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Serial != 0 {
		s.bySerial[r.Serial] = r
	}
	if r.KeyID != "" {
		s.byKeyID[r.KeyID] = r
	}
	return nil
}

// Snapshot satisfies [Store]. Returns a single deduplicated list
// sorted by Revoked ascending. An entry with both Serial and KeyID
// appears once.
func (s *InMemoryStore) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]Revocation, len(s.bySerial)+len(s.byKeyID))
	for _, r := range s.bySerial {
		seen[revocationKey(r)] = r
	}
	for _, r := range s.byKeyID {
		seen[revocationKey(r)] = r
	}
	out := make([]Revocation, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Revoked.Equal(out[j].Revoked) {
			// Tiebreak by Serial then KeyID to keep output stable
			// across snapshots taken at the same wall clock.
			if out[i].Serial != out[j].Serial {
				return out[i].Serial < out[j].Serial
			}
			return out[i].KeyID < out[j].KeyID
		}
		return out[i].Revoked.Before(out[j].Revoked)
	})
	return Snapshot{CapturedAt: time.Now().UTC(), Entries: out}
}

// IsRevoked satisfies [Store].
func (s *InMemoryStore) IsRevoked(serial uint64, keyID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if serial != 0 {
		if _, ok := s.bySerial[serial]; ok {
			return true
		}
	}
	if keyID != "" {
		if _, ok := s.byKeyID[keyID]; ok {
			return true
		}
	}
	return false
}

// revocationKey de-duplicates entries that registered under both
// Serial and KeyID. Returns the same string for an (S=42, K="foo")
// entry inserted via the by-serial map and the by-keyid map.
func revocationKey(r Revocation) string {
	return r.KeyID + "|" + serialString(r.Serial)
}

func serialString(s uint64) string {
	if s == 0 {
		return ""
	}
	var buf [20]byte
	pos := len(buf)
	for s > 0 {
		pos--
		buf[pos] = byte('0' + s%10)
		s /= 10
	}
	return string(buf[pos:])
}
