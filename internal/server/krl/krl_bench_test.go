package krl_test

import (
	"strconv"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
)

// loadedStore returns an InMemoryStore with n revocations split
// across serial + KeyID. Each entry registers under both fields so
// IsRevoked benchmarks exercise the typical two-key shape.
func loadedStore(n int) *krl.InMemoryStore {
	s := krl.NewInMemoryStore()
	for i := range n {
		_ = s.Revoke(krl.Revocation{
			Serial: uint64(i + 1),
			KeyID:  "user:" + strconv.Itoa(i) + "@example.com",
		})
	}
	return s
}

// BenchmarkIsRevoked_Hit measures the hit path against a 10k-entry
// store. Consumers (ssh-proxyd's polling client + the API's
// revoke handler) call IsRevoked per affected cert; cost matters
// when a fleet rotates en masse.
func BenchmarkIsRevoked_Hit(b *testing.B) {
	s := loadedStore(10_000)
	b.ReportAllocs()
	for b.Loop() {
		_ = s.IsRevoked(5_000, "")
	}
}

// BenchmarkIsRevoked_Miss is the common case — most certs aren't
// revoked. Confirms the negative path is still O(1).
func BenchmarkIsRevoked_Miss(b *testing.B) {
	s := loadedStore(10_000)
	b.ReportAllocs()
	for b.Loop() {
		_ = s.IsRevoked(999_999, "user:nope")
	}
}

// BenchmarkSnapshot measures the full snapshot rebuild that
// consumers poll for. Bounds the per-poll cost ssh-proxyd pays
// every 30s (or whatever the operator sets).
func BenchmarkSnapshot(b *testing.B) {
	s := loadedStore(1_000)
	b.ReportAllocs()
	for b.Loop() {
		_ = s.Snapshot()
	}
}

// BenchmarkMarshalSpec covers the ssh-keygen-spec render path
// served at /api/v1/ssh/krl.spec. Operators on direct sshd hosts
// poll this; the cost includes sort + format.
func BenchmarkMarshalSpec(b *testing.B) {
	s := loadedStore(1_000)
	b.ReportAllocs()
	for b.Loop() {
		_ = s.MarshalSpec()
	}
}
