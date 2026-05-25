package krl_test

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
)

func TestInMemoryStore_Revoke_RequiresSerialOrKeyID(t *testing.T) {
	s := krl.NewInMemoryStore()
	if err := s.Revoke(krl.Revocation{Reason: "no key"}); !errors.Is(err, krl.ErrEmptyRevocation) {
		t.Errorf("err = %v, want ErrEmptyRevocation", err)
	}
}

func TestInMemoryStore_IsRevoked_BySerial(t *testing.T) {
	s := krl.NewInMemoryStore()
	if err := s.Revoke(krl.Revocation{Serial: 42, Reason: "compromised"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !s.IsRevoked(42, "") {
		t.Error("IsRevoked(42) = false, want true")
	}
	if s.IsRevoked(99, "") {
		t.Error("IsRevoked(99) = true, want false")
	}
}

func TestInMemoryStore_IsRevoked_ByKeyID(t *testing.T) {
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{KeyID: "user:alice@example.com"})
	if !s.IsRevoked(0, "user:alice@example.com") {
		t.Error("IsRevoked(0, alice) = false, want true")
	}
	if s.IsRevoked(0, "user:bob@example.com") {
		t.Error("IsRevoked(0, bob) = true, want false")
	}
}

func TestInMemoryStore_IsRevoked_EitherMatchesEntry(t *testing.T) {
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{Serial: 7, KeyID: "user:eve"})
	// Either field alone should match.
	if !s.IsRevoked(7, "") {
		t.Error("serial-only lookup missed")
	}
	if !s.IsRevoked(0, "user:eve") {
		t.Error("key_id-only lookup missed")
	}
	// Wrong serial + right key_id still matches.
	if !s.IsRevoked(99, "user:eve") {
		t.Error("key_id match should win even with wrong serial")
	}
}

func TestInMemoryStore_Revoke_Idempotent(t *testing.T) {
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{Serial: 1, Reason: "initial"})
	_ = s.Revoke(krl.Revocation{Serial: 1, Reason: "refined"})

	snap := s.Snapshot()
	if len(snap.Entries) != 1 {
		t.Fatalf("Entries len = %d, want 1 (re-revoke should overwrite)", len(snap.Entries))
	}
	if snap.Entries[0].Reason != "refined" {
		t.Errorf("Reason = %q, want refined (latest wins)", snap.Entries[0].Reason)
	}
}

func TestInMemoryStore_Snapshot_StableSort(t *testing.T) {
	s := krl.NewInMemoryStore()
	base := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	_ = s.Revoke(krl.Revocation{Serial: 3, Revoked: base.Add(2 * time.Second)})
	_ = s.Revoke(krl.Revocation{Serial: 1, Revoked: base})
	_ = s.Revoke(krl.Revocation{Serial: 2, Revoked: base.Add(1 * time.Second)})

	got := s.Snapshot().Entries
	want := []uint64{1, 2, 3}
	for i, ent := range got {
		if ent.Serial != want[i] {
			t.Errorf("Entries[%d].Serial = %d, want %d", i, ent.Serial, want[i])
		}
	}
}

func TestInMemoryStore_Snapshot_DeduplicatesAcrossSerialAndKeyID(t *testing.T) {
	// A single Revoke call with both Serial + KeyID registers under
	// both maps; Snapshot must surface only one row for it.
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{Serial: 9, KeyID: "user:cad"})
	got := s.Snapshot().Entries
	if len(got) != 1 {
		t.Errorf("Entries len = %d, want 1 (dedup across both indices)", len(got))
	}
	if got[0].Serial != 9 || got[0].KeyID != "user:cad" {
		t.Errorf("entry = %+v", got[0])
	}
}

func TestInMemoryStore_Snapshot_ConcurrentRead(t *testing.T) {
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{Serial: 1})
	_ = s.Revoke(krl.Revocation{Serial: 2})

	// Concurrent Snapshots must not panic on the underlying maps —
	// the test relies on Go's race detector to catch missing locks.
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap := s.Snapshot()
			// Trivially-correct sanity check so we exercise the
			// returned slice; the assertion that matters is the
			// race detector running -race in CI.
			if len(snap.Entries) != 2 {
				t.Errorf("concurrent Snapshot saw %d entries", len(snap.Entries))
			}
		}()
	}
	wg.Wait()
}

// AppendsTimestampWhenAbsent is a thin sanity check that Revoke
// populates Revoked when the caller leaves it zero — most operators
// won't pass an explicit timestamp.
func TestInMemoryStore_Revoke_AppendsTimestampWhenAbsent(t *testing.T) {
	s := krl.NewInMemoryStore()
	before := time.Now().UTC()
	_ = s.Revoke(krl.Revocation{Serial: 1})
	after := time.Now().UTC()
	snap := s.Snapshot()
	if len(snap.Entries) == 0 {
		t.Fatal("no entry")
	}
	got := snap.Entries[0].Revoked
	if got.Before(before) || got.After(after) {
		t.Errorf("Revoked = %v, want within [%v, %v]", got, before, after)
	}
}

// SortedSlice is a tiny helper used to compare snapshot orderings
// in a stable way without pulling in cmp/cmpopts.
func sortedSlice(xs []uint64) []uint64 {
	out := append([]uint64(nil), xs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var _ = sortedSlice // keep helper compiled even if a future test stops using it
