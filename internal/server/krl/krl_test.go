package krl_test

import (
	"errors"
	"strings"
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
		wg.Go(func() {
			snap := s.Snapshot()
			// Trivially-correct sanity check so we exercise the
			// returned slice; the assertion that matters is the
			// race detector running -race in CI.
			if len(snap.Entries) != 2 {
				t.Errorf("concurrent Snapshot saw %d entries", len(snap.Entries))
			}
		})
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

func TestInMemoryStore_MarshalSpec_EmptyHasHeaderAndMarker(t *testing.T) {
	s := krl.NewInMemoryStore()
	got := s.MarshalSpec()
	if !strings.Contains(got, "# certd KRL spec") {
		t.Errorf("missing header banner:\n%s", got)
	}
	if !strings.Contains(got, "# generated ") {
		t.Errorf("missing generated-at line:\n%s", got)
	}
	if !strings.Contains(got, "# (empty") {
		t.Errorf("empty marker missing:\n%s", got)
	}
	if strings.Contains(got, "serial:") || strings.Contains(got, "id:") {
		t.Errorf("empty store should produce no directives:\n%s", got)
	}
}

func TestInMemoryStore_MarshalSpec_RendersSerialsAndKeyIDs(t *testing.T) {
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{Serial: 99, Reason: "compromised", Revoker: "portal"})
	_ = s.Revoke(krl.Revocation{Serial: 7})
	_ = s.Revoke(krl.Revocation{KeyID: "user:eve@example.com", Revoker: "ops"})
	_ = s.Revoke(krl.Revocation{KeyID: "user:alice@example.com"})

	spec := s.MarshalSpec()
	for _, want := range []string{
		"serial: 7",
		"serial: 99",
		"id: user:alice@example.com",
		"id: user:eve@example.com",
		"# reason: compromised | revoker: portal",
		"# revoker: ops",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("spec missing %q\n--- spec ---\n%s", want, spec)
		}
	}

	// Serials are ascending, key_ids alphabetical, serials before
	// key_ids.
	s7 := strings.Index(spec, "serial: 7")
	s99 := strings.Index(spec, "serial: 99")
	idA := strings.Index(spec, "id: user:alice@example.com")
	idE := strings.Index(spec, "id: user:eve@example.com")
	if !(s7 < s99 && s99 < idA && idA < idE) {
		t.Errorf("ordering not [serial:7 < serial:99 < id:alice < id:eve]; offsets %d %d %d %d\n%s", s7, s99, idA, idE, spec)
	}
}

func TestInMemoryStore_MarshalSpec_DeterministicAcrossCalls(t *testing.T) {
	// Re-rendering the same snapshot must produce byte-identical
	// output modulo the embedded timestamp. Strip the # generated
	// line for the comparison.
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{Serial: 1})
	_ = s.Revoke(krl.Revocation{KeyID: "k"})

	strip := func(raw string) string {
		var b strings.Builder
		for line := range strings.SplitSeq(raw, "\n") {
			if strings.HasPrefix(line, "# generated ") {
				continue
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}
		return b.String()
	}
	a := strip(s.MarshalSpec())
	b := strip(s.MarshalSpec())
	if a != b {
		t.Errorf("MarshalSpec not deterministic across calls:\nA=%q\nB=%q", a, b)
	}
}

func TestInMemoryStore_MarshalSpec_StripsNewlinesFromReason(t *testing.T) {
	// A multiline reason would break the spec by leaking onto a
	// directive line — verify newlines collapse to spaces.
	s := krl.NewInMemoryStore()
	_ = s.Revoke(krl.Revocation{Serial: 1, Reason: "first\nsecond"})
	spec := s.MarshalSpec()
	if strings.Contains(spec, "first\nsecond") {
		t.Errorf("reason newlines not stripped:\n%s", spec)
	}
	if !strings.Contains(spec, "first second") {
		t.Errorf("expected 'first second' after newline collapse:\n%s", spec)
	}
}
