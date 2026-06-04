// Package storetest provides backend-agnostic acceptance suites for the
// store interfaces, so the sqlite and postgres backends are verified
// against identical assertions. It is imported only from _test.go files.
package storetest

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/store"
)

// ── roles ──────────────────────────────────────────────────────────────

func sampleRole() policy.Role {
	return policy.Role{
		Name:                  "workload-issuer",
		GroupClaim:            "platform",
		AllowedPrincipals:     []string{"deploy", "ops"},
		HostPatterns:          []string{"*.svc.internal", "db-?"},
		SPIFFEPatterns:        []string{"spiffe://demo/workload/*"},
		MaxUserCertTTLSeconds: 3600,
		MaxHostCertTTLSeconds: 7200,
		MaxX509CertTTLSeconds: 600,
		DefaultExtensions:     map[string]string{"permit-pty": ""},
	}
}

// RunRoleStoreSuite runs the full RoleStore contract. newStore must return a
// FRESH, empty store on each call so subtests are isolated.
func RunRoleStoreSuite(t *testing.T, newStore func(t *testing.T) store.RoleStore) {
	t.Run("AddRoundTrip", func(t *testing.T) {
		rs := newStore(t)
		want := sampleRole()
		if err := rs.Add(want); err != nil {
			t.Fatalf("Add: %v", err)
		}
		got, ok := rs.ByName(want.Name)
		if !ok {
			t.Fatal("ByName: role not found after Add")
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
		}
	})

	t.Run("RolesForGroups", func(t *testing.T) {
		rs := newStore(t)
		for _, r := range []policy.Role{
			{Name: "a", GroupClaim: "platform", AllowedPrincipals: []string{"deploy"}},
			{Name: "b", GroupClaim: "platform", HostPatterns: []string{"*.internal"}},
			{Name: "c", GroupClaim: "audit"},
		} {
			if err := rs.Add(r); err != nil {
				t.Fatalf("Add %s: %v", r.Name, err)
			}
		}
		if got, want := names(rs.RolesForGroups([]string{"platform", "platform"})), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
			t.Errorf("RolesForGroups(platform) = %v, want %v", got, want)
		}
		if got, want := names(rs.RolesForGroups([]string{"audit", "nope"})), []string{"c"}; !reflect.DeepEqual(got, want) {
			t.Errorf("RolesForGroups(audit) = %v, want %v", got, want)
		}
		if r := rs.RolesForGroups(nil); r != nil {
			t.Errorf("RolesForGroups(nil) = %v, want nil", r)
		}
	})

	t.Run("AddDuplicate", func(t *testing.T) {
		rs := newStore(t)
		r := sampleRole()
		if err := rs.Add(r); err != nil {
			t.Fatalf("first Add: %v", err)
		}
		if err := rs.Add(r); !errors.Is(err, policy.ErrRoleExists) {
			t.Errorf("duplicate Add err = %v, want ErrRoleExists", err)
		}
		if err := rs.Add(policy.Role{}); err == nil {
			t.Error("Add with empty name: want error, got nil")
		}
	})

	t.Run("Replace", func(t *testing.T) {
		rs := newStore(t)
		mustAddRole(t, rs, policy.Role{Name: "old", GroupClaim: "g1"})
		mustAddRole(t, rs, policy.Role{Name: "other", GroupClaim: "g2"})

		if err := rs.Replace("old", policy.Role{Name: "new", GroupClaim: "g3"}); err != nil {
			t.Fatalf("Replace rename: %v", err)
		}
		if _, ok := rs.ByName("old"); ok {
			t.Error("old name still present after rename")
		}
		if got, ok := rs.ByName("new"); !ok || got.GroupClaim != "g3" {
			t.Errorf("renamed role = %+v ok=%v, want GroupClaim g3", got, ok)
		}
		if err := rs.Replace("new", policy.Role{Name: "other"}); !errors.Is(err, policy.ErrRoleExists) {
			t.Errorf("collision Replace err = %v, want ErrRoleExists", err)
		}
		if err := rs.Replace("ghost", policy.Role{Name: "ghost"}); !errors.Is(err, policy.ErrRoleNotFound) {
			t.Errorf("absent Replace err = %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		rs := newStore(t)
		mustAddRole(t, rs, policy.Role{Name: "doomed", GroupClaim: "g"})
		if err := rs.Delete("doomed"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, ok := rs.ByName("doomed"); ok {
			t.Error("role present after Delete")
		}
		if err := rs.Delete("doomed"); !errors.Is(err, policy.ErrRoleNotFound) {
			t.Errorf("second Delete err = %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("SeedRolesIfEmpty", func(t *testing.T) {
		rs := newStore(t)
		roles := []policy.Role{{Name: "a", GroupClaim: "g1"}, {Name: "b", GroupClaim: "g2"}}
		seeded, err := rs.SeedRolesIfEmpty(roles)
		if err != nil || !seeded {
			t.Fatalf("first SeedRolesIfEmpty: seeded=%v err=%v, want true/nil", seeded, err)
		}
		if got := len(rs.All()); got != 2 {
			t.Fatalf("after seed, All() len = %d, want 2", got)
		}
		seeded, err = rs.SeedRolesIfEmpty([]policy.Role{{Name: "c", GroupClaim: "g3"}})
		if err != nil || seeded {
			t.Fatalf("second SeedRolesIfEmpty: seeded=%v err=%v, want false/nil", seeded, err)
		}
		if got := len(rs.All()); got != 2 {
			t.Errorf("after no-op seed, All() len = %d, want 2", got)
		}
	})
}

// ── principals ───────────────────────────────────────────────────────────

// RunPrincipalStoreSuite runs the full PrincipalStore contract.
func RunPrincipalStoreSuite(t *testing.T, newStore func(t *testing.T) store.PrincipalStore) {
	seed := []mtls.Principal{
		{Name: "app", MatchedSAN: "spiffe://demo/workload/app", Groups: []string{"workload"}},
		{Name: "nats", MatchedSAN: "spiffe://demo/workload/nats", Groups: []string{"workload", "nats"}},
	}

	t.Run("SeedAndAll", func(t *testing.T) {
		ps := newStore(t)
		seeded, err := ps.SeedPrincipalsIfEmpty(seed)
		if err != nil || !seeded {
			t.Fatalf("SeedPrincipalsIfEmpty: seeded=%v err=%v, want true/nil", seeded, err)
		}
		all := ps.All()
		if got := sans(all); !reflect.DeepEqual(got, []string{"spiffe://demo/workload/app", "spiffe://demo/workload/nats"}) {
			t.Errorf("All sans = %v", got)
		}
		// no-op on a populated table
		seeded, err = ps.SeedPrincipalsIfEmpty([]mtls.Principal{{Name: "x", MatchedSAN: "z"}})
		if err != nil || seeded {
			t.Fatalf("second seed: seeded=%v err=%v, want false/nil", seeded, err)
		}
	})

	t.Run("Lookup", func(t *testing.T) {
		ps := newStore(t)
		if _, err := ps.SeedPrincipalsIfEmpty(seed); err != nil {
			t.Fatal(err)
		}
		// First presented SAN that matches wins (unknown skipped).
		p, err := ps.Lookup([]string{"spiffe://nope", "spiffe://demo/workload/nats"})
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if p.Name != "nats" || p.MatchedSAN != "spiffe://demo/workload/nats" {
			t.Errorf("Lookup = %+v, want nats/its SAN", p)
		}
		if !reflect.DeepEqual(p.Groups, []string{"workload", "nats"}) {
			t.Errorf("Lookup groups = %v", p.Groups)
		}
		if _, err := ps.Lookup([]string{"spiffe://unknown"}); !errors.Is(err, mtls.ErrUnknownPrincipal) {
			t.Errorf("unknown Lookup err = %v, want ErrUnknownPrincipal", err)
		}
		if _, err := ps.Lookup(nil); !errors.Is(err, mtls.ErrNoClientCert) {
			t.Errorf("empty Lookup err = %v, want ErrNoClientCert", err)
		}
	})
}

// ── revocations ──────────────────────────────────────────────────────────

// RunRevocationStoreSuite runs the full RevocationStore contract.
func RunRevocationStoreSuite(t *testing.T, newStore func(t *testing.T) store.RevocationStore) {
	t.Run("RevokeCheckSnapshot", func(t *testing.T) {
		rs := newStore(t)
		if err := rs.Revoke(krl.Revocation{}); !errors.Is(err, krl.ErrEmptyRevocation) {
			t.Errorf("empty Revoke err = %v, want ErrEmptyRevocation", err)
		}
		if err := rs.Revoke(krl.Revocation{Serial: 42, Reason: "compromised", Revoker: "admin"}); err != nil {
			t.Fatalf("Revoke serial: %v", err)
		}
		if err := rs.Revoke(krl.Revocation{KeyID: "user:alice", Reason: "left"}); err != nil {
			t.Fatalf("Revoke keyid: %v", err)
		}
		if !rs.IsRevoked(42, "") {
			t.Error("IsRevoked(42) = false, want true")
		}
		if rs.IsRevoked(43, "") {
			t.Error("IsRevoked(43) = true, want false")
		}
		if !rs.IsRevoked(0, "user:alice") {
			t.Error("IsRevoked(alice) = false, want true")
		}
		if rs.IsRevoked(0, "user:bob") {
			t.Error("IsRevoked(bob) = true, want false")
		}
		if got := len(rs.Snapshot().Entries); got != 2 {
			t.Fatalf("Snapshot entries = %d, want 2", got)
		}
	})

	t.Run("RevokeIdempotent", func(t *testing.T) {
		rs := newStore(t)
		if err := rs.Revoke(krl.Revocation{Serial: 7, Reason: "first"}); err != nil {
			t.Fatal(err)
		}
		if err := rs.Revoke(krl.Revocation{Serial: 7, Reason: "second"}); err != nil {
			t.Fatal(err)
		}
		entries := rs.Snapshot().Entries
		if len(entries) != 1 {
			t.Fatalf("re-revoke produced %d entries, want 1 (idempotent)", len(entries))
		}
		if entries[0].Reason != "second" {
			t.Errorf("reason = %q, want overwritten to %q", entries[0].Reason, "second")
		}
	})

	t.Run("MarshalSpec", func(t *testing.T) {
		rs := newStore(t)
		if err := rs.Revoke(krl.Revocation{Serial: 42}); err != nil {
			t.Fatal(err)
		}
		if err := rs.Revoke(krl.Revocation{KeyID: "user:alice"}); err != nil {
			t.Fatal(err)
		}
		spec := rs.MarshalSpec()
		if !strings.Contains(spec, "serial: 42") {
			t.Errorf("spec missing serial line:\n%s", spec)
		}
		if !strings.Contains(spec, "id: user:alice") {
			t.Errorf("spec missing id line:\n%s", spec)
		}
	})
}

// ── active workload certs ────────────────────────────────────────────────

// RunActiveCertStoreSuite runs the full ActiveCertStore contract.
func RunActiveCertStoreSuite(t *testing.T, newStore func(t *testing.T) store.ActiveCertStore) {
	cur := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	prev := cur.Add(-10 * time.Minute)

	t.Run("UpsertGet", func(t *testing.T) {
		as := newStore(t)
		if _, ok, err := as.Get("spiffe://demo/x"); err != nil || ok {
			t.Fatalf("empty Get: ok=%v err=%v, want false/nil", ok, err)
		}
		want := store.ActiveCert{
			Identity: "spiffe://demo/x", CurrentSerial: "123", CurrentNotAfter: cur,
			PreviousSerial: "122", PreviousNotAfter: prev,
		}
		if err := as.Upsert(want); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		got, ok, err := as.Get("spiffe://demo/x")
		if err != nil || !ok {
			t.Fatalf("Get after upsert: ok=%v err=%v", ok, err)
		}
		if got.CurrentSerial != "123" || got.PreviousSerial != "122" {
			t.Errorf("serials = %q/%q, want 123/122", got.CurrentSerial, got.PreviousSerial)
		}
		if !got.CurrentNotAfter.Equal(cur) || !got.PreviousNotAfter.Equal(prev) {
			t.Errorf("not_after round-trip mismatch: %v / %v", got.CurrentNotAfter, got.PreviousNotAfter)
		}
	})

	t.Run("CollapsePrevious", func(t *testing.T) {
		as := newStore(t)
		if err := as.Upsert(store.ActiveCert{Identity: "id", CurrentSerial: "9", CurrentNotAfter: cur, PreviousSerial: "8", PreviousNotAfter: prev}); err != nil {
			t.Fatal(err)
		}
		// Adopt: rewrite with no previous → collapses to a single serial.
		if err := as.Upsert(store.ActiveCert{Identity: "id", CurrentSerial: "9", CurrentNotAfter: cur}); err != nil {
			t.Fatal(err)
		}
		got, ok, err := as.Get("id")
		if err != nil || !ok {
			t.Fatalf("Get: ok=%v err=%v", ok, err)
		}
		if got.PreviousSerial != "" || !got.PreviousNotAfter.IsZero() {
			t.Errorf("previous not collapsed: serial=%q not_after=%v", got.PreviousSerial, got.PreviousNotAfter)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		as := newStore(t)
		if err := as.Upsert(store.ActiveCert{Identity: "doomed", CurrentSerial: "1", CurrentNotAfter: cur}); err != nil {
			t.Fatal(err)
		}
		if err := as.Delete("doomed"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, ok, _ := as.Get("doomed"); ok {
			t.Error("row present after Delete")
		}
		if err := as.Delete("doomed"); err != nil {
			t.Errorf("Delete absent: %v, want nil (idempotent)", err)
		}
	})
}

// ── helpers ──────────────────────────────────────────────────────────────

func mustAddRole(t *testing.T, rs store.RoleStore, r policy.Role) {
	t.Helper()
	if err := rs.Add(r); err != nil {
		t.Fatalf("Add %s: %v", r.Name, err)
	}
}

func names(roles []policy.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

func sans(ps []mtls.Principal) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.MatchedSAN)
	}
	sort.Strings(out)
	return out
}
