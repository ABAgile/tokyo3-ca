package reconcile_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/reconcile"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/store"
	"github.com/abagile/tokyo3-ca/internal/store/sqlite"
)

func rec(name, group, source string) store.RoleRecord {
	return store.RoleRecord{Role: policy.Role{Name: name, GroupClaim: group}, Source: source}
}

func TestDiffRoles(t *testing.T) {
	db := []store.RoleRecord{
		rec("keep", "g1", store.SourceConfig),     // unchanged
		rec("change", "old", store.SourceConfig),  // updated
		rec("orphan", "g3", store.SourceConfig),   // pruned (config, absent from file)
		rec("portal-x", "g4", store.SourcePortal), // portal-owned, absent from file → left alone
		rec("collide", "g5", store.SourcePortal),  // portal-owned, present in file → conflict
	}
	file := []policy.Role{
		{Name: "keep", GroupClaim: "g1"},
		{Name: "change", GroupClaim: "new"},
		{Name: "fresh", GroupClaim: "g6"}, // added
		{Name: "collide", GroupClaim: "g5"},
	}

	p := reconcile.DiffRoles(file, db, false)
	if got := names(p.Add); len(got) != 1 || got[0] != "fresh" {
		t.Errorf("Add = %v, want [fresh]", got)
	}
	if got := names(p.Update); len(got) != 1 || got[0] != "change" {
		t.Errorf("Update = %v, want [change]", got)
	}
	if len(p.Prune) != 1 || p.Prune[0] != "orphan" {
		t.Errorf("Prune = %v, want [orphan] (portal-x must NOT be pruned)", p.Prune)
	}
	if len(p.Conflicts) != 1 || p.Conflicts[0] != "collide" {
		t.Errorf("Conflicts = %v, want [collide]", p.Conflicts)
	}

	// With adopt, the collision becomes an ownership-taking update, not a conflict.
	pa := reconcile.DiffRoles(file, db, true)
	if len(pa.Conflicts) != 0 {
		t.Errorf("adopt Conflicts = %v, want none", pa.Conflicts)
	}
	if got := names(pa.Update); len(got) != 2 || got[0] != "change" || got[1] != "collide" {
		t.Errorf("adopt Update = %v, want [change collide]", got)
	}
}

func TestRoleEqualSetInsensitive(t *testing.T) {
	a := policy.Role{Name: "r", AllowedPrincipals: []string{"a", "b"}, HostPatterns: nil}
	b := policy.Role{Name: "r", AllowedPrincipals: []string{"b", "a"}, HostPatterns: []string{}}
	if !reconcile.RoleEqual(a, b) {
		t.Error("RoleEqual = false for reordered principals + nil/empty host patterns, want true")
	}
	c := policy.Role{Name: "r", AllowedPrincipals: []string{"a"}}
	if reconcile.RoleEqual(a, c) {
		t.Error("RoleEqual = true for differing principal sets, want false")
	}
}

func TestDiffPrincipals(t *testing.T) {
	db := []store.PrincipalRecord{
		{Principal: mtls.Principal{Name: "keep", MatchedSAN: "spiffe://keep"}, Source: store.SourceConfig},
		{Principal: mtls.Principal{Name: "old", MatchedSAN: "spiffe://change", Groups: []string{"a"}}, Source: store.SourceConfig},
		{Principal: mtls.Principal{Name: "orphan", MatchedSAN: "spiffe://orphan"}, Source: store.SourceConfig},
		{Principal: mtls.Principal{Name: "p", MatchedSAN: "spiffe://portal"}, Source: store.SourcePortal},
	}
	file := []mtls.Principal{
		{Name: "keep", MatchedSAN: "spiffe://keep"},
		{Name: "new", MatchedSAN: "spiffe://change", Groups: []string{"a", "b"}},
		{Name: "fresh", MatchedSAN: "spiffe://fresh"},
		{Name: "skipme", MatchedSAN: ""}, // no SAN → ignored
	}
	p := reconcile.DiffPrincipals(file, db, false)
	if len(p.Add) != 1 || p.Add[0].MatchedSAN != "spiffe://fresh" {
		t.Errorf("Add = %+v, want [spiffe://fresh]", p.Add)
	}
	if len(p.Update) != 1 || p.Update[0].MatchedSAN != "spiffe://change" {
		t.Errorf("Update = %+v, want [spiffe://change]", p.Update)
	}
	if len(p.Prune) != 1 || p.Prune[0] != "spiffe://orphan" {
		t.Errorf("Prune = %v, want [spiffe://orphan]", p.Prune)
	}
}

// TestApplyAndIdempotency applies a plan to a real store, then re-diffs to
// confirm a second run is a no-op (the GitOps convergence property).
func TestApplyAndIdempotency(t *testing.T) {
	db := openDB(t)
	rs := db.Roles()

	// A portal-created role that reconcile must never touch.
	if err := rs.Add(policy.Role{Name: "portal-only", GroupClaim: "p"}, store.SourcePortal); err != nil {
		t.Fatalf("seed portal role: %v", err)
	}

	file := []policy.Role{
		{Name: "alpha", GroupClaim: "g1"},
		{Name: "beta", GroupClaim: "g2"},
	}

	apply := func() reconcile.Applied {
		recs, err := rs.AllWithSource()
		if err != nil {
			t.Fatalf("AllWithSource: %v", err)
		}
		plan := reconcile.DiffRoles(file, recs, false)
		ap, err := plan.ApplyRoles(rs, true)
		if err != nil {
			t.Fatalf("ApplyRoles: %v", err)
		}
		return ap
	}

	if ap := apply(); ap.Added != 2 || ap.Updated != 0 || ap.Pruned != 0 {
		t.Fatalf("first apply = %+v, want 2 added", ap)
	}
	// Second run converges to a no-op.
	if ap := apply(); (ap != reconcile.Applied{}) {
		t.Errorf("second apply = %+v, want zero (idempotent)", ap)
	}
	// The portal role survived (never pruned).
	if _, ok := rs.ByName("portal-only"); !ok {
		t.Error("portal-only role was pruned by reconcile")
	}

	// Dropping beta from the file prunes it on the next apply — but only beta.
	file = []policy.Role{{Name: "alpha", GroupClaim: "g1"}}
	if ap := apply(); ap.Pruned != 1 {
		t.Errorf("prune apply = %+v, want 1 pruned", ap)
	}
	if _, ok := rs.ByName("beta"); ok {
		t.Error("beta not pruned")
	}
	if _, ok := rs.ByName("alpha"); !ok {
		t.Error("alpha wrongly pruned")
	}
}

func openDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "certd.db"), nil)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func names[T any](xs []T) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		switch v := any(x).(type) {
		case policy.Role:
			out = append(out, v.Name)
		}
	}
	return out
}
