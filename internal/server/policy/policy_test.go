package policy_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/policy"
)

// ── InMemoryStore ─────────────────────────────────────────────────────────────

func TestInMemoryStore_RolesForGroups(t *testing.T) {
	eng := policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"deploy"}}
	sre := policy.Role{Name: "sre", GroupClaim: "sre", AllowedPrincipals: []string{"root", "deploy"}}
	store := policy.NewInMemoryStore(eng, sre)

	got := store.RolesForGroups([]string{"eng"})
	if len(got) != 1 || got[0].Name != "eng" {
		t.Errorf("RolesForGroups(eng) = %v, want [eng]", got)
	}

	got = store.RolesForGroups([]string{"eng", "sre"})
	if len(got) != 2 {
		t.Errorf("RolesForGroups(eng,sre) length = %d, want 2", len(got))
	}

	got = store.RolesForGroups([]string{"nonexistent"})
	if len(got) != 0 {
		t.Errorf("RolesForGroups(nonexistent) = %v, want []", got)
	}

	// Duplicate group claims in the request collapse to one lookup.
	got = store.RolesForGroups([]string{"eng", "eng"})
	if len(got) != 1 {
		t.Errorf("RolesForGroups(eng,eng) length = %d, want 1 (deduped)", len(got))
	}
}

func TestInMemoryStore_ReplaceAll(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{Name: "old", GroupClaim: "g"})
	store.ReplaceAll([]policy.Role{{Name: "new", GroupClaim: "g"}})

	got := store.RolesForGroups([]string{"g"})
	if len(got) != 1 || got[0].Name != "new" {
		t.Errorf("after ReplaceAll, got %v, want [new]", got)
	}
	if all := store.All(); len(all) != 1 {
		t.Errorf("All() length = %d, want 1", len(all))
	}
}

// ── EvaluateUserCert ──────────────────────────────────────────────────────────

func TestEvaluateUserCert_SingleRoleMatch(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name:                  "eng",
		GroupClaim:            "eng",
		AllowedPrincipals:     []string{"deploy", "alice"},
		MaxUserCertTTLSeconds: int64((4 * time.Hour).Seconds()),
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateUserCert([]string{"eng"}, policy.UserCertRequest{
		RequestedPrincipals: []string{"alice"},
		RequestedTTL:        2 * time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateUserCert: %v", err)
	}
	if !slices.Equal(decision.Principals, []string{"alice"}) {
		t.Errorf("Principals = %v, want [alice]", decision.Principals)
	}
	if decision.TTL != 2*time.Hour {
		t.Errorf("TTL = %s, want 2h", decision.TTL)
	}
}

func TestEvaluateUserCert_MultiRoleUnion(t *testing.T) {
	// eng: deploy, 4h. sre: root + deploy, 12h.
	store := policy.NewInMemoryStore(
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"deploy"}, MaxUserCertTTLSeconds: int64((4 * time.Hour).Seconds())},
		policy.Role{Name: "sre", GroupClaim: "sre", AllowedPrincipals: []string{"root", "deploy"}, MaxUserCertTTLSeconds: int64((12 * time.Hour).Seconds())},
	)
	eng := policy.NewEngine(store)

	// Member of both eng + sre can request root, and the TTL ceiling
	// jumps to 12h (the more-permissive ceiling).
	decision, err := eng.EvaluateUserCert(
		[]string{"eng", "sre"},
		policy.UserCertRequest{
			RequestedPrincipals: []string{"root", "deploy"},
			RequestedTTL:        8 * time.Hour,
			EndpointMaxTTL:      24 * time.Hour,
		})
	if err != nil {
		t.Fatalf("EvaluateUserCert: %v", err)
	}
	sortedGot := slices.Clone(decision.Principals)
	slices.Sort(sortedGot)
	if !slices.Equal(sortedGot, []string{"deploy", "root"}) {
		t.Errorf("Principals = %v, want [deploy root]", sortedGot)
	}
	if decision.TTL != 8*time.Hour {
		t.Errorf("TTL = %s, want 8h", decision.TTL)
	}
}

func TestEvaluateUserCert_FiltersDeniedPrincipal(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"deploy"},
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateUserCert([]string{"eng"}, policy.UserCertRequest{
		RequestedPrincipals: []string{"deploy", "root"},
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateUserCert: %v", err)
	}
	// root is filtered out; deploy survives.
	if !slices.Equal(decision.Principals, []string{"deploy"}) {
		t.Errorf("Principals = %v, want [deploy]", decision.Principals)
	}
}

func TestEvaluateUserCert_NoMatchingRole(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"deploy"},
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateUserCert([]string{"random"}, policy.UserCertRequest{
		RequestedPrincipals: []string{"deploy"},
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	})
	if !errors.Is(err, policy.ErrNoRole) {
		t.Errorf("err = %v, want ErrNoRole", err)
	}
}

func TestEvaluateUserCert_EmptyDecision(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"deploy"},
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateUserCert([]string{"eng"}, policy.UserCertRequest{
		RequestedPrincipals: []string{"root"}, // not allowed
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	})
	if !errors.Is(err, policy.ErrEmptyDecision) {
		t.Errorf("err = %v, want ErrEmptyDecision", err)
	}
	if !strings.Contains(err.Error(), "deploy") {
		t.Errorf("err = %q should list allowed principals", err)
	}
}

func TestEvaluateUserCert_TTLCappedAtRoleMax(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals:     []string{"alice"},
		MaxUserCertTTLSeconds: int64((2 * time.Hour).Seconds()),
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateUserCert([]string{"eng"}, policy.UserCertRequest{
		RequestedPrincipals: []string{"alice"},
		RequestedTTL:        24 * time.Hour, // way over role cap
		EndpointMaxTTL:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateUserCert: %v", err)
	}
	if decision.TTL != 2*time.Hour {
		t.Errorf("TTL = %s, want 2h (capped at role max)", decision.TTL)
	}
}

func TestEvaluateUserCert_ZeroRoleTTLUsesEndpointMax(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"alice"},
		// MaxUserCertTTLSeconds unset → 0 → endpoint cap applies.
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateUserCert([]string{"eng"}, policy.UserCertRequest{
		RequestedPrincipals: []string{"alice"},
		RequestedTTL:        12 * time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateUserCert: %v", err)
	}
	if decision.TTL != 12*time.Hour {
		t.Errorf("TTL = %s, want 12h (within endpoint max)", decision.TTL)
	}
}

func TestEvaluateUserCert_MergesDefaultExtensions(t *testing.T) {
	store := policy.NewInMemoryStore(
		policy.Role{Name: "eng", GroupClaim: "eng",
			AllowedPrincipals: []string{"alice"},
			DefaultExtensions: map[string]string{"permit-pty": ""},
		},
		policy.Role{Name: "sre", GroupClaim: "sre",
			AllowedPrincipals: []string{"alice"},
			DefaultExtensions: map[string]string{"permit-port-forwarding": ""},
		},
	)
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateUserCert([]string{"eng", "sre"}, policy.UserCertRequest{
		RequestedPrincipals: []string{"alice"},
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateUserCert: %v", err)
	}
	if _, ok := decision.Extensions["permit-pty"]; !ok {
		t.Error("expected permit-pty in merged extensions")
	}
	if _, ok := decision.Extensions["permit-port-forwarding"]; !ok {
		t.Error("expected permit-port-forwarding in merged extensions")
	}
}

// ── EvaluateHostCert ──────────────────────────────────────────────────────────

func TestEvaluateHostCert_GlobMatch(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "prod-hosts", GroupClaim: "prod-host-admin",
		HostPatterns:          []string{"db-*.prod.internal", "*.staging"},
		MaxHostCertTTLSeconds: int64((7 * 24 * time.Hour).Seconds()),
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateHostCert([]string{"prod-host-admin"}, policy.HostCertRequest{
		RequestedPrincipals: []string{"db-1.prod.internal", "db-2.prod.internal", "api.staging"},
		RequestedTTL:        24 * time.Hour,
		EndpointMaxTTL:      30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateHostCert: %v", err)
	}
	sortedGot := slices.Clone(decision.Principals)
	slices.Sort(sortedGot)
	want := []string{"api.staging", "db-1.prod.internal", "db-2.prod.internal"}
	if !slices.Equal(sortedGot, want) {
		t.Errorf("Principals = %v, want %v", sortedGot, want)
	}
}

func TestEvaluateHostCert_FiltersUnmatchedPrincipal(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "staging-only", GroupClaim: "staging-admin",
		HostPatterns: []string{"*.staging"},
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateHostCert([]string{"staging-admin"}, policy.HostCertRequest{
		RequestedPrincipals: []string{"db-1.prod.internal", "api.staging"},
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateHostCert: %v", err)
	}
	if !slices.Equal(decision.Principals, []string{"api.staging"}) {
		t.Errorf("Principals = %v, want [api.staging]", decision.Principals)
	}
}

func TestEvaluateHostCert_NoRoleMatch(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "x", GroupClaim: "x", HostPatterns: []string{"*"},
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateHostCert([]string{"random"}, policy.HostCertRequest{
		RequestedPrincipals: []string{"db-1.prod.internal"},
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      30 * 24 * time.Hour,
	})
	if !errors.Is(err, policy.ErrNoRole) {
		t.Errorf("err = %v, want ErrNoRole", err)
	}
}

func TestEvaluateHostCert_AllPrincipalsFiltered(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "staging-only", GroupClaim: "staging-admin",
		HostPatterns: []string{"*.staging"},
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateHostCert([]string{"staging-admin"}, policy.HostCertRequest{
		RequestedPrincipals: []string{"db-1.prod.internal"}, // no match
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      30 * 24 * time.Hour,
	})
	if !errors.Is(err, policy.ErrEmptyDecision) {
		t.Errorf("err = %v, want ErrEmptyDecision", err)
	}
}

func TestEvaluateHostCert_TTLCapped(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "x", GroupClaim: "x",
		HostPatterns:          []string{"*"},
		MaxHostCertTTLSeconds: int64((3 * 24 * time.Hour).Seconds()), // 3 days
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateHostCert([]string{"x"}, policy.HostCertRequest{
		RequestedPrincipals: []string{"db-1.prod.internal"},
		RequestedTTL:        14 * 24 * time.Hour, // over role cap
		EndpointMaxTTL:      30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateHostCert: %v", err)
	}
	if decision.TTL != 3*24*time.Hour {
		t.Errorf("TTL = %s, want 3 days", decision.TTL)
	}
}

func TestEvaluateHostCert_InvalidPatternErrors(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "broken", GroupClaim: "broken",
		HostPatterns: []string{"[", "*.staging"}, // "[" is malformed
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateHostCert([]string{"broken"}, policy.HostCertRequest{
		RequestedPrincipals: []string{"api.staging"},
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      30 * 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected error for invalid host pattern")
	}
	if !strings.Contains(err.Error(), "invalid host pattern") {
		t.Errorf("err = %q, want to mention invalid host pattern", err)
	}
}

// ── EvaluateX509Cert ──────────────────────────────────────────────────────────

func TestEvaluateX509Cert_GlobMatch(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "workloads", GroupClaim: "workload-issuer",
		SPIFFEPatterns:        []string{"spiffe://corp/svc/*"},
		MaxX509CertTTLSeconds: int64((12 * time.Hour).Seconds()),
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateX509Cert([]string{"workload-issuer"}, policy.X509CertRequest{
		RequestedSPIFFEURI: "spiffe://corp/svc/billing",
		RequestedTTL:       2 * time.Hour,
		EndpointMaxTTL:     24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateX509Cert: %v", err)
	}
	if decision.SPIFFEURI != "spiffe://corp/svc/billing" {
		t.Errorf("SPIFFEURI = %q", decision.SPIFFEURI)
	}
	if decision.TTL != 2*time.Hour {
		t.Errorf("TTL = %s, want 2h", decision.TTL)
	}
}

func TestEvaluateX509Cert_PatternDoesNotMatch_403(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "workloads", GroupClaim: "workload-issuer",
		SPIFFEPatterns: []string{"spiffe://corp/svc/billing"},
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateX509Cert([]string{"workload-issuer"}, policy.X509CertRequest{
		RequestedSPIFFEURI: "spiffe://corp/svc/admin", // not matched
		RequestedTTL:       time.Hour,
		EndpointMaxTTL:     24 * time.Hour,
	})
	if !errors.Is(err, policy.ErrEmptyDecision) {
		t.Errorf("err = %v, want ErrEmptyDecision", err)
	}
}

func TestEvaluateX509Cert_NoRoleMatch(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "workloads", GroupClaim: "workload-issuer",
		SPIFFEPatterns: []string{"spiffe://corp/*"},
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateX509Cert([]string{"unrelated"}, policy.X509CertRequest{
		RequestedSPIFFEURI: "spiffe://corp/svc/anything",
		RequestedTTL:       time.Hour,
		EndpointMaxTTL:     24 * time.Hour,
	})
	if !errors.Is(err, policy.ErrNoRole) {
		t.Errorf("err = %v, want ErrNoRole", err)
	}
}

func TestEvaluateX509Cert_TTLCapped(t *testing.T) {
	// path.Match's "*" does not span "/", so a single-segment pattern
	// matches a single-segment path. Use spiffe://corp/svc/* to cover
	// the two-segment "svc/billing" tail.
	store := policy.NewInMemoryStore(policy.Role{
		Name: "workloads", GroupClaim: "workload-issuer",
		SPIFFEPatterns:        []string{"spiffe://corp/svc/*"},
		MaxX509CertTTLSeconds: int64((4 * time.Hour).Seconds()),
	})
	eng := policy.NewEngine(store)

	decision, err := eng.EvaluateX509Cert([]string{"workload-issuer"}, policy.X509CertRequest{
		RequestedSPIFFEURI: "spiffe://corp/svc/billing",
		RequestedTTL:       24 * time.Hour, // over role cap
		EndpointMaxTTL:     24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateX509Cert: %v", err)
	}
	if decision.TTL != 4*time.Hour {
		t.Errorf("TTL = %s, want 4h (capped)", decision.TTL)
	}
}

func TestEvaluateX509Cert_InvalidPatternErrors(t *testing.T) {
	store := policy.NewInMemoryStore(policy.Role{
		Name: "broken", GroupClaim: "broken",
		SPIFFEPatterns: []string{"["}, // malformed
	})
	eng := policy.NewEngine(store)

	_, err := eng.EvaluateX509Cert([]string{"broken"}, policy.X509CertRequest{
		RequestedSPIFFEURI: "spiffe://corp/x",
		RequestedTTL:       time.Hour,
		EndpointMaxTTL:     24 * time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid spiffe pattern") {
		t.Errorf("err = %v, want invalid spiffe pattern", err)
	}
}

func TestEvaluateX509Cert_MultiRoleUnion(t *testing.T) {
	store := policy.NewInMemoryStore(
		policy.Role{Name: "a", GroupClaim: "a", SPIFFEPatterns: []string{"spiffe://corp/svc/*"}, MaxX509CertTTLSeconds: int64((1 * time.Hour).Seconds())},
		policy.Role{Name: "b", GroupClaim: "b", SPIFFEPatterns: []string{"spiffe://other/*"}, MaxX509CertTTLSeconds: int64((6 * time.Hour).Seconds())},
	)
	eng := policy.NewEngine(store)

	// Member of a+b can request from either trust domain; the TTL
	// ceiling is the max of the two role caps.
	decision, err := eng.EvaluateX509Cert([]string{"a", "b"}, policy.X509CertRequest{
		RequestedSPIFFEURI: "spiffe://corp/svc/billing",
		RequestedTTL:       12 * time.Hour,
		EndpointMaxTTL:     24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("EvaluateX509Cert: %v", err)
	}
	if decision.TTL != 6*time.Hour {
		t.Errorf("TTL = %s, want 6h (max across roles)", decision.TTL)
	}
}

func TestNewEngine_NilStorePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewEngine(nil) did not panic")
		}
	}()
	_ = policy.NewEngine(nil)
}

func TestInMemoryStore_ByName(t *testing.T) {
	s := policy.NewInMemoryStore(
		policy.Role{Name: "eng", GroupClaim: "eng"},
		policy.Role{Name: "sre", GroupClaim: "sre"},
	)
	r, ok := s.ByName("sre")
	if !ok {
		t.Fatal("ByName(sre) missing")
	}
	if r.GroupClaim != "sre" {
		t.Errorf("GroupClaim = %q", r.GroupClaim)
	}
	if _, ok := s.ByName("ghost"); ok {
		t.Error("ByName(ghost) should be false")
	}
}

func TestInMemoryStore_Add_AppendsRole(t *testing.T) {
	s := policy.NewInMemoryStore()
	if err := s.Add(policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(s.All()) != 1 {
		t.Errorf("All len = %d, want 1", len(s.All()))
	}
	// RolesForGroups returns the new role for its claim.
	if got := s.RolesForGroups([]string{"eng"}); len(got) != 1 || got[0].Name != "eng" {
		t.Errorf("RolesForGroups = %v", got)
	}
}

func TestInMemoryStore_Add_RejectsDuplicateName(t *testing.T) {
	s := policy.NewInMemoryStore(policy.Role{Name: "eng", GroupClaim: "eng"})
	err := s.Add(policy.Role{Name: "eng", GroupClaim: "ops"})
	if !errors.Is(err, policy.ErrRoleExists) {
		t.Errorf("err = %v, want ErrRoleExists", err)
	}
}

func TestInMemoryStore_Add_RejectsEmptyName(t *testing.T) {
	s := policy.NewInMemoryStore()
	if err := s.Add(policy.Role{GroupClaim: "eng"}); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestInMemoryStore_Replace_UpdatesInPlace(t *testing.T) {
	s := policy.NewInMemoryStore(
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)
	updated := policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice", "bob"}}
	if err := s.Replace("eng", updated); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	r, _ := s.ByName("eng")
	if len(r.AllowedPrincipals) != 2 || r.AllowedPrincipals[1] != "bob" {
		t.Errorf("AllowedPrincipals = %v", r.AllowedPrincipals)
	}
}

func TestInMemoryStore_Replace_AllowsRename(t *testing.T) {
	s := policy.NewInMemoryStore(policy.Role{Name: "eng", GroupClaim: "eng"})
	if err := s.Replace("eng", policy.Role{Name: "engineering", GroupClaim: "eng"}); err != nil {
		t.Fatalf("Replace rename: %v", err)
	}
	if _, ok := s.ByName("eng"); ok {
		t.Error("old name still present after rename")
	}
	if _, ok := s.ByName("engineering"); !ok {
		t.Error("new name absent after rename")
	}
}

func TestInMemoryStore_Replace_RejectsRenameOverExistingName(t *testing.T) {
	s := policy.NewInMemoryStore(
		policy.Role{Name: "eng", GroupClaim: "eng"},
		policy.Role{Name: "sre", GroupClaim: "sre"},
	)
	err := s.Replace("eng", policy.Role{Name: "sre", GroupClaim: "eng"})
	if !errors.Is(err, policy.ErrRoleExists) {
		t.Errorf("err = %v, want ErrRoleExists", err)
	}
}

func TestInMemoryStore_Replace_MissingNameErrors(t *testing.T) {
	s := policy.NewInMemoryStore()
	err := s.Replace("ghost", policy.Role{Name: "ghost", GroupClaim: "x"})
	if !errors.Is(err, policy.ErrRoleNotFound) {
		t.Errorf("err = %v, want ErrRoleNotFound", err)
	}
}

func TestInMemoryStore_Delete_RemovesRole(t *testing.T) {
	s := policy.NewInMemoryStore(
		policy.Role{Name: "eng", GroupClaim: "eng"},
		policy.Role{Name: "sre", GroupClaim: "sre"},
	)
	if err := s.Delete("eng"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(s.All()) != 1 {
		t.Errorf("All len = %d, want 1", len(s.All()))
	}
	if _, ok := s.ByName("eng"); ok {
		t.Error("eng still present after Delete")
	}
}

func TestInMemoryStore_Delete_MissingNameErrors(t *testing.T) {
	s := policy.NewInMemoryStore()
	err := s.Delete("ghost")
	if !errors.Is(err, policy.ErrRoleNotFound) {
		t.Errorf("err = %v, want ErrRoleNotFound", err)
	}
}
