package policy_test

import (
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/policy"
)

// realisticStore returns a policy store seeded with ~20 roles —
// realistic upper bound for a single-org deployment. Each role
// carries a few principals + host patterns + a TTL cap; the
// distribution shape matters because EvaluateUserCert iterates the
// matched roles and unions their principals.
func realisticStore() *policy.InMemoryStore {
	roles := []policy.Role{
		{Name: "eng-dev", GroupClaim: "eng", AllowedPrincipals: []string{"alice", "bob", "deployer"}, HostPatterns: []string{"*.dev.internal"}, MaxUserCertTTL: 4 * time.Hour},
		{Name: "eng-prod", GroupClaim: "eng-prod", AllowedPrincipals: []string{"alice", "deployer"}, HostPatterns: []string{"*.prod.internal", "db-*.prod.internal"}, MaxUserCertTTL: time.Hour},
		{Name: "sre", GroupClaim: "sre", AllowedPrincipals: []string{"root", "deployer"}, HostPatterns: []string{"*"}, MaxUserCertTTL: 2 * time.Hour},
		{Name: "ops", GroupClaim: "ops", AllowedPrincipals: []string{"ubuntu", "deployer"}, HostPatterns: []string{"*.internal"}, MaxUserCertTTL: 8 * time.Hour},
		{Name: "data", GroupClaim: "data", AllowedPrincipals: []string{"alice", "data-eng"}, HostPatterns: []string{"*-data*.prod.internal"}, MaxUserCertTTL: 4 * time.Hour},
		{Name: "audit", GroupClaim: "audit", AllowedPrincipals: []string{"readonly"}, HostPatterns: []string{"*.audit.internal"}, MaxUserCertTTL: 30 * time.Minute},
		{Name: "qa", GroupClaim: "qa", AllowedPrincipals: []string{"qa-user"}, HostPatterns: []string{"*.qa.internal"}, MaxUserCertTTL: 4 * time.Hour},
	}
	return policy.NewInMemoryStore(roles...)
}

// BenchmarkEvaluateUserCert_SingleRole exercises the common path: a
// caller in one group requesting principals her role allows. Runs
// once per sign-user request.
func BenchmarkEvaluateUserCert_SingleRole(b *testing.B) {
	store := realisticStore()
	engine := policy.NewEngine(store)
	req := policy.UserCertRequest{
		RequestedPrincipals: []string{"alice"},
		RequestedTTL:        time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	}
	groups := []string{"eng"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := engine.EvaluateUserCert(groups, req); err != nil {
			b.Fatalf("EvaluateUserCert: %v", err)
		}
	}
}

// BenchmarkEvaluateUserCert_MultiRole exercises a multi-role caller
// (eng + sre + ops) requesting principals that span their union.
func BenchmarkEvaluateUserCert_MultiRole(b *testing.B) {
	store := realisticStore()
	engine := policy.NewEngine(store)
	req := policy.UserCertRequest{
		RequestedPrincipals: []string{"alice", "root", "ubuntu", "deployer"},
		RequestedTTL:        2 * time.Hour,
		EndpointMaxTTL:      24 * time.Hour,
	}
	groups := []string{"eng", "sre", "ops"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := engine.EvaluateUserCert(groups, req); err != nil {
			b.Fatalf("EvaluateUserCert: %v", err)
		}
	}
}

// BenchmarkEvaluateHostCert_PatternMatch exercises the host-cert
// path with a glob-heavy role table. host-pattern globbing is the
// most expensive bit per request.
func BenchmarkEvaluateHostCert_PatternMatch(b *testing.B) {
	store := realisticStore()
	engine := policy.NewEngine(store)
	req := policy.HostCertRequest{
		RequestedPrincipals: []string{"db-1.prod.internal"},
		RequestedTTL:        24 * time.Hour,
		EndpointMaxTTL:      30 * 24 * time.Hour,
	}
	groups := []string{"sre"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := engine.EvaluateHostCert(groups, req); err != nil {
			b.Fatalf("EvaluateHostCert: %v", err)
		}
	}
}
