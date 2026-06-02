package api_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// newPolicyServer returns a Server configured with the given roles and
// the subject pubkey/authorized-keys string to use in requests.
func newPolicyServer(t *testing.T, roles ...policy.Role) (*api.Server, string) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	_, _, subjectAuthKey, _ := newSignServer(t)

	store := policy.NewInMemoryStore(roles...)
	eng := policy.NewEngine(store)

	srv, err := api.New(api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		Policy:   eng,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return srv, subjectAuthKey
}

func TestPolicy_HealthzReportsActive(t *testing.T) {
	srv, _ := newPolicyServer(t, policy.Role{Name: "x", GroupClaim: "x"})
	body := getJSON(t, srv, "/healthz")
	if got := body["policy_active"]; got != true {
		t.Errorf("policy_active = %v, want true", got)
	}
}

func TestPolicy_SignUserCert_HappyPath_FiltersAndCaps(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t,
		policy.Role{
			Name: "eng", GroupClaim: "eng",
			AllowedPrincipals:     []string{"deploy"},
			MaxUserCertTTLSeconds: int64((2 * time.Hour).Seconds()),
			DefaultExtensions:     map[string]string{"permit-pty": ""},
		},
	)

	// Requested principals: deploy (allowed) + root (denied → dropped).
	// Requested TTL: 12h → capped at role's 2h.
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key":  subjectAuthKey,
		"key_id":      "user:alice@example.com",
		"principals":  []string{"deploy", "root"},
		"groups":      []string{"eng"},
		"ttl_seconds": int64(12 * 60 * 60),
	})

	var resp struct {
		Certificate string    `json:"certificate"`
		Principals  []string  `json:"principals"`
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)

	// root filtered out; deploy survives.
	if !slices.Equal(resp.Principals, []string{"deploy"}) {
		t.Errorf("principals = %v, want [deploy]", resp.Principals)
	}
	// TTL capped at 2h (role's MaxUserCertTTLSeconds).
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != 2*time.Hour {
		t.Errorf("validity window = %s, want 2h (capped)", got)
	}

	// Cert carries the role default permit-pty extension.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert := pub.(*ssh.Certificate)
	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Error("expected permit-pty extension from role default")
	}
}

func TestPolicy_SignUserCert_RequestExtensionsWinOnConflict(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t, policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"alice"},
		DefaultExtensions: map[string]string{"permit-pty": "role-default"},
	})

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
		"groups":     []string{"eng"},
		"extensions": map[string]string{
			"permit-pty":              "request-override",
			"permit-agent-forwarding": "",
		},
	})

	var resp struct {
		Certificate string `json:"certificate"`
	}
	decodeJSON(t, rec, &resp)

	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	cert := pub.(*ssh.Certificate)
	if got := cert.Permissions.Extensions["permit-pty"]; got != "request-override" {
		t.Errorf("permit-pty = %q, want request override to win", got)
	}
	if _, ok := cert.Permissions.Extensions["permit-agent-forwarding"]; !ok {
		t.Error("expected request-only extension to be present")
	}
}

func TestPolicy_SignUserCert_RejectsMissingGroups(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t, policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"alice"},
	})

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
		// groups omitted
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "groups") {
		t.Errorf("error = %q, want to mention groups", msg)
	}
}

func TestPolicy_SignUserCert_ForbiddenWhenNoMatchingRole(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t, policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"alice"},
	})

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
		"groups":     []string{"unrelated"},
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "no role") {
		t.Errorf("error = %q, want 'no role'", msg)
	}
}

func TestPolicy_SignUserCert_ForbiddenWhenAllPrincipalsDenied(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t, policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"deploy"},
	})

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"root"}, // not allowed
		"groups":     []string{"eng"},
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "denies") {
		t.Errorf("error = %q, want 'denies'", msg)
	}
}

func TestPolicy_SignHostCert_GlobAndTTL(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t, policy.Role{
		Name: "prod-hosts", GroupClaim: "prod-host-admin",
		HostPatterns:          []string{"db-*.prod.internal", "*.staging"},
		MaxHostCertTTLSeconds: int64((24 * time.Hour).Seconds()),
	})

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-host", map[string]any{
		"public_key":  subjectAuthKey,
		"key_id":      "host:db-1.prod.internal",
		"principals":  []string{"db-1.prod.internal", "api.staging", "other.example.com"},
		"groups":      []string{"prod-host-admin"},
		"ttl_seconds": int64(7 * 24 * 60 * 60), // requested 7d, capped at role's 24h
	})

	var resp struct {
		Principals  []string  `json:"principals"`
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)

	got := slices.Clone(resp.Principals)
	slices.Sort(got)
	want := []string{"api.staging", "db-1.prod.internal"}
	if !slices.Equal(got, want) {
		t.Errorf("principals = %v, want %v (other.example.com filtered out)", got, want)
	}
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != 24*time.Hour {
		t.Errorf("TTL = %s, want 24h (capped)", got)
	}
}

func TestPolicy_SignHostCert_ForbiddenAllFiltered(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t, policy.Role{
		Name: "staging-only", GroupClaim: "staging-admin",
		HostPatterns: []string{"*.staging"},
	})

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-host", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "host:db-1",
		"principals": []string{"db-1.prod.internal"}, // doesn't match *.staging
		"groups":     []string{"staging-admin"},
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPolicy_MultipleGroupsUnion(t *testing.T) {
	srv, subjectAuthKey := newPolicyServer(t,
		policy.Role{Name: "eng", GroupClaim: "eng",
			AllowedPrincipals:     []string{"deploy"},
			MaxUserCertTTLSeconds: int64((1 * time.Hour).Seconds()),
		},
		policy.Role{Name: "sre", GroupClaim: "sre",
			AllowedPrincipals:     []string{"root"},
			MaxUserCertTTLSeconds: int64((8 * time.Hour).Seconds()),
		},
	)

	// Caller in both groups: should get both principals, TTL 8h
	// (max of the two role caps).
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key":  subjectAuthKey,
		"key_id":      "user:alice",
		"principals":  []string{"deploy", "root"},
		"groups":      []string{"eng", "sre"},
		"ttl_seconds": int64(24 * 60 * 60), // requested 24h, capped at 8h
	})

	var resp struct {
		Principals  []string  `json:"principals"`
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)
	got := slices.Clone(resp.Principals)
	slices.Sort(got)
	if !slices.Equal(got, []string{"deploy", "root"}) {
		t.Errorf("principals = %v, want [deploy root]", got)
	}
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != 8*time.Hour {
		t.Errorf("TTL = %s, want 8h", got)
	}
}
