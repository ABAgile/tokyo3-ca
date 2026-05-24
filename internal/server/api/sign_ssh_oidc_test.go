package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// stubVerifier lets the API tests exercise the OIDC integration
// without spinning up a real issuer. Verify always returns the
// configured claims/err; the raw token is ignored.
type stubVerifier struct {
	claims *oidc.Claims
	err    error
}

func (s stubVerifier) Verify(_ context.Context, _ string) (*oidc.Claims, error) {
	return s.claims, s.err
}

// newOIDCServer constructs a Server with the given stub verifier and
// an optional role engine.
func newOIDCServer(t *testing.T, ver oidc.TokenVerifier, roles ...policy.Role) (*api.Server, string) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	_, _, subjectAuthKey, _ := newSignServer(t)

	cfg := api.Config{
		Log:          silentLogger(),
		CASigner:     caSig,
		OIDCVerifier: ver,
	}
	if len(roles) > 0 {
		cfg.Policy = policy.NewEngine(policy.NewInMemoryStore(roles...))
	}
	srv, err := api.New(cfg)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return srv, subjectAuthKey
}

// doSignWithToken issues a POST sign-user request with the given
// Authorization header value.
func doSignWithToken(srv *api.Server, authHeader string, body map[string]any) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	var buf strings.Builder
	if body != nil {
		_, _ = buf.WriteString(`{`)
		first := true
		for k, v := range body {
			if !first {
				_, _ = buf.WriteString(`,`)
			}
			first = false
			_, _ = buf.WriteString(`"` + k + `":`)
			switch vv := v.(type) {
			case string:
				_, _ = buf.WriteString(`"` + vv + `"`)
			case []string:
				_, _ = buf.WriteString(`[`)
				for i, s := range vv {
					if i > 0 {
						_, _ = buf.WriteString(`,`)
					}
					_, _ = buf.WriteString(`"` + s + `"`)
				}
				_, _ = buf.WriteString(`]`)
			default:
				panic("unsupported body value type")
			}
		}
		_, _ = buf.WriteString(`}`)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/sign-user", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestOIDC_HealthzReportsActive(t *testing.T) {
	srv, _ := newOIDCServer(t, stubVerifier{claims: &oidc.Claims{}})
	body := getJSON(t, srv, "/healthz")
	if got := body["oidc_active"]; got != true {
		t.Errorf("oidc_active = %v, want true", got)
	}
}

func TestOIDC_RejectsMissingAuthorization(t *testing.T) {
	srv, subjectAuthKey := newOIDCServer(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"eng"}}},
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignWithToken(srv, "", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "Authorization") {
		t.Errorf("error = %q, want to mention Authorization", msg)
	}
}

func TestOIDC_RejectsMalformedAuthorization(t *testing.T) {
	srv, subjectAuthKey := newOIDCServer(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"eng"}}},
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	cases := []string{
		"BearerNoSpace",
		"Basic dXNlcjpwYXNz",
		"Bearer ",
		"Bearer  ", // only whitespace
	}
	for _, h := range cases {
		t.Run(h, func(t *testing.T) {
			rec := doSignWithToken(srv, h, map[string]any{
				"public_key": subjectAuthKey,
				"key_id":     "k",
				"principals": []string{"alice"},
			})
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Authorization=%q: status = %d, want 401", h, rec.Code)
			}
		})
	}
}

func TestOIDC_RejectsInvalidToken(t *testing.T) {
	srv, subjectAuthKey := newOIDCServer(t,
		stubVerifier{err: errors.New("token expired")},
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignWithToken(srv, "Bearer bogus", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "invalid bearer token") {
		t.Errorf("error = %q, want 'invalid bearer token'", msg)
	}
}

func TestOIDC_TokenGroupsOverrideBodyGroups(t *testing.T) {
	// The verifier surfaces groups=[sre] from the token; the request
	// body claims groups=[unrelated]. The token must win.
	srv, subjectAuthKey := newOIDCServer(t,
		stubVerifier{claims: &oidc.Claims{
			Subject: "user-uuid",
			Groups:  []string{"sre"},
		}},
		policy.Role{Name: "sre", GroupClaim: "sre", AllowedPrincipals: []string{"root"}},
		policy.Role{Name: "unrelated", GroupClaim: "unrelated", AllowedPrincipals: []string{"alice"}},
	)

	// Caller asks for principal=root, which only the sre role
	// permits. If body groups were used instead, this would 403.
	rec := doSignWithToken(srv, "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"root"},
		"groups":     []string{"unrelated"}, // lies — gets ignored
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Principals []string `json:"principals"`
	}
	decodeJSON(t, rec, &resp)
	if !slices.Equal(resp.Principals, []string{"root"}) {
		t.Errorf("principals = %v, want [root]", resp.Principals)
	}
}

func TestOIDC_VerifiedTokenNoGroupsClaim_RejectedByPolicy(t *testing.T) {
	// Token verifies, but the claims carry no groups. Policy is
	// active → 400 (groups required when policy is active).
	srv, subjectAuthKey := newOIDCServer(t,
		stubVerifier{claims: &oidc.Claims{Subject: "user-uuid"}},
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	rec := doSignWithToken(srv, "Bearer x", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "groups") {
		t.Errorf("error = %q, want to mention groups", msg)
	}
}

func TestOIDC_NoOIDC_BodyGroupsStillRespected(t *testing.T) {
	// No OIDC verifier wired. Policy + body groups path stays open.
	// (This is the pre-2.6 behavior and must keep working for tests
	// and the pre-prod single-binary deployments.)
	srv, subjectAuthKey := newPolicyServer(t, policy.Role{
		Name: "eng", GroupClaim: "eng",
		AllowedPrincipals: []string{"alice"},
	})

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
		"groups":     []string{"eng"},
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 in non-OIDC mode; body=%s", rec.Code, rec.Body.String())
	}
}

func TestOIDC_HostCertEndpoint_AlsoRequiresToken(t *testing.T) {
	srv, subjectAuthKey := newOIDCServer(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"prod-host-admin"}}},
		policy.Role{
			Name: "prod-hosts", GroupClaim: "prod-host-admin",
			HostPatterns: []string{"db-*.prod.internal"},
		},
	)

	// Missing Authorization → 401, even on sign-host.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/sign-host", strings.NewReader(`{
		"public_key":"`+subjectAuthKey+`",
		"key_id":"host:db-1",
		"principals":["db-1.prod.internal"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}

	// With token, succeeds.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ssh/sign-host", strings.NewReader(`{
		"public_key":"`+subjectAuthKey+`",
		"key_id":"host:db-1",
		"principals":["db-1.prod.internal"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer x")
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("with token: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestOIDC_BearerHeaderCaseInsensitive(t *testing.T) {
	srv, subjectAuthKey := newOIDCServer(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"eng"}}},
		policy.Role{Name: "eng", GroupClaim: "eng", AllowedPrincipals: []string{"alice"}},
	)

	for _, h := range []string{"Bearer x", "bearer x", "BEARER x", "BeArEr x"} {
		t.Run(h, func(t *testing.T) {
			rec := doSignWithToken(srv, h, map[string]any{
				"public_key": subjectAuthKey,
				"key_id":     "k",
				"principals": []string{"alice"},
			})
			if rec.Code != http.StatusOK {
				t.Errorf("Authorization=%q: status = %d, want 200; body=%s", h, rec.Code, rec.Body.String())
			}
		})
	}
}
