package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/crypto"
)

// clearPortalOIDCEnv resets every env var loadPortalOIDC reads, so each
// test starts from a clean slate regardless of ambient environment.
func clearPortalOIDCEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CERTD_PORTAL_OIDC_ISSUER", "CERTD_PORTAL_OIDC_CLIENT_ID",
		"CERTD_PORTAL_OIDC_CLIENT_SECRET", "CERTD_PORTAL_OIDC_REDIRECT_URL",
		"CERTD_PORTAL_SESSION_KEY", "CERTD_PORTAL_ADMIN_GROUP",
	} {
		t.Setenv(k, "")
	}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLoadPortalOIDC_NothingSet(t *testing.T) {
	clearPortalOIDCEnv(t)
	cfg, err := loadPortalOIDC(testLogger())
	if err != nil {
		t.Fatalf("loadPortalOIDC: %v", err)
	}
	if cfg.Issuer != "" || len(cfg.SessionKey) != 0 {
		t.Errorf("cfg = %+v, want zero value", cfg)
	}
}

// TestLoadPortalOIDC_SessionKeyAloneEnablesStableBasicAuthCSRF:
// CERTD_PORTAL_SESSION_KEY set with no OIDC fields at all must NOT be
// treated as a partial/broken OIDC config — it's the documented way to
// stabilize the Basic-auth path's CSRF key across restarts without
// enabling OIDC.
func TestLoadPortalOIDC_SessionKeyAloneEnablesStableBasicAuthCSRF(t *testing.T) {
	clearPortalOIDCEnv(t)
	keyHex, err := crypto.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTD_PORTAL_SESSION_KEY", keyHex)

	cfg, err := loadPortalOIDC(testLogger())
	if err != nil {
		t.Fatalf("loadPortalOIDC: %v", err)
	}
	if len(cfg.SessionKey) == 0 {
		t.Fatal("SessionKey not populated")
	}
	// portal.OIDCConfig.enabled() (unexported) requires Issuer/ClientID/
	// Verifier too; asserting those stay unset is the visible proxy from
	// this package that SessionKey alone doesn't flip the mode to OIDC.
	if cfg.Issuer != "" || cfg.ClientID != "" || cfg.Verifier != nil {
		t.Errorf("SessionKey alone must not populate OIDC-enabling fields: cfg = %+v", cfg)
	}
}

func TestLoadPortalOIDC_MalformedSessionKeyAlone(t *testing.T) {
	clearPortalOIDCEnv(t)
	t.Setenv("CERTD_PORTAL_SESSION_KEY", "not-64-hex-chars")
	if _, err := loadPortalOIDC(testLogger()); err == nil {
		t.Error("want error for a malformed CERTD_PORTAL_SESSION_KEY")
	}
}

func TestLoadPortalOIDC_PartialOIDCFieldsRejected(t *testing.T) {
	clearPortalOIDCEnv(t)
	t.Setenv("CERTD_PORTAL_OIDC_ISSUER", "https://idp.example.com")
	// client_id/secret/redirect/session_key all left unset.
	_, err := loadPortalOIDC(testLogger())
	if err == nil || !strings.Contains(err.Error(), "partially configured") {
		t.Fatalf("err = %v, want partially-configured error", err)
	}
}

func TestLoadPortalOIDC_FullQuartetWithoutSessionKeyRejected(t *testing.T) {
	clearPortalOIDCEnv(t)
	t.Setenv("CERTD_PORTAL_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("CERTD_PORTAL_OIDC_CLIENT_ID", "portal")
	t.Setenv("CERTD_PORTAL_OIDC_CLIENT_SECRET", "secret")
	t.Setenv("CERTD_PORTAL_OIDC_REDIRECT_URL", "https://certd.example/portal/auth/callback")
	// CERTD_PORTAL_SESSION_KEY intentionally left unset — still required
	// to actually enable OIDC.
	_, err := loadPortalOIDC(testLogger())
	if err == nil || !strings.Contains(err.Error(), "partially configured") {
		t.Fatalf("err = %v, want partially-configured error", err)
	}
}
