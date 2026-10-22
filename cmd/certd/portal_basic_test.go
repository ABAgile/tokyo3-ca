package main

import "testing"

func clearPortalBasicEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CERTD_PORTAL_USERNAME", "CERTD_PORTAL_PASSWORD", "CERTD_PORTAL_REALM"} {
		t.Setenv(k, "")
	}
}

func TestLoadPortalBasicAuth_HalfConfiguredRejected(t *testing.T) {
	for _, tc := range []struct{ user, pass string }{
		{"admin", ""},
		{"", "secret"},
	} {
		clearPortalBasicEnv(t)
		t.Setenv("CERTD_PORTAL_USERNAME", tc.user)
		t.Setenv("CERTD_PORTAL_PASSWORD", tc.pass)
		if _, err := loadPortalBasicAuth(); err == nil {
			t.Errorf("user=%q pass=%q: expected error for half-configured gate", tc.user, tc.pass)
		}
	}
}

func TestLoadPortalBasicAuth_UnsetOrComplete(t *testing.T) {
	clearPortalBasicEnv(t)
	cfg, err := loadPortalBasicAuth()
	if err != nil {
		t.Fatalf("unset: %v", err)
	}
	if cfg.Enabled() {
		t.Error("unset: gate should be disabled")
	}
	if cfg.Realm != "certd portal" {
		t.Errorf("default realm = %q", cfg.Realm)
	}

	t.Setenv("CERTD_PORTAL_USERNAME", "admin")
	t.Setenv("CERTD_PORTAL_PASSWORD", "secret")
	cfg, err = loadPortalBasicAuth()
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !cfg.Enabled() || cfg.Username != "admin" || cfg.Password != "secret" {
		t.Errorf("complete: got %+v", cfg)
	}
}
