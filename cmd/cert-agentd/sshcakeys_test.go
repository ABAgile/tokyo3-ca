package main

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSSHCAKeysRefresher_OffWhenUnset(t *testing.T) {
	t.Setenv("CERT_AGENTD_SSH_CA_KEYS_PATH", "")
	r, err := buildSSHCAKeysRefresher(nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if r != nil {
		t.Error("expected nil runner when CERT_AGENTD_SSH_CA_KEYS_PATH is unset")
	}
}

func TestBuildSSHCAKeysRefresher_RejectsBadInterval(t *testing.T) {
	t.Setenv("CERT_AGENTD_SSH_CA_KEYS_PATH", filepath.Join(t.TempDir(), "ca-keys"))
	t.Setenv("CERT_AGENTD_SSH_CA_KEYS_REFRESH_SECONDS", "nope")
	_, err := buildSSHCAKeysRefresher(nil, slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "must be positive integer") {
		t.Errorf("err = %v, want 'must be positive integer'", err)
	}
}
