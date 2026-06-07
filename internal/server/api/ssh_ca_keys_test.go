package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

func getSSHCAKeys(t *testing.T, srv *api.Server) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ssh/ca-keys", nil))
	if rec.Code != http.StatusOK {
		return rec.Code, rec.Body.String()
	}
	var resp struct {
		TrustedUserCAKeys string `json:"trusted_user_ca_keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec.Code, resp.TrustedUserCAKeys
}

func liveSSHCAKey(t *testing.T, sig signer.Signer) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(sig.Public())
	if err != nil {
		t.Fatalf("ssh pubkey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(pub))
}

func TestSSHCAKeys_DerivesLiveKeyWhenUnset(t *testing.T) {
	sig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	srv, err := api.New(api.Config{Log: silentLogger(), CASigner: sig})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	code, body := getSSHCAKeys(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", code, body)
	}
	if want := liveSSHCAKey(t, sig); body != want {
		t.Errorf("served key = %q, want live CA key %q", body, want)
	}
}

func TestSSHCAKeys_ServesConfiguredFile(t *testing.T) {
	sig, _ := signer.NewEphemeralEd25519()
	set := "ssh-ed25519 AAAAOLD old@ca\nssh-ed25519 AAAANEW new@ca\n" // old⊕new overlap
	path := filepath.Join(t.TempDir(), "ca-keys")
	if err := os.WriteFile(path, []byte(set), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	srv, err := api.New(api.Config{Log: silentLogger(), CASigner: sig, SSHCAKeysPath: path})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	code, body := getSSHCAKeys(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", code, body)
	}
	if body != set {
		t.Errorf("served = %q, want file contents %q", body, set)
	}
}

func TestSSHCAKeys_FallsBackOnEmptyFile(t *testing.T) {
	sig, _ := signer.NewEphemeralEd25519()
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, []byte("  \n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	srv, err := api.New(api.Config{Log: silentLogger(), CASigner: sig, SSHCAKeysPath: path})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	code, body := getSSHCAKeys(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", code, body)
	}
	if want := liveSSHCAKey(t, sig); body != want {
		t.Errorf("empty file: served %q, want live-key fallback %q", body, want)
	}
}
