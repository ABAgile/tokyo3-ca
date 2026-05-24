package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// newSignServer returns a Server backed by a fresh in-memory CA and a
// fresh subject keypair to use as the cert subject. Returns the
// authorized_keys-encoded subject pubkey alongside.
func newSignServer(t *testing.T) (*api.Server, ssh.PublicKey, string, ssh.PublicKey) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	caPub, err := ssh.NewPublicKey(caSig.Public())
	if err != nil {
		t.Fatalf("ca public: %v", err)
	}

	_, subjectPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}
	subjectPub, err := ssh.NewPublicKey(subjectPriv.Public())
	if err != nil {
		t.Fatalf("subject ssh pub: %v", err)
	}
	subjectAuthKey := string(ssh.MarshalAuthorizedKey(subjectPub))

	srv, err := api.New(api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return srv, caPub, strings.TrimRight(subjectAuthKey, "\n"), subjectPub
}

func doJSON(t *testing.T, srv *api.Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// decodeJSON parses a successful response body into v; fails the test
// on any non-200.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
}

// errorBody returns the {error: "..."} message from a 4xx/5xx response.
func errorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v; raw=%s", err, rec.Body.String())
	}
	return body.Error
}

// ── happy paths ───────────────────────────────────────────────────────────────

func TestSignUserCert_HappyPath(t *testing.T) {
	srv, caPub, subjectAuthKey, subjectPub := newSignServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key":  subjectAuthKey,
		"key_id":      "user:alice@example.com",
		"principals":  []string{"alice", "deploy"},
		"ttl_seconds": 3600,
		"extensions":  map[string]string{"permit-pty": ""},
	})

	var resp struct {
		Certificate string    `json:"certificate"`
		Serial      uint64    `json:"serial"`
		KeyID       string    `json:"key_id"`
		Principals  []string  `json:"principals"`
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)

	if resp.KeyID != "user:alice@example.com" {
		t.Errorf("key_id = %q", resp.KeyID)
	}
	if resp.Serial == 0 {
		t.Error("serial = 0, want non-zero")
	}
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != time.Hour {
		t.Errorf("validity window = %s, want 1h", got)
	}

	// Parse the returned cert and verify it against the CA.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("parse returned cert: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("returned key is %T, want *ssh.Certificate", pub)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want UserCert", cert.CertType)
	}
	if string(cert.Key.Marshal()) != string(subjectPub.Marshal()) {
		t.Error("cert subject key does not match the requested public_key")
	}

	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caPub.Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Errorf("CheckCert(alice): %v", err)
	}
}

func TestSignUserCert_DefaultsTTL(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "user:alice",
		"principals": []string{"alice"},
		// ttl_seconds omitted → default 1h.
	})
	var resp struct {
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != time.Hour {
		t.Errorf("default user TTL = %s, want 1h", got)
	}
}

func TestSignHostCert_HappyPath(t *testing.T) {
	srv, caPub, subjectAuthKey, _ := newSignServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-host", map[string]any{
		"public_key":  subjectAuthKey,
		"key_id":      "host:db-1.prod.internal",
		"principals":  []string{"db-1.prod.internal", "db-1"},
		"ttl_seconds": 7 * 24 * 60 * 60,
	})

	var resp struct {
		Certificate string `json:"certificate"`
	}
	decodeJSON(t, rec, &resp)

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert := pub.(*ssh.Certificate)
	if cert.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want HostCert", cert.CertType)
	}

	checker := ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(caPub.Marshal())
		},
	}
	if err := checker.CheckHostKey("db-1.prod.internal:22", &fakeAddr{"db-1.prod.internal:22"}, cert); err != nil {
		t.Errorf("CheckHostKey: %v", err)
	}
}

func TestSignHostCert_DefaultsTTL(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)

	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-host", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "host:db-1",
		"principals": []string{"db-1.prod.internal"},
	})
	var resp struct {
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)
	want := 7 * 24 * time.Hour
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != want {
		t.Errorf("default host TTL = %s, want %s", got, want)
	}
}

// ── error paths ───────────────────────────────────────────────────────────────

func TestSignUserCert_BadJSON(t *testing.T) {
	srv, _, _, _ := newSignServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ssh/sign-user", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "invalid JSON") {
		t.Errorf("error = %q, want to contain 'invalid JSON'", msg)
	}
}

func TestSignUserCert_UnknownField(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{"alice"},
		"surprise":   "unknown field",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "surprise") {
		t.Errorf("error = %q, want to mention unknown field name", msg)
	}
}

func TestSignUserCert_InvalidPubKey(t *testing.T) {
	srv, _, _, _ := newSignServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": "not-a-real-ssh-key",
		"key_id":     "k",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "public_key") {
		t.Errorf("error = %q, want to mention public_key", msg)
	}
}

func TestSignUserCert_EmptyPubKey(t *testing.T) {
	srv, _, _, _ := newSignServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": "",
		"key_id":     "k",
		"principals": []string{"alice"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "required") {
		t.Errorf("error = %q, want 'required'", msg)
	}
}

func TestSignUserCert_TTLBounds(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)

	// 25 hours exceeds maxUserCertTTL (24h).
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key":  subjectAuthKey,
		"key_id":      "k",
		"principals":  []string{"alice"},
		"ttl_seconds": int64(25 * 60 * 60),
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "user-cert maximum") {
		t.Errorf("error = %q, want 'user-cert maximum'", msg)
	}
}

func TestSignHostCert_TTLBounds(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)

	// 31 days exceeds maxHostCertTTL (30d).
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-host", map[string]any{
		"public_key":  subjectAuthKey,
		"key_id":      "host:db-1",
		"principals":  []string{"db-1.prod.internal"},
		"ttl_seconds": int64(31 * 24 * 60 * 60),
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "host-cert maximum") {
		t.Errorf("error = %q, want 'host-cert maximum'", msg)
	}
}

func TestSignUserCert_MissingPrincipals(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		// principals omitted entirely
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "principals") {
		t.Errorf("error = %q, want to mention principals", msg)
	}
}

func TestSignEndpoints_RejectWrongMethod(t *testing.T) {
	srv, _, _, _ := newSignServer(t)
	for _, path := range []string{"/api/v1/ssh/sign-user", "/api/v1/ssh/sign-host"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: status = %d, want 405", path, rec.Code)
		}
	}
}

func TestSignUserCert_BodyTooLarge(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)

	// Build a request whose JSON exceeds maxSignRequestBytes by padding
	// principals with one absurdly long entry.
	longPrincipal := strings.Repeat("x", 70*1024)
	rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
		"public_key": subjectAuthKey,
		"key_id":     "k",
		"principals": []string{longPrincipal},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "too large") {
		t.Errorf("error = %q, want 'too large'", msg)
	}
}

// ── invariants ────────────────────────────────────────────────────────────────

// fakeAddr is a minimal net.Addr for driving ssh.CertChecker.CheckHostKey
// without dragging real network setup into the test.
type fakeAddr struct{ s string }

func (a *fakeAddr) Network() string { return "tcp" }
func (a *fakeAddr) String() string  { return a.s }

func TestSignUserCert_SerialIsUnique(t *testing.T) {
	srv, _, subjectAuthKey, _ := newSignServer(t)

	const N = 20
	seen := make(map[uint64]bool, N)
	for i := range N {
		rec := doJSON(t, srv, http.MethodPost, "/api/v1/ssh/sign-user", map[string]any{
			"public_key": subjectAuthKey,
			"key_id":     fmt.Sprintf("k-%d", i),
			"principals": []string{"alice"},
		})
		var resp struct {
			Serial uint64 `json:"serial"`
		}
		decodeJSON(t, rec, &resp)
		if resp.Serial == 0 {
			t.Fatalf("iteration %d: zero serial", i)
		}
		if seen[resp.Serial] {
			t.Fatalf("iteration %d: duplicate serial %d", i, resp.Serial)
		}
		seen[resp.Serial] = true
	}
}
