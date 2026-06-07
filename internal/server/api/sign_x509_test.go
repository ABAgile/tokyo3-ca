package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
)

// newX509Server builds a Server wired for X.509 issuance: a CA signer,
// a self-signed CA cert, and an audit capture sink so tests can also
// assert on emission. Returns the server, sink, subject PEM pubkey,
// and the CA cert (for cert-chain verification).
func newX509Server(t *testing.T, ver oidc.TokenVerifier, roles ...policy.Role) (*api.Server, *captureSink, string, *x509.Certificate) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	caCert, err := x509engine.NewSelfSignedCA(rand.Reader, caSig, "tokyo3-ca-test")
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}

	pubPEM := makeSubjectPubKeyPEM(t)

	cap := &captureSink{}
	sink := wrapCaptureSink(cap)

	cfg := api.Config{
		Log:            silentLogger(),
		CASigner:       caSig,
		X509IssuerCert: caCert,
		OIDCVerifier:   ver,
		Audit:          sink,
	}
	if len(roles) > 0 {
		cfg.Policy = policy.NewEngine(policy.NewInMemoryStore(roles...))
	}
	srv, err := api.New(cfg)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return srv, cap, pubPEM, caCert
}

// makeSubjectPubKeyPEM returns a fresh Ed25519 public key encoded as a
// PEM SubjectPublicKeyInfo block — the format the sign endpoint expects.
func makeSubjectPubKeyPEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// wrapCaptureSink wraps a captureSink in journal.NewJSONSink[Entry]
// to produce an audit.Sink the API layer can publish through.
func wrapCaptureSink(c *captureSink) audit.Sink {
	return journal.NewJSONSink[audit.Entry](c)
}

// TestSignX509Workload_RefusesNearExpiryIssuer verifies issuance is refused
// (503) when the issuer cert is within one max-TTL of its own expiry — the
// guard that stops certd minting leaves that would outlive a soon-to-expire
// intermediate.
func TestSignX509Workload_RefusesNearExpiryIssuer(t *testing.T) {
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	// Self-sign a CA cert expiring in 1h — inside the 24h max-TTL window.
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "near-expiry-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caSig.Public(), caSig)
	if err != nil {
		t.Fatalf("create near-expiry CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse near-expiry CA: %v", err)
	}

	cap := &captureSink{}
	srv, err := api.New(api.Config{
		Log:            silentLogger(),
		CASigner:       caSig,
		X509IssuerCert: caCert,
		OIDCVerifier:   stubVerifier{claims: &oidc.Claims{Email: "a@example.com", Groups: []string{"g"}}},
		Audit:          wrapCaptureSink(cap),
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": makeSubjectPubKeyPEM(t),
		"spiffe_uri": "spiffe://corp/svc/billing",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "near expiry") {
		t.Errorf("body = %q, want 'near expiry'", rec.Body.String())
	}
}

// ── happy paths ──────────────────────────────────────────────────────────────

func TestSignX509Workload_HappyPath(t *testing.T) {
	srv, cap, pubPEM, caCert := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Email: "alice@example.com", Groups: []string{"workload-issuer"}}},
		policy.Role{
			Name: "workload-issuer", GroupClaim: "workload-issuer",
			SPIFFEPatterns:        []string{"spiffe://corp/svc/*"},
			MaxX509CertTTLSeconds: int64((4 * time.Hour).Seconds()),
		},
	)

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": pubPEM,
		"spiffe_uri": "spiffe://corp/svc/billing",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Certificate string    `json:"certificate"`
		Serial      string    `json:"serial"`
		SPIFFEURI   string    `json:"spiffe_uri"`
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)

	if resp.SPIFFEURI != "spiffe://corp/svc/billing" {
		t.Errorf("spiffe_uri = %q", resp.SPIFFEURI)
	}
	if resp.Serial == "" {
		t.Error("serial empty")
	}
	// Default TTL is 1h; role caps at 4h. Defaults pick 1h.
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != time.Hour {
		t.Errorf("TTL = %s, want 1h", got)
	}

	// Returned cert PEM parses and validates against the CA.
	block, _ := pem.Decode([]byte(resp.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("returned cert is not a CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse returned cert: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://corp/svc/billing" {
		t.Errorf("URIs = %v", cert.URIs)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("cert does not verify against CA: %v", err)
	}

	// Audit emitted.
	entries := cap.entries(t)
	if len(entries) != 1 || entries[0].Action != audit.ActionX509WorkloadCertSigned {
		t.Errorf("audit entries = %v, want one x509.workload_cert.signed", entries)
	}
}

func TestSignX509Workload_TTLCappedByPolicy(t *testing.T) {
	srv, _, pubPEM, _ := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Email: "alice@example.com", Groups: []string{"workload-issuer"}}},
		policy.Role{
			Name: "workload-issuer", GroupClaim: "workload-issuer",
			SPIFFEPatterns:        []string{"spiffe://corp/svc/*"},
			MaxX509CertTTLSeconds: int64((30 * time.Minute).Seconds()), // tight cap
		},
	)

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key":  pubPEM,
		"spiffe_uri":  "spiffe://corp/svc/billing",
		"ttl_seconds": int64(12 * 60 * 60), // 12h requested → 30m granted
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	decodeJSON(t, rec, &resp)
	if got := resp.ValidBefore.Sub(resp.ValidAfter); got != 30*time.Minute {
		t.Errorf("TTL = %s, want 30m (capped)", got)
	}
}

// ── error paths ──────────────────────────────────────────────────────────────

func TestSignX509Workload_NoX509Config_503(t *testing.T) {
	// Server constructed without X509IssuerCert — endpoint should
	// refuse with 503 (not 200, not 500).
	caSig, _ := signer.NewEphemeralEd25519()
	srv, err := api.New(api.Config{
		Log:      silentLogger(),
		CASigner: caSig,
		// X509IssuerCert intentionally omitted
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "", map[string]any{
		"public_key": "stub",
		"spiffe_uri": "spiffe://corp/svc/x",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "x509 issuance") {
		t.Errorf("error = %q, want to mention x509 issuance", msg)
	}
}

func TestSignX509Workload_RejectsBadPubKey(t *testing.T) {
	srv, _, _, _ := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"w"}}},
		policy.Role{Name: "w", GroupClaim: "w", SPIFFEPatterns: []string{"spiffe://corp/*"}},
	)

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": "not a PEM",
		"spiffe_uri": "spiffe://corp/x",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSignX509Workload_RejectsEmptySpiffeURI(t *testing.T) {
	srv, _, pubPEM, _ := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"w"}}},
		policy.Role{Name: "w", GroupClaim: "w", SPIFFEPatterns: []string{"spiffe://corp/*"}},
	)

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": pubPEM,
		"spiffe_uri": "",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "spiffe_uri") {
		t.Errorf("error = %q, want to mention spiffe_uri", msg)
	}
}

func TestSignX509Workload_RejectsTTLOverMax(t *testing.T) {
	srv, _, pubPEM, _ := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"w"}}},
		policy.Role{Name: "w", GroupClaim: "w", SPIFFEPatterns: []string{"spiffe://corp/*"}},
	)

	// 48h is over the 24h endpoint max → 400.
	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key":  pubPEM,
		"spiffe_uri":  "spiffe://corp/svc/x",
		"ttl_seconds": int64(48 * 60 * 60),
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSignX509Workload_PolicyDenialEmitsDeniedEvent(t *testing.T) {
	srv, cap, pubPEM, _ := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Email: "alice@example.com", Groups: []string{"workload-issuer"}}},
		policy.Role{
			Name: "workload-issuer", GroupClaim: "workload-issuer",
			SPIFFEPatterns: []string{"spiffe://corp/svc/billing"},
		},
	)

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": pubPEM,
		"spiffe_uri": "spiffe://corp/svc/admin", // not in allowed patterns
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	entries := cap.entries(t)
	if len(entries) != 1 || entries[0].Action != audit.ActionX509WorkloadCertDenied {
		t.Errorf("audit entries = %v, want one x509.workload_cert.denied", entries)
	}
	if entries[0].Caller != "oidc:alice@example.com" {
		t.Errorf("Caller = %q", entries[0].Caller)
	}
}

func TestSignX509Workload_RejectsWrongScheme(t *testing.T) {
	// Pattern is an exact literal match for the request URI, so
	// policy approves and the request flows into the engine — which
	// must reject the non-spiffe scheme.
	srv, _, pubPEM, _ := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"w"}}},
		policy.Role{Name: "w", GroupClaim: "w", SPIFFEPatterns: []string{"https://example.com/x"}},
	)

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": pubPEM,
		"spiffe_uri": "https://example.com/x",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if msg := errorBody(t, rec); !strings.Contains(msg, "spiffe") {
		t.Errorf("error = %q, want to mention spiffe scheme", msg)
	}
}

func TestSignX509Workload_RejectsWrongMethod(t *testing.T) {
	srv, _, _, _ := newX509Server(t,
		stubVerifier{claims: &oidc.Claims{Groups: []string{"w"}}},
		policy.Role{Name: "w", GroupClaim: "w", SPIFFEPatterns: []string{"spiffe://corp/*"}},
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/x509/sign-workload", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/v1/x509/sign-workload: status = %d, want 405", rec.Code)
	}
}
