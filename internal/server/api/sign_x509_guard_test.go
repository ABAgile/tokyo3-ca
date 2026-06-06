package api_test

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/audit"
	"github.com/abagile/tokyo3-ca/internal/server/api"
	"github.com/abagile/tokyo3-ca/internal/server/oidc"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/x509engine"
	"github.com/abagile/tokyo3-ca/internal/store"
)

var errStoreDown = errors.New("store down")

// fakeActiveCerts is an in-memory store.ActiveCertStore for guard tests.
type fakeActiveCerts struct {
	mu     sync.Mutex
	m      map[string]store.ActiveCert
	getErr error // when set, Get fails (exercises fail-closed)
}

func (f *fakeActiveCerts) Get(id string) (store.ActiveCert, bool, error) {
	if f.getErr != nil {
		return store.ActiveCert{}, false, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ac, ok := f.m[id]
	return ac, ok, nil
}

func (f *fakeActiveCerts) Upsert(ac store.ActiveCert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[ac.Identity] = ac
	return nil
}

func (f *fakeActiveCerts) Delete(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, id)
	return nil
}

func (f *fakeActiveCerts) Lock(id, offendingSerial string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ac := f.m[id]
	ac.LockedAt = time.Now()
	ac.LockedSerial = offendingSerial
	f.m[id] = ac
	return nil
}

func (f *fakeActiveCerts) current(id string) store.ActiveCert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[id]
}

func newGuardedServer(t *testing.T, guard store.ActiveCertStore) (*api.Server, *captureSink) {
	t.Helper()
	caSig, err := signer.NewEphemeralEd25519()
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	caCert, err := x509engine.NewSelfSignedCA(rand.Reader, caSig, "tokyo3-ca-test")
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}
	cap := &captureSink{}
	srv, err := api.New(api.Config{
		Log:            silentLogger(),
		CASigner:       caSig,
		X509IssuerCert: caCert,
		OIDCVerifier:   stubVerifier{claims: &oidc.Claims{Email: "a@x", Groups: []string{"wi"}}},
		Audit:          wrapCaptureSink(cap),
		Policy: policy.NewEngine(policy.NewInMemoryStore(policy.Role{
			Name: "wi", GroupClaim: "wi", SPIFFEPatterns: []string{"spiffe://corp/svc/*"},
		})),
		ActiveCertStore: guard,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return srv, cap
}

func respSerial(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Serial string `json:"serial"`
	}
	decodeJSON(t, rec, &resp)
	return resp.Serial
}

// TestSignX509Workload_AntiTheftGuard walks the rotation/anti-theft state
// machine: first issuance records state; presenting the current serial
// rotates; the one-step-previous serial is still accepted (crash grace); a
// stale/unknown serial — and an empty serial once state exists — is rejected
// as a possible clone with a rollback audit event.
func TestSignX509Workload_AntiTheftGuard(t *testing.T) {
	guard := &fakeActiveCerts{m: map[string]store.ActiveCert{}}
	srv, cap := newGuardedServer(t, guard)
	pub := makeSubjectPubKeyPEM(t)
	const uri = "spiffe://corp/svc/billing"

	sign := func(currentSerial string) *httptest.ResponseRecorder {
		body := map[string]any{"public_key": pub, "spiffe_uri": uri}
		if currentSerial != "" {
			body["current_serial"] = currentSerial
		}
		return postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", body)
	}

	// 1. First issuance: no row, no presented serial → 200, records current.
	r1 := sign("")
	if r1.Code != http.StatusOK {
		t.Fatalf("first issuance: %d %s", r1.Code, r1.Body.String())
	}
	s1 := respSerial(t, r1)
	if got := guard.current(uri).CurrentSerial; got != s1 {
		t.Fatalf("recorded current = %q, want %q", got, s1)
	}

	// 2. Rotation presenting the current serial → 200; current advances,
	//    previous := s1.
	r2 := sign(s1)
	if r2.Code != http.StatusOK {
		t.Fatalf("rotation: %d %s", r2.Code, r2.Body.String())
	}
	s2 := respSerial(t, r2)
	if ac := guard.current(uri); ac.CurrentSerial != s2 || ac.PreviousSerial != s1 {
		t.Fatalf("after rotation: current=%q previous=%q, want %q/%q", ac.CurrentSerial, ac.PreviousSerial, s2, s1)
	}

	// 3. One-step-previous serial still accepted (crash grace) → 200.
	if r3 := sign(s1); r3.Code != http.StatusOK {
		t.Fatalf("previous-serial grace: %d %s", r3.Code, r3.Body.String())
	}
	cur := guard.current(uri).CurrentSerial

	// 4. Stale/unknown serial → 403 + ESCALATION: the identity is locked
	//    (locked_at + offending serial recorded), with a `locked` audit event.
	r4 := sign("999999999")
	if r4.Code != http.StatusForbidden {
		t.Fatalf("stale serial: %d, want 403", r4.Code)
	}
	locked := guard.current(uri)
	if locked.LockedAt.IsZero() || locked.LockedSerial != "999999999" {
		t.Fatalf("identity not locked on clone detection: locked_at=%v locked_serial=%q", locked.LockedAt, locked.LockedSerial)
	}
	if last := cap.entries(t); last[len(last)-1].Action != audit.ActionX509WorkloadCertLocked {
		t.Errorf("last audit = %q, want locked", last[len(last)-1].Action)
	}

	// 5. Once locked, even the *valid* current serial is denied (the lock
	//    halts the workload until an operator intervenes).
	if r5 := sign(cur); r5.Code != http.StatusForbidden {
		t.Fatalf("locked identity should deny a valid serial: %d", r5.Code)
	}

	// 6. Operator clears the record (Delete) → fresh enrollment succeeds.
	if err := guard.Delete(uri); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if r6 := sign(""); r6.Code != http.StatusOK {
		t.Fatalf("re-enroll after clearing lock: %d %s", r6.Code, r6.Body.String())
	}
}

// TestSignX509Workload_LockSurvivesExpiry: a locked identity stays denied even
// after its recorded cert expires — the lock overrides the auto-re-enroll
// path, so a detected clone can't quietly recover by waiting out the TTL.
func TestSignX509Workload_LockSurvivesExpiry(t *testing.T) {
	const uri = "spiffe://corp/svc/billing"
	guard := &fakeActiveCerts{m: map[string]store.ActiveCert{
		uri: {
			Identity: uri, CurrentSerial: "111",
			CurrentNotAfter: time.Now().Add(-time.Hour), // expired
			LockedAt:        time.Now().Add(-time.Minute),
			LockedSerial:    "999999999",
		},
	}}
	srv, cap := newGuardedServer(t, guard)
	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": makeSubjectPubKeyPEM(t),
		"spiffe_uri": uri, // empty current_serial would normally re-enroll once expired
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("locked+expired should deny (no auto-re-enroll): %d", rec.Code)
	}
	if got := guard.current(uri).CurrentSerial; got != "111" {
		t.Errorf("locked identity re-enrolled despite lock: current=%q", got)
	}
	var sawLocked bool
	for _, e := range cap.entries(t) {
		if e.Action == audit.ActionX509WorkloadCertLocked {
			sawLocked = true
		}
	}
	if !sawLocked {
		t.Error("no locked audit event emitted for the already-locked denial")
	}
}

// TestSignX509Workload_ReenrollAfterExpiry: once the recorded cert has
// expired, a renewal that can't present a matching serial (e.g. an agent
// that lost its cert and sends empty) is allowed to re-enroll — no valid
// credential is in the wild, so the anti-theft layer is moot — and the
// state resets to the new serial with a reenroll audit event.
func TestSignX509Workload_ReenrollAfterExpiry(t *testing.T) {
	const uri = "spiffe://corp/svc/billing"
	guard := &fakeActiveCerts{m: map[string]store.ActiveCert{
		uri: {Identity: uri, CurrentSerial: "111", CurrentNotAfter: time.Now().Add(-time.Hour)},
	}}
	srv, cap := newGuardedServer(t, guard)

	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": makeSubjectPubKeyPEM(t),
		"spiffe_uri": uri,
		// no current_serial: the agent lost its cert
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-enroll after expiry: %d %s", rec.Code, rec.Body.String())
	}
	if got := guard.current(uri).CurrentSerial; got == "111" {
		t.Errorf("state not advanced on re-enroll: current=%q", got)
	}
	if got := guard.current(uri).PreviousSerial; got != "" {
		t.Errorf("previous not reset on re-enroll: %q", got)
	}
	var sawReenroll bool
	for _, e := range cap.entries(t) {
		if e.Action == audit.ActionX509WorkloadCertReenroll {
			sawReenroll = true
		}
	}
	if !sawReenroll {
		t.Error("no reenroll audit event emitted")
	}
}

// TestSignX509Workload_GuardFailsClosed: a store error on Get denies
// issuance (503) rather than minting unguarded.
func TestSignX509Workload_GuardFailsClosed(t *testing.T) {
	guard := &fakeActiveCerts{m: map[string]store.ActiveCert{}, getErr: errStoreDown}
	srv, _ := newGuardedServer(t, guard)
	rec := postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", map[string]any{
		"public_key": makeSubjectPubKeyPEM(t),
		"spiffe_uri": "spiffe://corp/svc/billing",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
