package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/store"
)

// TestSignX509Workload_AdoptCollapsesGrace: once a workload acks adoption of
// its current cert, certd drops the one-step grace — so re-presenting the
// (now-collapsed) previous serial is treated as a clone and locks the
// identity, rather than being accepted for another cycle.
func TestSignX509Workload_AdoptCollapsesGrace(t *testing.T) {
	guard := &fakeActiveCerts{m: map[string]store.ActiveCert{}}
	srv, _ := newGuardedServer(t, guard)
	pub := makeSubjectPubKeyPEM(t)
	const uri = "spiffe://corp/svc/billing"

	sign := func(serial string) *httptest.ResponseRecorder {
		body := map[string]any{"public_key": pub, "spiffe_uri": uri}
		if serial != "" {
			body["current_serial"] = serial
		}
		return postJSON(srv, "/api/v1/x509/sign-workload", "Bearer x", body)
	}
	adoptCall := func(serial string) *httptest.ResponseRecorder {
		return postJSON(srv, "/api/v1/x509/adopt", "Bearer x",
			map[string]any{"spiffe_uri": uri, "serial": serial})
	}

	s1 := respSerial(t, sign("")) // first issuance → current=s1
	s2 := respSerial(t, sign(s1)) // rotate → current=s2, previous=s1

	// A non-current serial adopts nothing (previous grace intact).
	var nope struct {
		Adopted bool `json:"adopted"`
	}
	decodeJSON(t, adoptCall("not-a-serial"), &nope)
	if nope.Adopted {
		t.Fatal("adopt reported success for a non-current serial")
	}
	if guard.current(uri).PreviousSerial != s1 {
		t.Fatalf("grace collapsed by a non-current adopt: previous=%q", guard.current(uri).PreviousSerial)
	}

	// Ack the current serial → previous collapses.
	var ok struct {
		Adopted bool `json:"adopted"`
	}
	decodeJSON(t, adoptCall(s2), &ok)
	if !ok.Adopted {
		t.Fatal("adopt of the current serial reported not-adopted")
	}
	if p := guard.current(uri).PreviousSerial; p != "" {
		t.Fatalf("previous not collapsed after adopt: %q", p)
	}

	// Re-presenting the rotated-from serial is now a clone → lock.
	if rec := sign(s1); rec.Code != http.StatusForbidden {
		t.Fatalf("post-adopt previous serial: %d, want 403", rec.Code)
	}
	if guard.current(uri).LockedAt.IsZero() {
		t.Error("identity not locked after presenting the collapsed previous serial")
	}
}
