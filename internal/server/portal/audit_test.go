package portal_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

// stubAuditStore is the read-only portal.AuditStore test double.
type stubAuditStore struct{ events []portal.AuditEvent }

func (s *stubAuditStore) Events() []portal.AuditEvent { return s.events }

// pushCertdEvent marshals a certd audit Entry (Caller / Subject / IP /
// Metadata) onto the mock source.
func pushCertdEvent(t *testing.T, src *mockSource, action, caller, subject, ip string, when time.Time) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"id":          "evt-" + action,
		"action":      action,
		"caller":      caller,
		"subject":     subject,
		"ip":          ip,
		"metadata":    `{"role":"eng-prod"}`,
		"occurred_at": when,
	})
	src.out <- journal.Msg{Seq: 1, Time: when, Data: payload}
}

func TestNewAuditTracker_RequiresSource(t *testing.T) {
	_, err := portal.NewAuditTracker(portal.AuditTrackerConfig{})
	if err == nil || !strings.Contains(err.Error(), "source is required") {
		t.Errorf("err = %v, want source-required", err)
	}
}

func TestAuditTracker_IngestsCertdEvents(t *testing.T) {
	src := newMockSource()
	tracker, err := portal.NewAuditTracker(portal.AuditTrackerConfig{Source: src})
	if err != nil {
		t.Fatalf("NewAuditTracker: %v", err)
	}
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	now := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	pushCertdEvent(t, src, "ssh.user_cert.signed", "alice@example.com", "user:alice", "10.0.0.1", now)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := tracker.Events(); len(events) == 1 {
			e := events[0]
			// certd event: Actor = Caller, Subject = Subject, IP = IP.
			if e.Actor != "alice@example.com" || e.Subject != "user:alice" || e.IP != "10.0.0.1" {
				t.Errorf("certd fields: actor=%q subject=%q ip=%q", e.Actor, e.Subject, e.IP)
			}
			if !strings.Contains(e.Detail, "eng-prod") {
				t.Errorf("certd Detail not preserved: %q", e.Detail)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not ingest the event; got=%v", tracker.Events())
}

func TestAuditTracker_SortsNewestFirst(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Source: src,
	})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	// Push out-of-order timestamps; the tracker should sort them.
	base := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	pushCertdEvent(t, src, "ssh.user_cert.signed", "alice", "s1", "ip", base.Add(2*time.Second))
	pushCertdEvent(t, src, "ssh.host_cert.signed", "alice", "s2", "ip", base)
	pushCertdEvent(t, src, "x509.workload_cert.signed", "alice", "s3", "ip", base.Add(1*time.Second))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := tracker.Events(); len(events) == 3 {
			if !events[0].OccurredAt.After(events[1].OccurredAt) ||
				!events[1].OccurredAt.After(events[2].OccurredAt) {
				t.Errorf("not sorted newest-first: %v %v %v",
					events[0].OccurredAt, events[1].OccurredAt, events[2].OccurredAt)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not ingest 3 events; got=%d", len(tracker.Events()))
}

func TestAuditTracker_BoundedByMaxEvents(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Source:    src,
		MaxEvents: 3,
	})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	base := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	for i := range 6 {
		pushCertdEvent(t, src, "ssh.user_cert.signed", "alice", "s", "ip", base.Add(time.Duration(i)*time.Second))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(tracker.Events()) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(tracker.Events()); got != 3 {
		t.Errorf("Events len = %d, want 3 (bounded)", got)
	}
}

func TestAuditTracker_SkipsMalformedAndIncompleteEvents(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Source: src,
	})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	// 1. Garbage JSON.
	src.out <- journal.Msg{Seq: 1, Time: time.Now(), Data: []byte("{not json")}
	// 2. Missing action (skipped — would render a useless row).
	payload, _ := json.Marshal(map[string]any{
		"id":          "x",
		"caller":      "alice",
		"occurred_at": time.Now(),
	})
	src.out <- journal.Msg{Seq: 2, Time: time.Now(), Data: payload}
	// 3. Valid event.
	pushCertdEvent(t, src, "ssh.user_cert.signed", "alice", "s", "ip", time.Now())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := tracker.Events(); len(got) == 1 && got[0].Action == "ssh.user_cert.signed" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not recover; events=%v", tracker.Events())
}

func TestPortal_AuditIndex_RendersList(t *testing.T) {
	when := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	store := &stubAuditStore{events: []portal.AuditEvent{
		{
			Action:     "ssh.user_cert.signed",
			Actor:      "alice@example.com",
			Subject:    "user:alice",
			IP:         "10.0.0.1",
			OccurredAt: when,
			Detail:     `{"role":"eng-prod"}`,
		},
		{
			Action:     "x509.workload_cert.locked",
			Actor:      "spiffe://tokyo3/authd/agent",
			Subject:    "spiffe://tokyo3/authd/db-app",
			OccurredAt: when.Add(time.Second),
			Detail:     `{"presented_serial":"deadbeef"}`,
		},
	}}
	p, _ := portal.New(portal.Config{Version: "v", AuditStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/audit")
	for _, want := range []string{
		`<h1>Audit</h1>`,
		`<code>ssh.user_cert.signed</code>`,
		`<code>x509.workload_cert.locked</code>`,
		`alice@example.com`,
		`spiffe://tokyo3/authd/db-app`,
		`eng-prod`,         // from the first detail blob
		`presented_serial`, // from the second detail blob
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_AuditIndex_EmptyStore(t *testing.T) {
	p, _ := portal.New(portal.Config{Version: "v", AuditStore: &stubAuditStore{}, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/audit")
	if !strings.Contains(body, "No audit events yet") {
		t.Errorf("expected empty-state:\n%s", body)
	}
}

func TestPortal_AuditIndex_503WhenNoAuditStore(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/audit")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestPortal_Index_FlipsAuditToReadyWhenAuditStoreWired(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version:    "v",
		Now:        func() time.Time { return time.Now() },
		AuditStore: &stubAuditStore{},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/")
	if !strings.Contains(body, `<a href="/audit">Audit</a>`) {
		t.Errorf("Audit entry not clickable when AuditStore is wired:\n%s", body)
	}
}
