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

// pushCertdEvent marshals a certd-shaped audit Entry onto the mock
// source. Tests use this to confirm the tracker handles the certd
// schema (Caller / Subject / IP fields, no SessionID).
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

// pushSshProxyEvent marshals an ssh-proxy-shaped audit Entry onto the
// mock source. Different field names (User / Target / ClientIP) so
// the tracker has to pick them up off the union schema.
func pushSshProxyEvent(t *testing.T, src *mockSource, action, user, target, clientIP, sessionID string, when time.Time) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"id":          "evt-" + action,
		"action":      action,
		"user":        user,
		"target":      target,
		"client_ip":   clientIP,
		"session_id":  sessionID,
		"occurred_at": when,
	})
	src.out <- journal.Msg{Seq: 1, Time: when, Data: payload}
}

func TestNewAuditTracker_RequiresSources(t *testing.T) {
	_, err := portal.NewAuditTracker(portal.AuditTrackerConfig{})
	if err == nil || !strings.Contains(err.Error(), "at least one source") {
		t.Errorf("err = %v, want source-required", err)
	}
}

func TestNewAuditTracker_RejectsEmptyLabel(t *testing.T) {
	_, err := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Sources: []portal.AuditSource{{Source: newMockSource(), Label: ""}},
	})
	if err == nil || !strings.Contains(err.Error(), "empty Label") {
		t.Errorf("err = %v, want empty-label rejection", err)
	}
}

func TestAuditTracker_IngestsCertdAndSshProxyShapes(t *testing.T) {
	certdSrc := newMockSource()
	sshSrc := newMockSource()
	tracker, err := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Sources: []portal.AuditSource{
			{Source: certdSrc, Label: "certd"},
			{Source: sshSrc, Label: "ssh-proxy"},
		},
	})
	if err != nil {
		t.Fatalf("NewAuditTracker: %v", err)
	}
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	now := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	pushCertdEvent(t, certdSrc, "ssh.user_cert.signed", "alice@example.com", "user:alice", "10.0.0.1", now)
	pushSshProxyEvent(t, sshSrc, "ssh.session.opened", "user:alice", "db-1.prod:22", "10.0.0.1", "sess-abc", now.Add(time.Second))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := tracker.Events(); len(events) == 2 {
			// Newest-first across both sources.
			if events[0].Action != "ssh.session.opened" {
				t.Errorf("newest action = %q, want ssh.session.opened (ssh-proxy is +1s)", events[0].Action)
			}
			// ssh-proxy event normalized: Actor = User, Subject = Target, IP = ClientIP.
			if events[0].Actor != "user:alice" || events[0].Subject != "db-1.prod:22" || events[0].IP != "10.0.0.1" {
				t.Errorf("ssh-proxy normalization: actor=%q subject=%q ip=%q",
					events[0].Actor, events[0].Subject, events[0].IP)
			}
			if events[0].SessionID != "sess-abc" {
				t.Errorf("SessionID = %q", events[0].SessionID)
			}
			if events[0].Source != "ssh-proxy" {
				t.Errorf("Source = %q, want ssh-proxy", events[0].Source)
			}
			// certd event normalized: Actor = Caller, Subject = Subject, IP = IP.
			if events[1].Actor != "alice@example.com" || events[1].Subject != "user:alice" {
				t.Errorf("certd normalization: actor=%q subject=%q",
					events[1].Actor, events[1].Subject)
			}
			if events[1].Source != "certd" {
				t.Errorf("Source = %q, want certd", events[1].Source)
			}
			if !strings.Contains(events[1].Detail, "eng-prod") {
				t.Errorf("certd Detail not preserved: %q", events[1].Detail)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not ingest 2 events; got=%v", tracker.Events())
}

func TestAuditTracker_SortsNewestFirst(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Sources: []portal.AuditSource{{Source: src, Label: "certd"}},
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
		Sources:   []portal.AuditSource{{Source: src, Label: "certd"}},
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
		Sources: []portal.AuditSource{{Source: src, Label: "certd"}},
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
			Source:     "certd",
			Action:     "ssh.user_cert.signed",
			Actor:      "alice@example.com",
			Subject:    "user:alice",
			IP:         "10.0.0.1",
			OccurredAt: when,
			Detail:     `{"role":"eng-prod"}`,
		},
		{
			Source:     "ssh-proxy",
			Action:     "ssh.channel.rejected",
			Actor:      "user:bob",
			Subject:    "db-1:22",
			OccurredAt: when.Add(time.Second),
			Reason:     "policy denied principal 'bob' for db-1",
		},
	}}
	p, _ := portal.New(portal.Config{Version: "v", AuditStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/audit")
	for _, want := range []string{
		`<h1>Audit</h1>`,
		`<code>certd</code>`,
		`<code>ssh-proxy</code>`,
		`<code>ssh.user_cert.signed</code>`,
		`<code>ssh.channel.rejected</code>`,
		`alice@example.com`,
		`db-1:22`,
		`policy denied principal`,
		`eng-prod`, // from the certd detail blob
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
