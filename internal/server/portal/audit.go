package portal

import (
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// AuditStore is the source for the /audit page. Implementations must
// be safe for concurrent reads — the portal calls Events() on every
// render while the underlying tracker may be appending new entries
// from its subscriber goroutine.
type AuditStore interface {
	Events() []AuditEvent
}

// AuditEvent is the portal's view of one record from certd's ca_audit
// stream — a cert issuance, denial, or revocation event.
type AuditEvent struct {
	// ID is the event's unique identifier (UUID).
	ID string

	// Action is the dotted event name (e.g., "ssh.user_cert.signed",
	// "x509.workload_cert.locked").
	Action string

	// OccurredAt is the producer-side timestamp.
	OccurredAt time.Time

	// Actor is who performed the action (the Caller).
	Actor string

	// Subject is what the action acted on (e.g.,
	// "user:alice@example.com").
	Subject string

	// IP is the originating network address.
	IP string

	// Detail is the action-specific JSON blob (Metadata field).
	// Rendered as a <pre> in the page so operators can read the full
	// payload without an external JetStream tool.
	Detail string
}

// AuditTracker subscribes to certd's audit stream and maintains a
// bounded ring of the latest events, newest first. It wraps the shared
// [journal.Tracker]; construct via [NewAuditTracker] and own the
// subscriber goroutine via [journal.Tracker.Run].
type AuditTracker struct {
	*journal.Tracker[AuditEvent]
}

// AuditTrackerConfig wires a tracker.
type AuditTrackerConfig struct {
	// Source is the journal source to subscribe to. Required.
	Source journal.Source

	// MaxEvents caps the in-memory ring. 0 ⇒ DefaultMaxAuditEvents.
	MaxEvents int

	// Log is the structured logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// DefaultMaxAuditEvents is the recent-events cap. Old entries fall out
// of the buffer when newer ones arrive; the portal surfaces the latest
// activity rather than the full history.
const DefaultMaxAuditEvents = 500

// NewAuditTracker validates cfg and returns a tracker.
func NewAuditTracker(cfg AuditTrackerConfig) (*AuditTracker, error) {
	if cfg.Source == nil {
		return nil, errors.New("source is required")
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = DefaultMaxAuditEvents
	}
	t, err := journal.NewTracker(journal.TrackerConfig[AuditEvent]{
		Source: cfg.Source,
		Decode: decodeAuditEvent,
		Less:   func(a, b AuditEvent) bool { return a.OccurredAt.After(b.OccurredAt) },
		Max:    cfg.MaxEvents,
		Label:  "ca_audit",
		Log:    cfg.Log,
	})
	if err != nil {
		return nil, err
	}
	return &AuditTracker{Tracker: t}, nil
}

// Events returns a snapshot of the current event ring, newest first.
// Safe to call from request handlers while Run is active.
func (t *AuditTracker) Events() []AuditEvent { return t.Snapshot() }

// decodeAuditEvent turns a journal message into an AuditEvent. Returns
// ok=false to skip a record: a decode failure or a payload missing the
// fields needed to render a useful row (no action / zero timestamp).
func decodeAuditEvent(msg journal.Msg) (AuditEvent, bool) {
	var raw struct {
		ID         string    `json:"id"`
		Action     string    `json:"action"`
		OccurredAt time.Time `json:"occurred_at"`
		Caller     string    `json:"caller,omitempty"`
		Subject    string    `json:"subject,omitempty"`
		IP         string    `json:"ip,omitempty"`
		Metadata   string    `json:"metadata,omitempty"`
	}
	if err := json.Unmarshal(msg.Data, &raw); err != nil {
		return AuditEvent{}, false
	}
	if raw.Action == "" || raw.OccurredAt.IsZero() {
		return AuditEvent{}, false
	}
	return AuditEvent{
		ID:         raw.ID,
		Action:     raw.Action,
		OccurredAt: raw.OccurredAt,
		Actor:      raw.Caller,
		Subject:    raw.Subject,
		IP:         raw.IP,
		Detail:     raw.Metadata,
	}, true
}
