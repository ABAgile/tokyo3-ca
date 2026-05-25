package portal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// AuditStore is the source for the /audit page. Implementations must
// be safe for concurrent reads — the portal calls Events() on every
// render while the underlying tracker may be appending new entries
// from its subscriber goroutines.
type AuditStore interface {
	Events() []AuditEvent
}

// AuditEvent is the portal's normalized view of one audit record.
// Both ssh-proxy's audit.Entry (session lifecycle, recording events)
// and certd's audit.Entry (cert issuance/denial) collapse onto these
// fields — whichever JSON tags are present in the payload populate
// the corresponding fields.
type AuditEvent struct {
	// Source labels which stream produced the event so the portal
	// can render a per-source badge ("certd" or "ssh-proxy"). Set by
	// [AuditTracker] at ingest based on the [AuditSource] config.
	Source string

	// ID is the event's unique identifier (UUID). Same field name in
	// both producer schemas.
	ID string

	// Action is the dotted event name (e.g.,
	// "ssh.user_cert.signed", "ssh.session.opened").
	Action string

	// OccurredAt is the producer-side timestamp.
	OccurredAt time.Time

	// Actor is who performed the action — Caller (certd) or User
	// (ssh-proxy). Either-or; whichever the payload populated wins.
	Actor string

	// Subject is what the action acted on — Subject (certd, e.g.,
	// "user:alice@example.com") or Target (ssh-proxy, e.g.,
	// "db-1.prod:22"). Either-or.
	Subject string

	// IP is the originating network address — IP (certd) or
	// ClientIP (ssh-proxy). Either-or.
	IP string

	// SessionID is set only on ssh-proxy events that participate in
	// a session lifecycle. Empty on certd events.
	SessionID string

	// Reason is set on denial events with the policy explanation.
	Reason string

	// Detail is the action-specific JSON blob (Metadata field on
	// both producers). Rendered as a <pre> in the page so operators
	// can read the full payload without an external JetStream tool.
	Detail string
}

// AuditSource pairs a [journal.Source] with a human label so the
// tracker can stamp every ingested event with its origin. Operators
// see "ssh-proxy" vs "certd" in the page.
type AuditSource struct {
	Source journal.Source
	Label  string
}

// AuditTracker subscribes to N audit streams concurrently and
// maintains a single bounded ring of the latest events across all of
// them. Construct via [NewAuditTracker]; the subscriber goroutines
// are owned by [AuditTracker.Run] — call once after construction.
type AuditTracker struct {
	sources []AuditSource
	max     int
	log     *slog.Logger

	mu     sync.RWMutex
	events []AuditEvent // newest first across all sources
}

// AuditTrackerConfig wires a tracker.
type AuditTrackerConfig struct {
	// Sources are the journal sources to subscribe to. At least one
	// is required.
	Sources []AuditSource

	// MaxEvents caps the in-memory ring. 0 ⇒ DefaultMaxAuditEvents.
	MaxEvents int

	// Log is the structured logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// DefaultMaxAuditEvents is the per-tracker recent-events cap. Old
// entries fall out of the buffer when newer ones arrive; the portal
// surfaces the latest activity rather than the full history.
const DefaultMaxAuditEvents = 500

// NewAuditTracker validates cfg and returns a tracker.
func NewAuditTracker(cfg AuditTrackerConfig) (*AuditTracker, error) {
	if len(cfg.Sources) == 0 {
		return nil, errors.New("at least one source is required")
	}
	for i, s := range cfg.Sources {
		if s.Source == nil {
			return nil, errors.New("audit source has nil Source")
		}
		if s.Label == "" {
			return nil, errors.New("audit source has empty Label")
		}
		_ = i
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = DefaultMaxAuditEvents
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &AuditTracker{
		sources: cfg.Sources,
		max:     cfg.MaxEvents,
		log:     cfg.Log,
	}, nil
}

// Run starts one subscriber goroutine per source and ingests until
// ctx cancels or every source's channel closes. Returns the first
// non-nil error any source's [journal.Source.Subscribe] surfaces;
// per-message decode failures are logged at debug and ignored.
func (t *AuditTracker) Run(ctx context.Context) error {
	errCh := make(chan error, len(t.sources))
	var wg sync.WaitGroup
	for _, src := range t.sources {
		wg.Add(1)
		go func(src AuditSource) {
			defer wg.Done()
			errCh <- t.runOne(ctx, src)
		}(src)
	}
	wg.Wait()
	close(errCh)
	var firstErr error
	for err := range errCh {
		if err != nil && !errors.Is(err, context.Canceled) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *AuditTracker) runOne(ctx context.Context, src AuditSource) error {
	ch, err := src.Source.Subscribe(ctx, t.max, 0)
	if err != nil {
		return err
	}
	t.log.Info("audit tracker subscribed", "source", src.Label, "replay", t.max)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			t.ingest(src.Label, msg)
		}
	}
}

// Events returns a snapshot of the current event ring, newest first
// across every wired source. Safe to call from request handlers
// while Run is active.
func (t *AuditTracker) Events() []AuditEvent {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]AuditEvent, len(t.events))
	copy(out, t.events)
	return out
}

// ingest decodes one journal message into an AuditEvent, tags it
// with sourceLabel, and inserts into the ring. The ring stays sorted
// newest-first by OccurredAt — a re-sort is cheap at len ≤ MaxEvents.
func (t *AuditTracker) ingest(sourceLabel string, msg journal.Msg) {
	// Schema is the union of certd and ssh-proxy fields. JSON
	// decoding silently ignores tags that aren't in the payload, so
	// the same struct handles both producers.
	var raw struct {
		ID         string    `json:"id"`
		Action     string    `json:"action"`
		OccurredAt time.Time `json:"occurred_at"`

		// ssh-proxy fields.
		User      string `json:"user,omitempty"`
		Target    string `json:"target,omitempty"`
		ClientIP  string `json:"client_ip,omitempty"`
		SessionID string `json:"session_id,omitempty"`
		Reason    string `json:"reason,omitempty"`

		// certd fields.
		Caller  string `json:"caller,omitempty"`
		Subject string `json:"subject,omitempty"`
		IP      string `json:"ip,omitempty"`

		Metadata string `json:"metadata,omitempty"`
	}
	if err := json.Unmarshal(msg.Data, &raw); err != nil {
		t.log.Debug("audit tracker: decode failed", "source", sourceLabel, "seq", msg.Seq, "err", err)
		return
	}
	if raw.Action == "" || raw.OccurredAt.IsZero() {
		// Malformed in a less obvious way — skip rather than render
		// a row with no useful content.
		return
	}

	ev := AuditEvent{
		Source:     sourceLabel,
		ID:         raw.ID,
		Action:     raw.Action,
		OccurredAt: raw.OccurredAt,
		Actor:      firstNonEmpty(raw.Caller, raw.User),
		Subject:    firstNonEmpty(raw.Subject, raw.Target),
		IP:         firstNonEmpty(raw.IP, raw.ClientIP),
		SessionID:  raw.SessionID,
		Reason:     raw.Reason,
		Detail:     raw.Metadata,
	}

	t.mu.Lock()
	t.events = append(t.events, ev)
	// Sort newest-first. The ring is small (≤ MaxEvents) and growth
	// is one-per-message, so sort.Slice is plenty.
	sort.Slice(t.events, func(i, j int) bool {
		return t.events[i].OccurredAt.After(t.events[j].OccurredAt)
	})
	if len(t.events) > t.max {
		t.events = t.events[:t.max]
	}
	t.mu.Unlock()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
