// Package audit defines the audit event types for certd.
//
// Write path (certd serve):
//
//	Handler → journal.EncodedSink[Entry].Append → JetStream "ca_audit"
//	                                              stream (authoritative store)
//
// Read paths (both off the same stream):
//
//	/portal/admin/audit/sse → journal/sse.Handler → live tail in browser
//	certd audit query       → journal/jetstream.Source → terminal output
//
// The JetStream stream is the tamper-resistant authoritative record
// (DenyDelete, DenyPurge, FileStorage, ~13-month retention); there is no
// separate projection database. Querying back is a thin reader on top of
// journal.Source — the same primitive both UI and CLI use.
//
// The Entry → JSON adapter and JetStream transport are provided by
// base/journal: certd wires `journal.NewJSONSink[Entry](jetstreamInner)`
// and handlers call Append directly. The audit package owns only the
// Entry shape and wire-config constants (Subject / StreamName /
// StreamMaxAge); transport and marshalling are not its concerns.
package audit

import (
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// Wire-format constants for the audit journal. Subject is what certd
// publishes to; StreamName is the JetStream stream covering it.
// StreamMaxAge is the retention floor: PCI-DSS 10.5 requires 12 months;
// 13 months gives a comfortable roll-over buffer.
const (
	Subject      = "ca.audit.events"
	StreamName   = "ca_audit"
	StreamMaxAge = 400 * 24 * time.Hour
)

// Action names for [Entry.Action]. Dotted lowercase, suffix is one of
// .signed (successful issuance) or .denied (policy rejection after
// auth succeeded). Auth failures (401) are deliberately not audited —
// they happen before a caller identity is established, so attributing
// them is impossible.
const (
	ActionSSHUserCertSigned      = "ssh.user_cert.signed"
	ActionSSHHostCertSigned      = "ssh.host_cert.signed"
	ActionSSHUserCertDenied      = "ssh.user_cert.denied"
	ActionSSHHostCertDenied      = "ssh.host_cert.denied"
	ActionX509WorkloadCertSigned = "x509.workload_cert.signed"
	ActionX509WorkloadCertDenied = "x509.workload_cert.denied"
	// ActionX509WorkloadCertRollback flags a renewal that presented a
	// serial outside the {current, previous} window for its identity — a
	// superseded/unknown cert reappearing, i.e. a possible key-pair theft
	// (the renewal/anti-theft guard). High-signal: alert on it.
	ActionX509WorkloadCertRollback = "x509.workload_cert.rollback_rejected"
	// ActionX509WorkloadCertReenroll flags issuance that bypassed the
	// active-cert serial check because the prior recorded cert had already
	// expired (no valid credential in the wild ⇒ the anti-theft layer is
	// moot). Expected after an agent is down longer than a cert TTL;
	// worth surfacing in case it signals lost agent state.
	ActionX509WorkloadCertReenroll = "x509.workload_cert.reenroll"
	ActionSSHCertRevoked           = "ssh.cert.revoked"
)

// Caller-identity prefix scheme used in [Entry.Caller]:
//
//	oidc:<email>       OIDC bearer-token path; email when present, sub otherwise.
//	mtls:<name>        mTLS client-cert path; principal Name when set, SAN otherwise.
//	anonymous          Body-groups fallback (no auth wired; tests / pre-prod only).
const (
	CallerPrefixOIDC = "oidc:"
	CallerPrefixMTLS = "mtls:"
	CallerAnonymous  = "anonymous"
)

// Sink is the typed JSON-encoding journal sink used to publish Entries.
// Construct with journal.NewJSONSink[Entry](innerSink); the alias is an
// ergonomic shortcut, not a distinct type.
type Sink = *journal.EncodedSink[Entry]

// NoopSink discards every event. Used in tests and dev environments
// where the audit journal is not configured. Safe for concurrent use.
var NoopSink Sink = journal.NewJSONSink[Entry](journal.NoopSink{})

// Entry is one audit event in canonical form. Serialised as JSON and
// stored verbatim in JetStream.
//
// Action is the dotted event name (e.g., "ssh.user_cert.signed",
// "ssh.host_cert.signed", "policy.role.created"). Subject identifies
// the principal the cert was issued to / the policy applies to —
// formatted as "user:<oidc-sub>", "host:<fqdn>", or "workload:<spiffe-uri>".
// Caller identifies who initiated the action — same format. Serial is
// the issued cert serial when relevant; empty otherwise. Metadata is a
// pre-serialised JSON object holding action-specific detail (principals,
// TTL, KeyID, etc.).
type Entry struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	Subject    string    `json:"subject,omitempty"`
	Caller     string    `json:"caller,omitempty"`
	Serial     uint64    `json:"serial,omitempty"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Metadata   string    `json:"metadata,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}
