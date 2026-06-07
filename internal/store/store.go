// Package store defines certd's persistent-store interfaces plus the
// shared row-mapping helpers its backends reuse. Two backends implement
// these, mirroring the layout of tokyo3-auth's internal/store:
//
//   - postgres/ — production backend (pgx/v5)
//   - sqlite/   — dev + test backend (pure-Go modernc.org/sqlite)
//
// Both expose the composite [Store] (role + principal + revocation tables
// behind ONE connection — required so SQLite, which has a single handle and
// per-connection ":memory:" databases, works). The engine is a deploy-time
// choice. See certd-store-design.md for the engine rationale and the
// renewal/anti-theft protocol the active-cert table will back.
//
// Invariant: these stores never hold private key material — the CA signing
// key lives in CERTD_CA_KEY_FILE / KMS, and issued leaf keys never reach
// certd. This package holds policy + registries + revocation + active-cert
// state only.
package store

import (
	"database/sql"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/server/policy"
)

// Store is the composite a backend exposes: accessors for each table store
// (all sharing the one connection), plus Close. Accessors rather than
// embedding because [policy.Store] and [mtls.Store] both declare All() with
// different return types — a single type can't satisfy both, so each table
// gets its own sub-store value.
type Store interface {
	Roles() RoleStore
	Principals() PrincipalStore
	Revocations() RevocationStore
	ActiveCerts() ActiveCertStore
	io.Closer
}

// Owner-marker values for the row `source` column, passed to the Add/Replace
// mutation methods. SourceConfig rows are managed by `certd reconcile`
// (config-authoritative: added, updated, and pruned to match the files);
// SourcePortal rows are created in the admin portal and never pruned.
const (
	SourceConfig = "config"
	SourcePortal = "portal"
)

// NormalizeSource maps an empty source to [SourceConfig] — the default for
// cold-start seeding and any caller that doesn't set one. Reconcile and the
// portal always pass an explicit value.
func NormalizeSource(s string) string {
	if s == "" {
		return SourceConfig
	}
	return s
}

// RoleStore is the persistent backend for the role table. It satisfies
// [policy.Store] (the sign-time read surface) plus the audited admin write
// surface, plus SeedRolesIfEmpty for cold-start seeding from CERTD_ROLES_FILE.
// Reads fail closed in the backends.
type RoleStore interface {
	policy.Store // RolesForGroups(groups) []Role; All() []Role
	ByName(name string) (policy.Role, bool)
	// Add and Replace stamp the row's owner-marker source (SourceConfig /
	// SourcePortal). Delete needs none — it writes no row.
	Add(role policy.Role, source string) error
	Replace(oldName string, newRole policy.Role, source string) error
	Delete(name string) error
	// AllWithSource returns every role paired with its owner-marker source —
	// the read `certd reconcile` diffs against (it only prunes/updates
	// SourceConfig rows). Returns an error (not a swallowed nil) so reconcile
	// fails closed on a query failure rather than pruning on a partial read.
	AllWithSource() ([]RoleRecord, error)
	// SeedRolesIfEmpty inserts roles only when the table is empty,
	// returning true when it seeded. Distinct name from the principal
	// seed so both can live on one composite Store.
	SeedRolesIfEmpty(roles []policy.Role) (bool, error)
}

// PrincipalStore is the persistent backend for the mTLS cert-principal
// registry. It satisfies [mtls.Store] (Lookup/All), the audited write surface
// (keyed by SAN), and a cold-start seed.
type PrincipalStore interface {
	mtls.Store // Lookup(sans) (*Principal, error); All() []Principal
	BySAN(san string) (mtls.Principal, bool)
	Add(p mtls.Principal, source string) error
	Replace(oldSAN string, p mtls.Principal, source string) error
	Delete(san string) error
	// AllWithSource mirrors [RoleStore.AllWithSource] for principals.
	AllWithSource() ([]PrincipalRecord, error)
	SeedPrincipalsIfEmpty(principals []mtls.Principal) (bool, error)
}

// RoleRecord pairs a role with its owner-marker source. PrincipalRecord does
// the same for a principal. Both are the reconcile read shape.
type RoleRecord struct {
	Role   policy.Role
	Source string
}

// PrincipalRecord pairs a principal with its owner-marker source.
type PrincipalRecord struct {
	Principal mtls.Principal
	Source    string
}

// RevocationStore is the persistent backend for the SSH KRL. It satisfies
// [krl.Store] (Revoke/Snapshot/IsRevoked) plus MarshalSpec so the
// /api/v1/ssh/krl.spec endpoint works against the DB backend too.
type RevocationStore interface {
	krl.Store // Revoke; Snapshot; IsRevoked
	MarshalSpec() string
}

// ActiveCert is the per-identity X.509 workload-cert rotation state that
// backs the renewal/anti-theft guard (see certd-store-design.md): the
// currently-valid serial plus a one-step grace (previous) covering the
// crash/rotation window. Serials are decimal big-int strings (X.509 serials
// exceed uint64). PreviousSerial == "" means the state has collapsed to a
// single live serial.
type ActiveCert struct {
	Identity         string // SPIFFE URI
	CurrentSerial    string
	CurrentNotAfter  time.Time
	PreviousSerial   string
	PreviousNotAfter time.Time
	// LockedAt is non-zero once the identity has been locked by the
	// reuse-detection escalation (a serial mismatch while the recorded cert
	// was still valid — a possible clone). While locked, every sign request
	// for the identity is denied — including past expiry, so the auto-
	// re-enroll path does NOT fire — until an operator clears the row.
	LockedAt time.Time
	// LockedSerial is the offending serial that triggered the lock (the
	// serial the suspected clone presented), kept for forensics.
	LockedSerial string
}

// ActiveCertStore persists [ActiveCert] rows. The equality guard + reuse
// detection live in the X.509 sign path; this is the data layer it reads
// and writes. Get returns an error (not a swallowed miss) so the sign path
// can fail closed on a real query failure.
type ActiveCertStore interface {
	Get(identity string) (ActiveCert, bool, error)
	Upsert(ac ActiveCert) error
	Delete(identity string) error
	// Lock escalates a reuse detection: it stamps locked_at (now) and
	// locked_serial on the identity's row so every later sign request is
	// denied until the row is cleared with Delete. A no-op if the row is
	// absent (the guard only locks an identity that already has a record).
	Lock(identity, offendingSerial string) error
	// AdoptCurrent collapses the one-step grace: it clears previous_serial /
	// previous_not_after for the identity IFF serial is its recorded current
	// serial and the row is not locked. Returns whether a row was collapsed
	// (false when serial isn't current, the row is absent, or it's locked).
	// The agent calls it once it has durably persisted the current cert,
	// shrinking the window the rotated-from serial stays acceptable.
	AdoptCurrent(identity, serial string) (bool, error)
}

// ── roles ──────────────────────────────────────────────────────────────

// RoleColumns is the shared SELECT/INSERT column list (excluding
// updated_at). Order matches [ScanRole] and [RoleInsertArgs].
const RoleColumns = `name, group_claim, allowed_principals, host_patterns, ` +
	`spiffe_patterns, default_extensions, max_user_cert_ttl_seconds, ` +
	`max_host_cert_ttl_seconds, max_x509_cert_ttl_seconds`

// RowScanner is satisfied by both *sql.Row and *sql.Rows.
type RowScanner interface{ Scan(dest ...any) error }

// ScanRole reads one role row (in [RoleColumns] order) into a policy.Role.
func ScanRole(sc RowScanner) (policy.Role, error) {
	var (
		r                      policy.Role
		allowed, hosts, spiffe string
		exts                   string
	)
	if err := sc.Scan(&r.Name, &r.GroupClaim, &allowed, &hosts, &spiffe, &exts,
		&r.MaxUserCertTTLSeconds, &r.MaxHostCertTTLSeconds, &r.MaxX509CertTTLSeconds); err != nil {
		return policy.Role{}, err
	}
	if err := DecodeJSON(allowed, &r.AllowedPrincipals); err != nil {
		return policy.Role{}, err
	}
	if err := DecodeJSON(hosts, &r.HostPatterns); err != nil {
		return policy.Role{}, err
	}
	if err := DecodeJSON(spiffe, &r.SPIFFEPatterns); err != nil {
		return policy.Role{}, err
	}
	if err := DecodeJSON(exts, &r.DefaultExtensions); err != nil {
		return policy.Role{}, err
	}
	return r, nil
}

// ScanRoles drains rows into a slice.
func ScanRoles(rows *sql.Rows) ([]policy.Role, error) {
	var out []policy.Role
	for rows.Next() {
		r, err := ScanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RoleInsertArgs returns positional args for an INSERT over [RoleColumns]
// plus a trailing updated_at, with multi-valued fields JSON-encoded.
func RoleInsertArgs(r policy.Role, updatedAt string) ([]any, error) {
	allowed, err := EncodeJSON(r.AllowedPrincipals)
	if err != nil {
		return nil, err
	}
	hosts, err := EncodeJSON(r.HostPatterns)
	if err != nil {
		return nil, err
	}
	spiffe, err := EncodeJSON(r.SPIFFEPatterns)
	if err != nil {
		return nil, err
	}
	exts, err := EncodeJSON(r.DefaultExtensions)
	if err != nil {
		return nil, err
	}
	return []any{
		r.Name, r.GroupClaim, allowed, hosts, spiffe, exts,
		r.MaxUserCertTTLSeconds, r.MaxHostCertTTLSeconds, r.MaxX509CertTTLSeconds,
		updatedAt,
	}, nil
}

// ScanRoleRecord reads one role row in [RoleColumns] order plus a trailing
// source column into a [RoleRecord] — the shape AllWithSource selects.
func ScanRoleRecord(sc RowScanner) (RoleRecord, error) {
	var (
		r                      policy.Role
		allowed, hosts, spiffe string
		exts, source           string
	)
	if err := sc.Scan(&r.Name, &r.GroupClaim, &allowed, &hosts, &spiffe, &exts,
		&r.MaxUserCertTTLSeconds, &r.MaxHostCertTTLSeconds, &r.MaxX509CertTTLSeconds, &source); err != nil {
		return RoleRecord{}, err
	}
	if err := DecodeJSON(allowed, &r.AllowedPrincipals); err != nil {
		return RoleRecord{}, err
	}
	if err := DecodeJSON(hosts, &r.HostPatterns); err != nil {
		return RoleRecord{}, err
	}
	if err := DecodeJSON(spiffe, &r.SPIFFEPatterns); err != nil {
		return RoleRecord{}, err
	}
	if err := DecodeJSON(exts, &r.DefaultExtensions); err != nil {
		return RoleRecord{}, err
	}
	return RoleRecord{Role: r, Source: source}, nil
}

// ScanRoleRecords drains rows (over [RoleColumns] + source) into a slice.
func ScanRoleRecords(rows *sql.Rows) ([]RoleRecord, error) {
	var out []RoleRecord
	for rows.Next() {
		rec, err := ScanRoleRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ── principals ─────────────────────────────────────────────────────────

// PrincipalColumns is the shared column list for the principals table.
// Order matches [ScanPrincipal] and [PrincipalInsertArgs]. The registered
// SAN is the primary key (mtls.Principal.MatchedSAN).
const PrincipalColumns = `san, name, groups`

// ScanPrincipal reads one principal row into an mtls.Principal, setting
// MatchedSAN from the san column.
func ScanPrincipal(sc RowScanner) (mtls.Principal, error) {
	var (
		p      mtls.Principal
		groups string
	)
	if err := sc.Scan(&p.MatchedSAN, &p.Name, &groups); err != nil {
		return mtls.Principal{}, err
	}
	if err := DecodeJSON(groups, &p.Groups); err != nil {
		return mtls.Principal{}, err
	}
	return p, nil
}

// ScanPrincipals drains rows into a slice.
func ScanPrincipals(rows *sql.Rows) ([]mtls.Principal, error) {
	var out []mtls.Principal
	for rows.Next() {
		p, err := ScanPrincipal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PrincipalInsertArgs returns positional args for an INSERT over
// [PrincipalColumns] plus a trailing updated_at.
func PrincipalInsertArgs(p mtls.Principal, updatedAt string) ([]any, error) {
	groups, err := EncodeJSON(p.Groups)
	if err != nil {
		return nil, err
	}
	return []any{p.MatchedSAN, p.Name, groups, updatedAt}, nil
}

// ScanPrincipalRecord reads one principal row (over [PrincipalColumns]) plus a
// trailing source column into a [PrincipalRecord].
func ScanPrincipalRecord(sc RowScanner) (PrincipalRecord, error) {
	var (
		p              mtls.Principal
		groups, source string
	)
	if err := sc.Scan(&p.MatchedSAN, &p.Name, &groups, &source); err != nil {
		return PrincipalRecord{}, err
	}
	if err := DecodeJSON(groups, &p.Groups); err != nil {
		return PrincipalRecord{}, err
	}
	return PrincipalRecord{Principal: p, Source: source}, nil
}

// ScanPrincipalRecords drains rows (over [PrincipalColumns] + source) into a
// slice.
func ScanPrincipalRecords(rows *sql.Rows) ([]PrincipalRecord, error) {
	var out []PrincipalRecord
	for rows.Next() {
		rec, err := ScanPrincipalRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ── revocations (SSH KRL) ────────────────────────────────────────────────

// RevocationColumns is the shared column list for the ssh_revocations
// table. Order matches [ScanRevocation]. serial is stored as TEXT (decimal)
// so the full uint64 range survives without signed-64 overflow; either
// serial or key_id may be NULL (never both — enforced by a CHECK).
const RevocationColumns = `serial, key_id, reason, revoker, revoked_at`

// ScanRevocation reads one revocation row into a krl.Revocation.
func ScanRevocation(sc RowScanner) (krl.Revocation, error) {
	var (
		r         krl.Revocation
		serial    sql.NullString
		keyID     sql.NullString
		revokedAt string
	)
	if err := sc.Scan(&serial, &keyID, &r.Reason, &r.Revoker, &revokedAt); err != nil {
		return krl.Revocation{}, err
	}
	if serial.Valid && serial.String != "" {
		n, err := strconv.ParseUint(serial.String, 10, 64)
		if err != nil {
			return krl.Revocation{}, err
		}
		r.Serial = n
	}
	if keyID.Valid {
		r.KeyID = keyID.String
	}
	if revokedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, revokedAt)
		if err != nil {
			return krl.Revocation{}, err
		}
		r.Revoked = t
	}
	return r, nil
}

// ScanRevocations drains rows into a slice.
func ScanRevocations(rows *sql.Rows) ([]krl.Revocation, error) {
	var out []krl.Revocation
	for rows.Next() {
		r, err := ScanRevocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevocationInsertArgs returns positional args for an INSERT over
// [RevocationColumns]. A zero Serial / empty KeyID becomes NULL.
func RevocationInsertArgs(r krl.Revocation) []any {
	var serial any
	if r.Serial != 0 {
		serial = strconv.FormatUint(r.Serial, 10)
	}
	var keyID any
	if r.KeyID != "" {
		keyID = r.KeyID
	}
	return []any{serial, keyID, r.Reason, r.Revoker, r.Revoked.UTC().Format(time.RFC3339Nano)}
}

// ── active workload certs ────────────────────────────────────────────────

// ActiveCertColumns is the column list the issuance upsert writes (excluding
// updated_at). The lock columns are deliberately NOT here — they're mutated
// only by Lock and read by [ActiveCertSelectColumns], never by Upsert.
const ActiveCertColumns = `identity, current_serial, current_not_after, previous_serial, previous_not_after`

// ActiveCertSelectColumns is what Get reads: the issuance columns plus the
// lock state. Order matches [ScanActiveCert].
const ActiveCertSelectColumns = ActiveCertColumns + `, locked_at, locked_serial`

// ScanActiveCert reads one row (over [ActiveCertSelectColumns]) into an
// [ActiveCert]. previous_* are NULL when the state has collapsed to a single
// live serial; locked_* are NULL when the identity is not locked.
func ScanActiveCert(sc RowScanner) (ActiveCert, error) {
	var (
		ac           ActiveCert
		curNotAfter  string
		prevSerial   sql.NullString
		prevNotAfter sql.NullString
		lockedAt     sql.NullString
		lockedSerial sql.NullString
	)
	if err := sc.Scan(&ac.Identity, &ac.CurrentSerial, &curNotAfter, &prevSerial, &prevNotAfter, &lockedAt, &lockedSerial); err != nil {
		return ActiveCert{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, curNotAfter)
	if err != nil {
		return ActiveCert{}, err
	}
	ac.CurrentNotAfter = t
	if prevSerial.Valid {
		ac.PreviousSerial = prevSerial.String
	}
	if lockedSerial.Valid {
		ac.LockedSerial = lockedSerial.String
	}
	if lockedAt.Valid && lockedAt.String != "" {
		t, err := time.Parse(time.RFC3339Nano, lockedAt.String)
		if err != nil {
			return ActiveCert{}, err
		}
		ac.LockedAt = t
	}
	if prevNotAfter.Valid && prevNotAfter.String != "" {
		t, err := time.Parse(time.RFC3339Nano, prevNotAfter.String)
		if err != nil {
			return ActiveCert{}, err
		}
		ac.PreviousNotAfter = t
	}
	return ac, nil
}

// ActiveCertUpsertArgs returns positional args for an upsert over
// [ActiveCertColumns] plus a trailing updated_at. A zero previous collapses
// to NULL columns.
func ActiveCertUpsertArgs(ac ActiveCert, updatedAt string) []any {
	var prevSerial any
	if ac.PreviousSerial != "" {
		prevSerial = ac.PreviousSerial
	}
	var prevNotAfter any
	if !ac.PreviousNotAfter.IsZero() {
		prevNotAfter = ac.PreviousNotAfter.UTC().Format(time.RFC3339Nano)
	}
	return []any{
		ac.Identity, ac.CurrentSerial, ac.CurrentNotAfter.UTC().Format(time.RFC3339Nano),
		prevSerial, prevNotAfter, updatedAt,
	}
}

// ── JSON helpers ─────────────────────────────────────────────────────────

// EncodeJSON marshals v to a JSON string for a TEXT column.
func EncodeJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeJSON unmarshals s into dst, treating empty/"null" as a no-op so a
// zero column leaves the destination at its zero value.
func DecodeJSON(s string, dst any) error {
	if s == "" || s == "null" {
		return nil
	}
	return json.Unmarshal([]byte(s), dst)
}
