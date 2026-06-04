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
	io.Closer
}

// RoleStore is the persistent backend for the role table. It satisfies
// [policy.Store] (the sign-time read surface) plus the admin write surface
// the portal's MutableRoleStore wants, plus SeedRolesIfEmpty for cold-start
// seeding from CERTD_ROLES_FILE. Reads fail closed in the backends.
type RoleStore interface {
	policy.Store // RolesForGroups(groups) []Role; All() []Role
	ByName(name string) (policy.Role, bool)
	Add(role policy.Role) error
	Replace(oldName string, newRole policy.Role) error
	Delete(name string) error
	// SeedRolesIfEmpty inserts roles only when the table is empty,
	// returning true when it seeded. Distinct name from the principal
	// seed so both can live on one composite Store.
	SeedRolesIfEmpty(roles []policy.Role) (bool, error)
}

// PrincipalStore is the persistent backend for the mTLS cert-principal
// registry. It satisfies [mtls.Store] (Lookup/All) plus a cold-start seed.
type PrincipalStore interface {
	mtls.Store // Lookup(sans) (*Principal, error); All() []Principal
	SeedPrincipalsIfEmpty(principals []mtls.Principal) (bool, error)
}

// RevocationStore is the persistent backend for the SSH KRL. It satisfies
// [krl.Store] (Revoke/Snapshot/IsRevoked) plus MarshalSpec so the
// /api/v1/ssh/krl.spec endpoint works against the DB backend too.
type RevocationStore interface {
	krl.Store // Revoke; Snapshot; IsRevoked
	MarshalSpec() string
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
