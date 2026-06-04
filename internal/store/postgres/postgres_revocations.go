package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/krl"
	"github.com/abagile/tokyo3-ca/internal/store"
)

// Revoke satisfies [krl.Store]. Idempotent: re-revoking the same serial or
// key_id replaces the row's reason/revoker/revoked_at (delete-then-insert,
// matching the in-memory store's overwrite semantics).
func (s *revocationStore) Revoke(r krl.Revocation) error {
	if r.Serial == 0 && r.KeyID == "" {
		return krl.ErrEmptyRevocation
	}
	if r.Revoked.IsZero() {
		r.Revoked = time.Now().UTC()
	}
	return inTx(s.db, func(tx *sql.Tx) error {
		if r.Serial != 0 {
			if _, err := tx.ExecContext(context.Background(),
				`DELETE FROM ssh_revocations WHERE serial = $1`, strconv.FormatUint(r.Serial, 10)); err != nil {
				return err
			}
		}
		if r.KeyID != "" {
			if _, err := tx.ExecContext(context.Background(),
				`DELETE FROM ssh_revocations WHERE key_id = $1`, r.KeyID); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(context.Background(),
			`INSERT INTO ssh_revocations (`+store.RevocationColumns+`) VALUES ($1, $2, $3, $4, $5)`,
			store.RevocationInsertArgs(r)...)
		return err
	})
}

// Snapshot satisfies [krl.Store]. Sorted by revoked_at; fails closed (empty)
// on error. (Numeric serial ordering for the KRL spec is applied by
// [krl.MarshalSpec], not here.)
func (s *revocationStore) Snapshot() krl.Snapshot {
	now := time.Now().UTC()
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT `+store.RevocationColumns+` FROM ssh_revocations ORDER BY revoked_at, serial, key_id`)
	if err != nil {
		s.log.Error("postgres revocations Snapshot query failed", "err", err)
		return krl.Snapshot{CapturedAt: now}
	}
	defer rows.Close()
	entries, err := store.ScanRevocations(rows)
	if err != nil {
		s.log.Error("postgres revocations Snapshot scan failed", "err", err)
		return krl.Snapshot{CapturedAt: now}
	}
	return krl.Snapshot{CapturedAt: now, Entries: entries}
}

// IsRevoked satisfies [krl.Store]. Fails CLOSED: on a query error it logs
// and returns true (treat as revoked) — honouring a possibly-revoked cert
// is the failure this guard exists to prevent.
func (s *revocationStore) IsRevoked(serial uint64, keyID string) bool {
	conds := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if serial != 0 {
		conds = append(conds, "serial = $"+strconv.Itoa(len(args)+1))
		args = append(args, strconv.FormatUint(serial, 10))
	}
	if keyID != "" {
		conds = append(conds, "key_id = $"+strconv.Itoa(len(args)+1))
		args = append(args, keyID)
	}
	if len(conds) == 0 {
		return false
	}
	var one int
	err := s.db.QueryRowContext(context.Background(),
		`SELECT 1 FROM ssh_revocations WHERE `+strings.Join(conds, " OR ")+` LIMIT 1`, args...).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false
	case err != nil:
		s.log.Error("postgres IsRevoked failed; failing closed (treating as revoked)", "err", err)
		return true
	}
	return true
}

// MarshalSpec renders the current set as an ssh-keygen KRL spec, reusing the
// shared formatter so it is byte-identical to the in-memory store's output.
func (s *revocationStore) MarshalSpec() string { return krl.MarshalSpec(s.Snapshot()) }
