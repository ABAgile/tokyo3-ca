package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-ca/internal/store"
)

// Get satisfies [store.ActiveCertStore]. ok is false when no row exists
// (first issuance); a real query error is returned so the sign-path guard
// can fail closed.
func (s *activeCertStore) Get(identity string) (store.ActiveCert, bool, error) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT `+store.ActiveCertSelectColumns+` FROM active_workload_cert WHERE identity = ?`, identity)
	ac, err := store.ScanActiveCert(row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.ActiveCert{}, false, nil
	case err != nil:
		return store.ActiveCert{}, false, err
	}
	return ac, true, nil
}

// Upsert satisfies [store.ActiveCertStore].
func (s *activeCertStore) Upsert(ac store.ActiveCert) error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO active_workload_cert (`+store.ActiveCertColumns+`, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (identity) DO UPDATE SET
		   current_serial     = excluded.current_serial,
		   current_not_after  = excluded.current_not_after,
		   previous_serial    = excluded.previous_serial,
		   previous_not_after = excluded.previous_not_after,
		   updated_at         = excluded.updated_at`,
		store.ActiveCertUpsertArgs(ac, nowRFC3339())...)
	return err
}

// Delete satisfies [store.ActiveCertStore]. No error when the row is absent.
func (s *activeCertStore) Delete(identity string) error {
	_, err := s.db.ExecContext(context.Background(),
		`DELETE FROM active_workload_cert WHERE identity = ?`, identity)
	return err
}

// Lock satisfies [store.ActiveCertStore]: stamp locked_at (now) +
// locked_serial on the identity. A no-op on a missing row (0 rows updated).
func (s *activeCertStore) Lock(identity, offendingSerial string) error {
	var serial any
	if offendingSerial != "" {
		serial = offendingSerial
	}
	_, err := s.db.ExecContext(context.Background(),
		`UPDATE active_workload_cert SET locked_at = ?, locked_serial = ? WHERE identity = ?`,
		nowRFC3339(), serial, identity)
	return err
}

// AdoptCurrent satisfies [store.ActiveCertStore]: collapse the one-step grace
// only when serial is the current serial and the row isn't locked.
func (s *activeCertStore) AdoptCurrent(identity, serial string) (bool, error) {
	res, err := s.db.ExecContext(context.Background(),
		`UPDATE active_workload_cert SET previous_serial = NULL, previous_not_after = NULL
		 WHERE identity = ? AND current_serial = ? AND locked_at IS NULL`,
		identity, serial)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
