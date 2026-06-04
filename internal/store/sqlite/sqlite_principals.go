package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-ca/internal/server/mtls"
	"github.com/abagile/tokyo3-ca/internal/store"
)

// Lookup satisfies [mtls.Store]. Returns the first presented SAN that is
// registered (presented order preserved). A query error fails closed —
// returned as an error so the caller treats it as an auth failure.
func (s *principalStore) Lookup(sans []string) (*mtls.Principal, error) {
	if len(sans) == 0 {
		return nil, mtls.ErrNoClientCert
	}
	for _, san := range sans {
		row := s.db.QueryRowContext(context.Background(),
			`SELECT `+store.PrincipalColumns+` FROM principals WHERE san = ?`, san)
		p, err := store.ScanPrincipal(row)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue
		case err != nil:
			s.log.Error("sqlite principal Lookup failed", "san", san, "err", err)
			return nil, err
		}
		return &p, nil
	}
	return nil, mtls.ErrUnknownPrincipal
}

// All satisfies [mtls.Store]. Ordered by SAN; fails closed on error.
func (s *principalStore) All() []mtls.Principal {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT `+store.PrincipalColumns+` FROM principals ORDER BY san`)
	if err != nil {
		s.log.Error("sqlite principals All query failed", "err", err)
		return nil
	}
	defer rows.Close()
	out, err := store.ScanPrincipals(rows)
	if err != nil {
		s.log.Error("sqlite principals All scan failed", "err", err)
		return nil
	}
	return out
}

// SeedPrincipalsIfEmpty satisfies [store.PrincipalStore]. Entries without a
// registration SAN (MatchedSAN) are skipped, matching the in-memory store.
func (s *principalStore) SeedPrincipalsIfEmpty(principals []mtls.Principal) (bool, error) {
	seeded := false
	err := inTx(s.db, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM principals`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		for _, p := range principals {
			if p.MatchedSAN == "" {
				continue
			}
			if err := insertPrincipal(tx, p); err != nil {
				return err
			}
			seeded = true
		}
		return nil
	})
	return seeded, err
}

func insertPrincipal(tx *sql.Tx, p mtls.Principal) error {
	args, err := store.PrincipalInsertArgs(p, nowRFC3339())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(context.Background(),
		`INSERT INTO principals (`+store.PrincipalColumns+`, updated_at) VALUES (?, ?, ?, ?)`,
		args...)
	return err
}
