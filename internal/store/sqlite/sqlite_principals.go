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

// BySAN returns the principal registered under san; ok is false when absent
// (or on error, logged).
func (s *principalStore) BySAN(san string) (mtls.Principal, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT `+store.PrincipalColumns+` FROM principals WHERE san = ?`, san)
	p, err := store.ScanPrincipal(row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return mtls.Principal{}, false
	case err != nil:
		s.log.Error("sqlite principal BySAN failed", "san", san, "err", err)
		return mtls.Principal{}, false
	}
	return p, true
}

// Add inserts p (keyed by MatchedSAN), stamping the owner-marker source.
// Returns [mtls.ErrPrincipalExists] on a SAN collision.
func (s *principalStore) Add(p mtls.Principal, source string) error {
	if p.MatchedSAN == "" {
		return errors.New("principal SAN is required")
	}
	return inTx(s.db, func(tx *sql.Tx) error {
		exists, err := principalExists(tx, p.MatchedSAN)
		if err != nil {
			return err
		}
		if exists {
			return mtls.ErrPrincipalExists
		}
		return insertPrincipal(tx, p, source)
	})
}

// Replace swaps the principal registered as oldSAN for p (a re-key when the
// SANs differ), stamping the owner-marker source. Returns
// [mtls.ErrPrincipalNotFound] / [mtls.ErrPrincipalExists].
func (s *principalStore) Replace(oldSAN string, p mtls.Principal, source string) error {
	if p.MatchedSAN == "" {
		return errors.New("principal SAN is required")
	}
	return inTx(s.db, func(tx *sql.Tx) error {
		exists, err := principalExists(tx, oldSAN)
		if err != nil {
			return err
		}
		if !exists {
			return mtls.ErrPrincipalNotFound
		}
		if p.MatchedSAN != oldSAN {
			collide, err := principalExists(tx, p.MatchedSAN)
			if err != nil {
				return err
			}
			if collide {
				return mtls.ErrPrincipalExists
			}
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM principals WHERE san = ?`, oldSAN); err != nil {
			return err
		}
		return insertPrincipal(tx, p, source)
	})
}

// Delete removes the principal registered as san. Returns
// [mtls.ErrPrincipalNotFound] when absent.
func (s *principalStore) Delete(san string) error {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM principals WHERE san = ?`, san)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return mtls.ErrPrincipalNotFound
	}
	return nil
}

// AllWithSource satisfies [store.PrincipalStore]: every principal with its
// owner-marker source, ordered by SAN. Returns an error so reconcile fails
// closed.
func (s *principalStore) AllWithSource() ([]store.PrincipalRecord, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT `+store.PrincipalColumns+`, source FROM principals ORDER BY san`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return store.ScanPrincipalRecords(rows)
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
			if err := insertPrincipal(tx, p, store.SourceConfig); err != nil {
				return err
			}
			seeded = true
		}
		return nil
	})
	return seeded, err
}

func principalExists(tx *sql.Tx, san string) (bool, error) {
	var one int
	err := tx.QueryRowContext(context.Background(), `SELECT 1 FROM principals WHERE san = ?`, san).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

func insertPrincipal(tx *sql.Tx, p mtls.Principal, source string) error {
	args, err := store.PrincipalInsertArgs(p, nowRFC3339())
	if err != nil {
		return err
	}
	args = append(args, store.NormalizeSource(source))
	_, err = tx.ExecContext(context.Background(),
		`INSERT INTO principals (`+store.PrincipalColumns+`, updated_at, source) VALUES (?, ?, ?, ?, ?)`,
		args...)
	return err
}
