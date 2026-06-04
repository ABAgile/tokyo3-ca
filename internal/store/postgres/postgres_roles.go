package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/policy"
	"github.com/abagile/tokyo3-ca/internal/store"
)

// RolesForGroups satisfies [policy.Store]. Duplicate groups collapse; a
// query error fails closed (nil → caller denies).
func (s *roleStore) RolesForGroups(groups []string) []policy.Role {
	if len(groups) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(groups))
	args := make([]any, 0, len(groups))
	ph := make([]string, 0, len(groups))
	for _, g := range groups {
		if seen[g] {
			continue
		}
		seen[g] = true
		args = append(args, g)
		ph = append(ph, "$"+strconv.Itoa(len(args)))
	}
	q := `SELECT ` + store.RoleColumns + ` FROM roles WHERE group_claim IN (` + strings.Join(ph, ",") + `)`
	rows, err := s.db.QueryContext(context.Background(), q, args...)
	if err != nil {
		s.log.Error("postgres RolesForGroups query failed; denying", "err", err)
		return nil
	}
	defer rows.Close()
	out, err := store.ScanRoles(rows)
	if err != nil {
		s.log.Error("postgres RolesForGroups scan failed; denying", "err", err)
		return nil
	}
	return out
}

// All satisfies [policy.Store]. Ordered by name; fails closed on error.
func (s *roleStore) All() []policy.Role {
	rows, err := s.db.QueryContext(context.Background(), `SELECT `+store.RoleColumns+` FROM roles ORDER BY name`)
	if err != nil {
		s.log.Error("postgres roles All query failed", "err", err)
		return nil
	}
	defer rows.Close()
	out, err := store.ScanRoles(rows)
	if err != nil {
		s.log.Error("postgres roles All scan failed", "err", err)
		return nil
	}
	return out
}

// ByName returns the role registered under name; ok is false when absent
// (or on error, logged).
func (s *roleStore) ByName(name string) (policy.Role, bool) {
	row := s.db.QueryRowContext(context.Background(), `SELECT `+store.RoleColumns+` FROM roles WHERE name = $1`, name)
	r, err := store.ScanRole(row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return policy.Role{}, false
	case err != nil:
		s.log.Error("postgres ByName failed", "name", name, "err", err)
		return policy.Role{}, false
	}
	return r, true
}

// Add inserts role. Returns [policy.ErrRoleExists] on a name collision.
func (s *roleStore) Add(role policy.Role) error {
	if role.Name == "" {
		return errors.New("role name is required")
	}
	return inTx(s.db, func(tx *sql.Tx) error {
		exists, err := roleExists(tx, role.Name)
		if err != nil {
			return err
		}
		if exists {
			return policy.ErrRoleExists
		}
		return insertRole(tx, role)
	})
}

// Replace swaps the role registered as oldName for newRole (a rename when
// the names differ). Returns [policy.ErrRoleNotFound] / [policy.ErrRoleExists].
func (s *roleStore) Replace(oldName string, newRole policy.Role) error {
	if newRole.Name == "" {
		return errors.New("role name is required")
	}
	return inTx(s.db, func(tx *sql.Tx) error {
		exists, err := roleExists(tx, oldName)
		if err != nil {
			return err
		}
		if !exists {
			return policy.ErrRoleNotFound
		}
		if newRole.Name != oldName {
			collide, err := roleExists(tx, newRole.Name)
			if err != nil {
				return err
			}
			if collide {
				return policy.ErrRoleExists
			}
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM roles WHERE name = $1`, oldName); err != nil {
			return err
		}
		return insertRole(tx, newRole)
	})
}

// Delete removes the role registered as name. Returns [policy.ErrRoleNotFound]
// when absent.
func (s *roleStore) Delete(name string) error {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM roles WHERE name = $1`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return policy.ErrRoleNotFound
	}
	return nil
}

// SeedRolesIfEmpty satisfies [store.RoleStore].
func (s *roleStore) SeedRolesIfEmpty(roles []policy.Role) (bool, error) {
	seeded := false
	err := inTx(s.db, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM roles`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		for _, r := range roles {
			if r.Name == "" {
				return errors.New("seed role has empty name")
			}
			if err := insertRole(tx, r); err != nil {
				return err
			}
		}
		seeded = len(roles) > 0
		return nil
	})
	return seeded, err
}

func roleExists(tx *sql.Tx, name string) (bool, error) {
	var one int
	err := tx.QueryRowContext(context.Background(), `SELECT 1 FROM roles WHERE name = $1`, name).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

func insertRole(tx *sql.Tx, r policy.Role) error {
	args, err := store.RoleInsertArgs(r, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(context.Background(),
		`INSERT INTO roles (`+store.RoleColumns+`, updated_at) `+
			`VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		args...)
	return err
}
