// Package sqlite implements certd's store interfaces on SQLite via the
// pure-Go modernc.org/sqlite driver (no cgo). It is the dev-rig + unit-test
// backend; production uses the postgres backend behind the same interfaces.
// See certd-store-design.md.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver

	"github.com/abagile/tokyo3-ca/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a *sql.DB and exposes certd's per-table stores for SQLite, all
// sharing the one connection.
type DB struct {
	db  *sql.DB
	log *slog.Logger
}

var _ store.Store = (*DB)(nil)

// Open opens (creating if absent) the SQLite database at path, applies all
// pending migrations, and returns a *DB. path may be ":memory:" for tests.
// log may be nil. WAL + foreign-keys + a busy timeout are set; the open-conn
// cap is 1 because SQLite has a single writer (and it keeps a ":memory:"
// database single-instanced across the pool).
func Open(ctx context.Context, path string, log *slog.Logger) (*DB, error) {
	if log == nil {
		log = slog.Default()
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)&_pragma=journal_mode(WAL)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("ping sqlite %q: %w", path, err)
	}
	d := &DB{db: sqldb, log: log}
	if err := d.migrate(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

// Close closes the underlying database.
func (d *DB) Close() error { return d.db.Close() }

// Roles returns the role-table store.
func (d *DB) Roles() store.RoleStore { return &roleStore{db: d.db, log: d.log} }

// Principals returns the mTLS cert-principal store.
func (d *DB) Principals() store.PrincipalStore { return &principalStore{db: d.db, log: d.log} }

// Revocations returns the SSH KRL store.
func (d *DB) Revocations() store.RevocationStore { return &revocationStore{db: d.db, log: d.log} }

type roleStore struct {
	db  *sql.DB
	log *slog.Logger
}

type principalStore struct {
	db  *sql.DB
	log *slog.Logger
}

type revocationStore struct {
	db  *sql.DB
	log *slog.Logger
}

var (
	_ store.RoleStore       = (*roleStore)(nil)
	_ store.PrincipalStore  = (*principalStore)(nil)
	_ store.RevocationStore = (*revocationStore)(nil)
)

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// inTx runs fn inside a transaction, rolling back on error.
func inTx(db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// migrate applies every embedded migrations/*.sql not yet recorded in
// schema_migrations, in lexical filename order, each in its own
// transaction. Idempotent — safe to call on every boot.
func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var already int
		if err := d.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&already); err != nil {
			return err
		}
		if already > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := d.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			name, time.Now().UTC().Format(time.RFC3339)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}
