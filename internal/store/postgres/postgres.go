// Package postgres implements certd's store interfaces on PostgreSQL via
// pgx/v5 (over database/sql). It is the production backend; the sqlite
// backend behind the same interfaces serves the dev rig and unit tests.
// See certd-store-design.md.
//
// Connection identity follows the WORKLOAD/mTLS convention: pass a
// *tls.Config (from the daemon's reloader) to Open for client-cert auth to
// Postgres, or nil for a plain DSN-only connection.
package postgres

import (
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	pgx "github.com/jackc/pgx/v5"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"

	"github.com/abagile/tokyo3-ca/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a *sql.DB and exposes certd's per-table stores for PostgreSQL,
// all sharing the one pool.
type DB struct {
	db  *sql.DB
	log *slog.Logger
}

var _ store.Store = (*DB)(nil)

// Open connects to dsn, applies pending migrations, and returns a *DB with
// a small connection pool. tlsCfg enables client-cert auth when non-nil
// (its ServerName defaults to the DSN host). log may be nil.
func Open(ctx context.Context, dsn string, tlsCfg *tls.Config, log *slog.Logger) (*DB, error) {
	if log == nil {
		log = slog.Default()
	}
	sqldb, err := openDB(dsn, tlsCfg)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(25)
	sqldb.SetMaxIdleConns(5)
	sqldb.SetConnMaxLifetime(5 * time.Minute)
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
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

// ActiveCerts returns the X.509 workload-cert rotation store.
func (d *DB) ActiveCerts() store.ActiveCertStore { return &activeCertStore{db: d.db, log: d.log} }

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

type activeCertStore struct {
	db  *sql.DB
	log *slog.Logger
}

var (
	_ store.RoleStore       = (*roleStore)(nil)
	_ store.PrincipalStore  = (*principalStore)(nil)
	_ store.RevocationStore = (*revocationStore)(nil)
	_ store.ActiveCertStore = (*activeCertStore)(nil)
)

func openDB(dsn string, tlsCfg *tls.Config) (*sql.DB, error) {
	connCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	if tlsCfg != nil {
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = connCfg.Host
		}
		connCfg.TLSConfig = tlsCfg
	}
	return pgxstdlib.OpenDB(*connCfg), nil
}

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
// transaction. Multi-statement files are exec'd arg-less so pgx uses the
// simple protocol (which permits multiple commands per Exec).
func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
			`SELECT COUNT(*) FROM schema_migrations WHERE version = $1`, name).Scan(&already); err != nil {
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
			`INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}
