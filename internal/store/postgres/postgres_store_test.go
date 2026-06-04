package postgres_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // "pgx" driver for the truncation handle

	"github.com/abagile/tokyo3-ca/internal/store"
	"github.com/abagile/tokyo3-ca/internal/store/postgres"
	"github.com/abagile/tokyo3-ca/internal/store/storetest"
)

// TestStores runs the shared acceptance suites against a real PostgreSQL
// when CERTD_TEST_DATABASE_URL is set; otherwise it skips, so the default
// `go test ./...` stays green offline. The sqlite backend always covers the
// logic; this verifies the pg dialect (placeholders, types, migrations)
// against a live server.
func TestStores(t *testing.T) {
	dsn := os.Getenv("CERTD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set CERTD_TEST_DATABASE_URL to run the postgres store suite")
	}
	db, err := postgres.Open(context.Background(), dsn, nil, nil)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Separate raw handle to TRUNCATE between subtests for isolation.
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open truncation handle: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	reset := func(t *testing.T) {
		t.Helper()
		if _, err := raw.Exec(`TRUNCATE roles, principals, ssh_revocations`); err != nil {
			t.Fatalf("truncate: %v", err)
		}
	}

	storetest.RunRoleStoreSuite(t, func(t *testing.T) store.RoleStore { reset(t); return db.Roles() })
	storetest.RunPrincipalStoreSuite(t, func(t *testing.T) store.PrincipalStore { reset(t); return db.Principals() })
	storetest.RunRevocationStoreSuite(t, func(t *testing.T) store.RevocationStore { reset(t); return db.Revocations() })
}
