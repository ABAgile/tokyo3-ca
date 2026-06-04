package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/store"
	"github.com/abagile/tokyo3-ca/internal/store/sqlite"
	"github.com/abagile/tokyo3-ca/internal/store/storetest"
)

// open returns a fresh file-backed SQLite store (migrated) per call, so each
// subtest is isolated.
func open(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "certd.db"), nil)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRoleStore(t *testing.T) {
	storetest.RunRoleStoreSuite(t, func(t *testing.T) store.RoleStore { return open(t).Roles() })
}

func TestPrincipalStore(t *testing.T) {
	storetest.RunPrincipalStoreSuite(t, func(t *testing.T) store.PrincipalStore { return open(t).Principals() })
}

func TestRevocationStore(t *testing.T) {
	storetest.RunRevocationStoreSuite(t, func(t *testing.T) store.RevocationStore { return open(t).Revocations() })
}
