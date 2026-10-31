//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// apiKeysDropped is the migration that removes the unused api_keys table.
const apiKeysDropped = 20261031140000

// The legacy api_keys table is gone after up, comes back as it was when the
// drop is rolled back, and is gone again after the next up.
func TestLegacyAPIKeysTableDropped(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	exists := func() bool {
		t.Helper()
		var ok bool
		if err := db.QueryRow(ctx, `SELECT to_regclass('public.api_keys') IS NOT NULL`).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if exists() {
		t.Fatal("api_keys still exists after the migrations")
	}

	m, err := postgres.NewMigrator(testConfig().Postgres.DSN(), migrationsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	top, _, _ := m.Version()
	for v, _, _ := m.Version(); v >= apiKeysDropped; v, _, _ = m.Version() {
		if err := m.Down(); err != nil {
			t.Fatal(err)
		}
	}
	if !exists() {
		t.Fatal("rolling back the drop did not recreate api_keys")
	}
	var indexes int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE tablename = 'api_keys' AND indexname LIKE 'idx_api_keys_%'`).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	if indexes != 3 {
		t.Fatalf("recreated api_keys has %d of its 3 indexes", indexes)
	}
	if err := m.Up(); err != nil {
		t.Fatal(err)
	}
	if v, dirty, _ := m.Version(); v != top || dirty {
		t.Fatalf("after up: %d dirty=%v, want %d", v, dirty, top)
	}
	if exists() {
		t.Fatal("api_keys exists after up again")
	}
}
