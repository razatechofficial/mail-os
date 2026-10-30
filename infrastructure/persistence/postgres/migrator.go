package postgres

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // pgx5:// driver
	_ "github.com/golang-migrate/migrate/v4/source/file"     // file:// source

	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Migrator wraps golang-migrate. It is used by cmd/migrate-postgres and the
// tests; the server never migrates on start.
type Migrator struct {
	migrate *migrate.Migrate
}

// NewMigrator opens migrationsPath (migrations/postgres) against dsn.
func NewMigrator(dsn, migrationsPath string) (*Migrator, error) {
	m, err := migrate.New("file://"+migrationsPath, "pgx5://"+strings.TrimPrefix(dsn, "postgres://"))
	if err != nil {
		return nil, fmt.Errorf("creating migrator: %w", err)
	}
	return &Migrator{migrate: m}, nil
}

// Up applies all pending migrations.
func (m *Migrator) Up() error {
	if err := m.migrate.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("applying migrations: %w", err)
	}
	v, _, _ := m.migrate.Version()
	logger.Info("migrations applied", logger.Int64("version", int64(v)))
	return nil
}

// Down rolls back the most recently applied migration.
func (m *Migrator) Down() error {
	if err := m.migrate.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("rolling back migration: %w", err)
	}
	return nil
}

// DownAll rolls back every migration (development and CI only).
func (m *Migrator) DownAll() error {
	if err := m.migrate.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("rolling back all migrations: %w", err)
	}
	return nil
}

// Version returns the applied version and whether it is dirty.
func (m *Migrator) Version() (uint, bool, error) {
	v, dirty, err := m.migrate.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return v, dirty, err
}

// Close releases the source and database handles.
func (m *Migrator) Close() error {
	srcErr, dbErr := m.migrate.Close()
	return errors.Join(srcErr, dbErr)
}
