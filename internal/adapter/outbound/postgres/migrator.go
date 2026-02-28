package postgres

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

type Migrator struct {
	m *migrate.Migrate
}

func NewMigrator(dsn, migrationsPath string) (*Migrator, error) {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return nil, fmt.Errorf("migrator.New: %w", err)
	}
	return &Migrator{m: m}, nil
}

func (mg *Migrator) Up() error {
	if err := mg.m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrator.Up: %w", err)
	}
	return nil
}

func (mg *Migrator) Down() error {
	if err := mg.m.Steps(-1); err != nil {
		return fmt.Errorf("migrator.Down: %w", err)
	}
	return nil
}

func (mg *Migrator) DownAll() error {
	if err := mg.m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrator.DownAll: %w", err)
	}
	return nil
}

func (mg *Migrator) Version() (uint, bool, error) {
	return mg.m.Version()
}

func (mg *Migrator) Close() error {
	srcErr, dbErr := mg.m.Close()
	if srcErr != nil {
		return srcErr
	}
	return dbErr
}
