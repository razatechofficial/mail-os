// Package main is the entry point for the database migration tool.
// Run this before starting the API server to apply pending migrations.
//
// Usage:
//
//	go run cmd/migrate/main.go -config environments/local.yaml up
//	go run cmd/migrate/main.go -config environments/local.yaml down
//	go run cmd/migrate/main.go -config environments/local.yaml down-all
//	go run cmd/migrate/main.go -config environments/local.yaml version
//
// Or via Makefile:
//
//	make migrate-up
//	make migrate-down
//	make migrate-version
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/postgres"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// migrationsPath is relative to the project root.
// When running via Makefile or go run from project root, this resolves correctly.
const migrationsPath = "migrations"

func main() {
	// ── 1. parse flags ──────────────────────────────────────────
	configPath := flag.String("config", "environments/local.yaml", "path to config file")
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}
	command := flag.Arg(0)

	// ── 2. load config ──────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	// ── 3. init logger ──────────────────────────────────────────
	logger.Init(cfg.App.LogLevel)
	defer logger.Sync()

	// ── 4. create migrator ──────────────────────────────────────
	migrator, err := postgres.NewMigrator(cfg.Postgres.DSN(), migrationsPath)
	if err != nil {
		logger.Fatal("failed to create migrator", logger.Err(err))
	}
	defer func() {
		if err := migrator.Close(); err != nil {
			logger.Error("error closing migrator", logger.Err(err))
		}
	}()

	// ── 5. execute command ──────────────────────────────────────
	switch command {
	case "up":
		logger.Info("applying migrations...")
		if err := migrator.Up(); err != nil {
			logger.Fatal("migration up failed", logger.Err(err))
		}
		logger.Info("migrations applied successfully")

	case "down":
		logger.Info("rolling back last migration...")
		if err := migrator.Down(); err != nil {
			logger.Fatal("migration down failed", logger.Err(err))
		}
		logger.Info("rollback completed")

	case "down-all":
		if cfg.App.IsProduction() {
			logger.Fatal("down-all is not allowed in production")
		}
		logger.Info("rolling back all migrations...")
		if err := migrator.DownAll(); err != nil {
			logger.Fatal("migration down-all failed", logger.Err(err))
		}
		logger.Info("all migrations rolled back")

	case "version":
		version, dirty, err := migrator.Version()
		if err != nil {
			logger.Fatal("failed to get migration version", logger.Err(err))
		}
		fmt.Printf("current migration version: %d (dirty: %v)\n", version, dirty)

	default:
		fmt.Printf("unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: migrate [flags] <command>")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -config string   path to config file (default \"environments/local.yaml\")")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  up         apply all pending migrations")
	fmt.Println("  down       rollback last migration")
	fmt.Println("  down-all   rollback all migrations (development only)")
	fmt.Println("  version    show current migration version")
}
