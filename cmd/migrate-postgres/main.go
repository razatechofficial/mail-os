// Command migrate-postgres applies the Postgres migrations in
// migrations/postgres. Migrations run as their own step before a rollout;
// the server never migrates on start.
//
//	migrate-postgres up | down | down-all | version
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

func main() {
	dir := flag.String("dir", "migrations/postgres", "migrations directory")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: migrate-postgres [-dir migrations/postgres] up|down|down-all|version")
		os.Exit(2)
	}
	_ = logger.InitSimple("info", "json")
	cfg, err := config.LoadDatabase()
	if err != nil {
		logger.Fatal("config", logger.Err(err))
	}
	m, err := postgres.NewMigrator(cfg.Postgres.DSN(), *dir)
	if err != nil {
		logger.Fatal("migrator", logger.Err(err))
	}
	defer func() { _ = m.Close() }()

	switch flag.Arg(0) {
	case "up":
		err = m.Up()
	case "down":
		err = m.Down()
	case "down-all":
		if cfg.App.IsProduction() {
			logger.Fatal("down-all is refused in production")
		}
		err = m.DownAll()
	case "version":
		var v uint
		var dirty bool
		v, dirty, err = m.Version()
		if err == nil {
			fmt.Printf("version %d dirty %v\n", v, dirty)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", flag.Arg(0))
		os.Exit(2)
	}
	if err != nil {
		logger.Fatal("migrate "+flag.Arg(0), logger.Err(err))
	}
}
