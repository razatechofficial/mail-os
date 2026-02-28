package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/razatechofficial/mail-os/config"
)

func main() {
	configPath := flag.String("config", "environments/local.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("usage: migrate [up|down|down-all|version]")
		os.Exit(1)
	}

	command := flag.Arg(0)

	// TODO: migrator will be wired in adapter-outbound-postgres phase
	fmt.Printf("migrate %s using DSN: %s\n", command, cfg.Postgres.DSN())
}
