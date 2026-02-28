package main

import (
	"flag"
	"log"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/app"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

func main() {
	configPath := flag.String("config", "environments/local.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger.Init(cfg.App.LogLevel)
	defer logger.Sync()

	application, err := app.New(cfg)
	if err != nil {
		logger.Fatal("failed to initialize app", logger.Err(err))
	}

	if err := application.Start(); err != nil {
		logger.Fatal("app failed", logger.Err(err))
	}
}
