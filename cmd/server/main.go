// Command server runs the MailOS API server: REST and gRPC (TLS), metrics and, with
// FEATURE_PUBSUB_INGEST, the Kafka consumer of signed IAM events.
package main

import (
	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/app"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Version and Commit are set by the build (-ldflags -X).
var (
	Version = "dev"
	Commit  = ""
)

func main() {
	_ = logger.InitSimple("info", "json")
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("config", logger.Err(err))
	}
	if cfg.App.Version == "dev" {
		cfg.App.Version = Version
	}
	if err := logger.Init(logger.Options{Level: cfg.App.LogLevel, Format: cfg.App.LogFormat, Production: cfg.App.IsProduction(),
		Service: "mailos-server", Version: cfg.App.Version, Env: cfg.App.Env}); err != nil {
		logger.Fatal("logger", logger.Err(err))
	}
	if err := app.RunServer(cfg); err != nil {
		logger.Fatal("server exited", logger.Err(err))
	}
	logger.Sync()
}
