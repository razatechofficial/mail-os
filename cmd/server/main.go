package main

import (
	"flag"
	"log"

	"github.com/razatechofficial/mail-os/config"
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

	logger.Info("starting mailOS server",
		logger.String("env", cfg.App.Env),
		logger.String("http_addr", cfg.HTTP.Addr()),
		logger.String("grpc_addr", cfg.GRPC.Addr()),
	)

	// TODO: app.New(cfg) -> app.Start(ctx) will be wired in app-bootstrap phase
	_ = cfg
}
