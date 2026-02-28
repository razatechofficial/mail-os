// Package main is the entry point for the MailOS API server.
// It starts both HTTP and gRPC listeners, background workers,
// and handles graceful shutdown on SIGINT/SIGTERM.
//
// Usage:
//
//	go run cmd/server/main.go -config environments/local.yaml
//
// Or via Makefile:
//
//	make run
package main

import (
	"flag"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/app"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

func main() {

	//! ================================ CONFIGURATION ================================
	//* Step 1: Load configuration from YAML + environment variables
	configPath := flag.String("config", "environments/local.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic("failed to load configuration: " + err.Error())
	}

	//! ================================ LOGGER ================================
	//* Step 2: Initialize structured logger before any other work
	logger.Init(cfg.App.LogLevel)

	//! ================================ APPLICATION BOOTSTRAP ================================
	//* Step 3: Build the application (infra connections, DI container, servers)
	application, err := app.New(cfg)
	if err != nil {
		logger.Fatal("failed to initialize application", logger.Err(err))
	}

	//! ================================ START & SHUTDOWN ================================
	//* Step 4: Start HTTP, gRPC, workers concurrently; block until signal
	// app.Start uses errgroup and signal.NotifyContext internally.
	// On SIGINT/SIGTERM it drains in-flight requests and closes connections.
	if err := application.Start(); err != nil {
		logger.Error("application exited with error", logger.Err(err))
	}

	logger.Info("process exited cleanly")

	// Flush all buffered log entries before the process exits
	logger.Sync()
}
