// Package main is the entry point for the MailOS background worker process.
// Workers handle email processing, campaign fan-out, webhook delivery,
// stats aggregation, and scheduled-job polling.
//
// Usage:
//
//	go run cmd/worker/main.go -config environments/local.yaml
//
// Or via Makefile:
//
//	make run-worker
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/postgres"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/queue"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/rediscache"
	"github.com/razatechofficial/mail-os/internal/container"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/internal/worker"
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
	//* Step 2: Initialize structured logger
	logger.Init(cfg.App.LogLevel)

	//! ================================ INFRASTRUCTURE ================================
	//* Step 3: Connect to PostgreSQL, Redis, and queue backend
	ctx := context.Background()

	db, err := postgres.NewConnection(ctx, cfg.Postgres.DSN(), cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if err != nil {
		logger.Fatal("failed to connect to PostgreSQL", logger.Err(err))
	}
	logger.Info("connected to PostgreSQL")

	redis := rediscache.NewClient(cfg.Redis.Addr(), cfg.Redis.Password, cfg.Redis.DB)
	if err := redis.Health(ctx); err != nil {
		logger.Warn("redis not available, continuing without cache", logger.Err(err))
	} else {
		logger.Info("connected to Redis")
	}

	pub, con, err := queue.NewFromConfig(cfg.Queue.Backend, map[string]any{
		"dsn": cfg.Postgres.DSN(),
	})
	if err != nil {
		logger.Fatal("failed to initialize queue", logger.Err(err))
	}
	logger.Info("queue initialized", logger.String("backend", cfg.Queue.Backend))

	//! ================================ DI CONTAINER ================================
	//* Step 4: Build the dependency injection container
	c := container.New(cfg, db, redis, pub, con)

	//! ================================ WORKERS ================================
	//* Step 5: Create all worker instances and the manager
	mgr := worker.NewManager(
		worker.NewEmailProcessor(con, c.Adapters.MailRouter, c.Services.Message, cfg.Worker.EmailConcurrency),
		worker.NewCampaignProcessor(con, &messageEnqueuerProxy{svc: c.Services.Message}, c.Services.Campaign, c.Services.ContactList),
		worker.NewWebhookDeliverer(c.Services.Webhook, c.Adapters.Signer, c.Adapters.EventBus, 30*time.Second),
		worker.NewStatsAggregator(c.Services.Analytics, c.Adapters.EventBus, 100, cfg.Worker.StatsFlushInterval),
		worker.NewScheduler(c.Services.Message, c.Services.Campaign, pub, cfg.Worker.SchedulerInterval),
	)

	//! ================================ START & SHUTDOWN ================================
	//* Step 6: Block until SIGINT/SIGTERM, then gracefully stop workers
	runCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger.Info("starting workers",
		logger.String("env", cfg.App.Env),
		logger.Int("email_concurrency", cfg.Worker.EmailConcurrency),
	)

	if err := mgr.Start(runCtx); err != nil {
		logger.Error("worker manager exited with error", logger.Err(err))
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	logger.Info("stopping workers...")
	if err := mgr.Stop(shutdownCtx); err != nil {
		logger.Error("worker stop error", logger.Err(err))
	}

	if err := redis.Close(); err != nil {
		logger.Error("redis close error", logger.Err(err))
	}
	db.Close()

	logger.Info("worker process exited cleanly")
	logger.Sync()
}

// messageEnqueuerProxy adapts the message.Service to port.MessageEnqueuer
// so it can be used by the CampaignProcessor without a circular import.
type messageEnqueuerProxy struct {
	svc interface {
		EnqueueCampaignEmail(ctx context.Context, orgID, campaignID, contactEmail string) error
	}
}

func (p *messageEnqueuerProxy) EnqueueForContact(ctx context.Context, orgID, campaignID, contactEmail string) error {
	return p.svc.EnqueueCampaignEmail(ctx, orgID, campaignID, contactEmail)
}

var _ port.MessageEnqueuer = (*messageEnqueuerProxy)(nil)
