// Package app wires infrastructure, DI container, and transport servers
// into a single application lifecycle with concurrent startup and
// graceful shutdown.
package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/grpc"
	grpcinterceptor "github.com/razatechofficial/mail-os/internal/adapter/inbound/grpc/interceptor"
	inhttp "github.com/razatechofficial/mail-os/internal/adapter/inbound/http"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/middleware"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/postgres"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/queue"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/rediscache"
	"github.com/razatechofficial/mail-os/internal/container"
	"github.com/razatechofficial/mail-os/pkg/logger"
	grpclib "google.golang.org/grpc"
)

type App struct {
	cfg       *config.Config
	http      *inhttp.Server
	grpc      *grpc.Server
	db        *postgres.Pool
	redis     *rediscache.Client
	container *container.Container
}

func New(cfg *config.Config) (*App, error) {
	ctx := context.Background()

	db, err := postgres.NewConnection(ctx, cfg.Postgres.DSN(), cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if err != nil {
		return nil, fmt.Errorf("app.New: postgres: %w", err)
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
		return nil, fmt.Errorf("app.New: queue: %w", err)
	}
	logger.Info("queue initialized", logger.String("backend", cfg.Queue.Backend))

	c := container.New(cfg, db, redis, pub, con)

	httpServer := inhttp.NewServer(
		cfg.HTTP.Addr(),
		cfg.HTTP.ReadTimeout,
		cfg.HTTP.WriteTimeout,
		cfg.HTTP.IdleTimeout,
	)

	handlers := inhttp.Handlers(*c.HTTPHandlers)
	httpServer.RegisterRoutes(&handlers,
		middleware.Recovery(),
		middleware.RequestID(),
		middleware.Logging(),
		middleware.CORS([]string{"*"}),
		middleware.Auth(c.Services.APIKey),
	)

	grpcServer := grpc.NewServer(
		cfg.GRPC.Addr(),
		grpclib.ChainUnaryInterceptor(
			grpcinterceptor.RecoveryUnary(),
			grpcinterceptor.LoggingUnary(),
			grpcinterceptor.AuthUnary(c.Services.APIKey),
		),
	)

	return &App{
		cfg:       cfg,
		http:      httpServer,
		grpc:      grpcServer,
		db:        db,
		redis:     redis,
		container: c,
	}, nil
}

func (a *App) Start() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return a.http.Start() })
	g.Go(func() error { return a.grpc.Start() })

	g.Go(func() error {
		<-ctx.Done()
		return a.shutdown()
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("app.Start: %w", err)
	}
	return nil
}

func (a *App) shutdown() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger.Info("shutting down...")

	a.grpc.Shutdown()

	if err := a.http.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown error", logger.Err(err))
	}

	if err := a.redis.Close(); err != nil {
		logger.Error("redis close error", logger.Err(err))
	}

	a.db.Close()

	logger.Info("shutdown complete")
	return nil
}
