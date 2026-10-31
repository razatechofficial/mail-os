// Package app runs the processes: the API server (REST, gRPC, metrics and,
// with FEATURE_PUBSUB_INGEST, the Kafka consumer) and the worker (asynq
// queues and schedules), each with graceful shutdown on SIGINT/SIGTERM.
package app

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/internal/container"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/metrics"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
	transporthttp "github.com/razatechofficial/mail-os/transport/http"
	"github.com/razatechofficial/mail-os/transport/http/e2ehooks"
)

// Router builds the REST engine from the container.
func Router(c *container.Container) *gin.Engine {
	deps := transporthttp.Deps{
		Auth: c.Auth, Guard: c.Guard, Limiter: c.Redis,
		Ready: func(g *gin.Context) error { return c.Ready(g.Request.Context()) },
	}
	if c.E2ESink != nil {
		deps.Hooks = func(r *gin.Engine) { e2ehooks.Mount(r, c.Cfg.E2EHooks.Token, c.E2ESink) }
	}
	return transporthttp.NewRouter(c.Cfg, deps, c.Routes...)
}

// RunServer serves until a signal.
func RunServer(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	c, err := container.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()

	httpSrv, err := transporthttp.NewServer(cfg.HTTP, Router(c))
	if err != nil {
		return err
	}
	grpcSrv, err := grpctransport.NewServer(cfg.GRPC, c.GRPCAuth, cfg.Telemetry.Enabled)
	if err != nil {
		return err
	}
	for _, register := range c.GRPCServices {
		register(grpcSrv.Registrar())
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(httpSrv.Start)
	g.Go(grpcSrv.Start)
	if cfg.Metrics.Enabled {
		g.Go(func() error { return serveMetrics(gctx, cfg.Metrics.Addr) })
	}
	for _, consume := range c.Consumers {
		g.Go(func() error { return consume(gctx) })
	}
	g.Go(func() error {
		<-gctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), cfg.Shutdown.Timeout)
		defer cancel()
		logger.Info("shutting down")
		grpcSrv.Stop()
		return httpSrv.Shutdown(sctx)
	})
	logger.Info("mailos server started", logger.String("env", cfg.App.Env))
	return g.Wait()
}

// RunWorker runs the queues until a signal.
func RunWorker(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	c, err := container.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	srv := worker.NewServer(c.RedisOpt, cfg.Worker)
	for _, register := range c.Tasks {
		if err := register(srv); err != nil {
			return err
		}
	}
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return srv.Run(gctx) })
	if cfg.Metrics.Enabled {
		g.Go(func() error { return serveMetrics(gctx, cfg.Metrics.Addr) })
	}
	logger.Info("mailos worker started", logger.String("env", cfg.App.Env))
	return g.Wait()
}

func serveMetrics(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	s := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
