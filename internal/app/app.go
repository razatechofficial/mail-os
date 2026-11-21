// Package app runs the processes: the API server (REST, gRPC, metrics,
// with FEATURE_PUBSUB_INGEST the Kafka consumer, and with
// SMTP_SUBMISSION_ENABLED the SMTP submission listener) and the worker
// (asynq queues and schedules), each with graceful shutdown on
// SIGINT/SIGTERM.
package app

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/internal/container"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/metrics"
	"github.com/razatechofficial/mail-os/pkg/telemetry"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
	transporthttp "github.com/razatechofficial/mail-os/transport/http"
	"github.com/razatechofficial/mail-os/transport/http/e2ehooks"
	smtptransport "github.com/razatechofficial/mail-os/transport/smtp"
)

// Router builds the REST engine from the container.
func Router(c *container.Container) *gin.Engine {
	deps := transporthttp.Deps{
		Auth: c.Auth, Guard: c.Guard, Limiter: c.Redis,
		Ready:        func(g *gin.Context) error { return c.Ready(g.Request.Context()) },
		Public:       c.PublicRoutes,
		PlatformAuth: c.PlatformAuth, PlatformGuard: c.PlatformGuard, Platform: c.PlatformRoutes,
	}
	if c.E2ESink != nil {
		deps.Hooks = func(r *gin.Engine) { e2ehooks.Mount(r, c.Cfg.E2EHooks.Token, c.E2ESink, c.E2EZone) }
	}
	return transporthttp.NewRouter(c.Cfg, deps, c.Routes...)
}

// RunServer serves until a signal.
func RunServer(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	flush, err := startTelemetry(ctx, cfg, "mailos-server")
	if err != nil {
		return err
	}
	defer flush()
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

	var smtpSrv *smtptransport.Server
	if cfg.SMTPSubmission.Enabled {
		if smtpSrv, err = c.SMTPServer(); err != nil {
			return err
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(httpSrv.Start)
	g.Go(grpcSrv.Start)
	if smtpSrv != nil {
		g.Go(smtpSrv.Start)
	}
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
		// SMTP sessions finish their transaction while HTTP and gRPC drain.
		var wg sync.WaitGroup
		if smtpSrv != nil {
			wg.Go(func() {
				if err := smtpSrv.Shutdown(sctx); err != nil {
					logger.Warn("smtp submission shutdown", logger.Err(err))
				}
			})
		}
		grpcSrv.Stop()
		err := httpSrv.Shutdown(sctx)
		wg.Wait()
		return err
	})
	logger.Info("mailos server started", logger.String("env", cfg.App.Env))
	return g.Wait()
}

// RunWorker runs the queues until a signal.
func RunWorker(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	flush, err := startTelemetry(ctx, cfg, "mailos-worker")
	if err != nil {
		return err
	}
	defer flush()
	c, err := container.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	srv := worker.NewServer(c.RedisOpt, cfg.Worker)
	inspector := asynq.NewInspector(c.RedisOpt)
	defer inspector.Close()
	prometheus.MustRegister(worker.NewQueueCollector(inspector))
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

// startTelemetry exports the process's traces when TELEMETRY_ENABLED is
// on, and returns the flush to run at exit.
func startTelemetry(ctx context.Context, cfg *config.Config, service string) (func(), error) {
	shutdown, err := telemetry.Setup(ctx, cfg.Telemetry, service, cfg.App.Version)
	if err != nil {
		return nil, err
	}
	return func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(sctx); err != nil {
			logger.Warn("telemetry flush", logger.Err(err))
		}
	}, nil
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
