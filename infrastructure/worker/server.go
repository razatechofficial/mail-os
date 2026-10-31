// Package worker runs MailOS's background work on asynq (Redis), as IAM's
// workers do: the send queue with retries and jittered backoff, and the
// scheduled tasks (key manager tick, audit outbox relay, retention purges).
package worker

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"time"

	"github.com/hibiken/asynq"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/metrics"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
)

// Queues by priority: sends first, then scheduled maintenance.
const (
	QueueCritical = "critical" // transactional sends (OTP, password reset)
	QueueDefault  = "default"
	QueueLow      = "low" // campaigns and maintenance
)

// RedisOpt is the asynq connection, with TLS when REDIS_TLS is on.
func RedisOpt(cfg config.Redis) (asynq.RedisClientOpt, error) {
	opt := asynq.RedisClientOpt{
		Addr: cfg.Addr(), Password: cfg.Password, DB: cfg.DB, PoolSize: cfg.PoolSize,
		DialTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	if cfg.TLS {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}
		if cfg.CAFile != "" {
			pool, err := tlsconfig.LoadPool(cfg.CAFile)
			if err != nil {
				return opt, err
			}
			tc.RootCAs = pool
		}
		opt.TLSConfig = tc
	}
	return opt, nil
}

// Server is the asynq server and its scheduler.
type Server struct {
	srv   *asynq.Server
	mux   *asynq.ServeMux
	sched *asynq.Scheduler
}

// NewServer builds the server for cfg.
func NewServer(opt asynq.RedisClientOpt, cfg config.Worker) *Server {
	srv := asynq.NewServer(opt, asynq.Config{
		Concurrency:    cfg.Concurrency,
		Queues:         map[string]int{QueueCritical: 6, QueueDefault: 3, QueueLow: 1},
		Logger:         logger.Asynq(),
		RetryDelayFunc: RetryDelay,
		// Shutdown waits for sends in flight (bounded by the send timeout).
		ShutdownTimeout: cfg.SendTimeout + 5*time.Second,
	})
	mux := asynq.NewServeMux()
	mux.Use(metricsMiddleware)
	return &Server{srv: srv, mux: mux, sched: asynq.NewScheduler(opt, &asynq.SchedulerOpts{Logger: logger.Asynq()})}
}

// Handle registers a task handler.
func (s *Server) Handle(typ string, h asynq.Handler) { s.mux.Handle(typ, h) }

// HandleFunc registers a task function.
func (s *Server) HandleFunc(typ string, f func(context.Context, *asynq.Task) error) {
	s.mux.HandleFunc(typ, f)
}

// Every schedules a payload-less task on a cron spec ("@every 1m"). The
// task is unique for its interval, so replicas do not pile up copies.
func (s *Server) Every(spec, typ string, unique time.Duration) error {
	_, err := s.sched.Register(spec, asynq.NewTask(typ, nil), asynq.Queue(QueueLow), asynq.Unique(unique), asynq.MaxRetry(0))
	return err
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	if err := s.sched.Start(); err != nil {
		return err
	}
	if err := s.srv.Start(s.mux); err != nil {
		s.sched.Shutdown()
		return err
	}
	<-ctx.Done()
	s.sched.Shutdown()
	s.srv.Shutdown()
	return nil
}

func metricsMiddleware(next asynq.Handler) asynq.Handler {
	return asynq.HandlerFunc(func(ctx context.Context, t *asynq.Task) error {
		err := next.ProcessTask(ctx, t)
		result := "ok"
		if err != nil {
			result = "error"
			if errors.Is(err, asynq.SkipRetry) {
				result = "dropped"
			}
		}
		metrics.Task(t.Type(), result)
		return err
	})
}

// RetryAfter lets a handler ask for a specific delay (a provider's
// Retry-After) instead of the backoff.
type RetryAfter interface{ RetryAfter() time.Duration }

// RetryDelay is exponential backoff from 10 s doubling to at most 1 h, with
// ±20% jitter from crypto/rand so retries of a provider outage do not
// arrive together. A provider's Retry-After wins when it is longer.
func RetryDelay(n int, err error, _ *asynq.Task) time.Duration {
	d := Backoff(10*time.Second, n+1, time.Hour)
	var ra RetryAfter
	if errors.As(err, &ra) && ra.RetryAfter() > d {
		return min(ra.RetryAfter(), time.Hour)
	}
	return d
}

// Backoff is base doubled n-1 times, capped, with ±20% jitter.
func Backoff(base time.Duration, n int, cap time.Duration) time.Duration {
	d := base
	for i := 1; i < n && d < cap; i++ {
		d *= 2
	}
	d = min(d, cap)
	return d + time.Duration((unitRandom()*0.4-0.2)*float64(d))
}

func unitRandom() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

// Enqueuer queues tasks.
type Enqueuer struct {
	client *asynq.Client
}

// NewEnqueuer connects the client.
func NewEnqueuer(opt asynq.RedisClientOpt) *Enqueuer { return &Enqueuer{client: asynq.NewClient(opt)} }

// Enqueue queues typ with payload.
func (e *Enqueuer) Enqueue(ctx context.Context, typ string, payload []byte, opts ...asynq.Option) error {
	_, err := e.client.EnqueueContext(ctx, asynq.NewTask(typ, payload), opts...)
	if errors.Is(err, asynq.ErrTaskIDConflict) || errors.Is(err, asynq.ErrDuplicateTask) {
		return nil
	}
	return err
}

// Close releases the client.
func (e *Enqueuer) Close() error { return e.client.Close() }
