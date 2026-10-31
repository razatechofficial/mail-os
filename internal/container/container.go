// Package container is the composition root: it builds the infrastructure,
// the use cases and the transport handlers by constructor injection. It is
// wiring only; nothing here decides behaviour.
package container

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hibiken/asynq"
	grpclib "google.golang.org/grpc"

	"github.com/razatechofficial/mail-os/application/auditlog"
	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/application/tenant"
	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/cache/redis"
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/infrastructure/kafka"
	infrakm "github.com/razatechofficial/mail-os/infrastructure/keymanager"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
	transporthttp "github.com/razatechofficial/mail-os/transport/http"
	"github.com/razatechofficial/mail-os/transport/http/handler"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

// Container holds everything the server and the worker run.
type Container struct {
	Cfg      *config.Config
	DB       *postgres.Pool
	Redis    *redis.Client
	RedisOpt asynq.RedisClientOpt
	Enqueuer *worker.Enqueuer

	AuditRepo  *postgres.AuditRepository
	Audit      *audit.Writer
	Keys       *appkm.Service
	Verifier   *jwt.Verifier
	Grants     access.ServiceGrants
	Tenants    *tenant.Service
	TenantRepo *postgres.TenantRepository
	// Templates resolves published template versions for sends.
	Templates *apptemplate.Service

	Auth     *middleware.Auth
	Guard    middleware.Guard
	GRPCAuth *grpctransport.Auth

	// Platform is the default sender (the platform relay, or the e2e sink).
	Platform mailer.Sender
	// E2ESink is set when the test-only hooks are on.
	E2ESink *mailer.E2ESink
	// AuditStream publishes the audit outbox (FEATURE_AUDIT_STREAM).
	AuditStream *kafka.Producer

	// Routes are the REST route sets; GRPCServices register on the gRPC
	// server; Tasks register worker handlers and schedules; Consumers run
	// in the server process (FEATURE_PUBSUB_INGEST).
	Routes       []transporthttp.Routes
	GRPCServices []func(*grpclib.Server)
	Tasks        []func(*worker.Server) error
	Consumers    []func(ctx context.Context) error
	closers      []func()
}

// New builds the container.
func New(ctx context.Context, cfg *config.Config) (*Container, error) {
	c := &Container{Cfg: cfg}
	if err := c.buildInfrastructure(ctx); err != nil {
		c.Close()
		return nil, err
	}
	for _, build := range []func(context.Context) error{
		c.buildCore,
		c.buildTemplates,
	} {
		if err := build(ctx); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

func (c *Container) buildInfrastructure(ctx context.Context) error {
	cfg := c.Cfg
	db, err := postgres.NewConnection(ctx, cfg)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	c.DB = db
	c.closers = append(c.closers, db.Close)

	rdb, err := redis.NewClient(cfg.Redis)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	c.Redis = rdb
	c.closers = append(c.closers, func() { _ = rdb.Close() })
	if c.RedisOpt, err = worker.RedisOpt(cfg.Redis); err != nil {
		return err
	}
	c.Enqueuer = worker.NewEnqueuer(c.RedisOpt)
	c.closers = append(c.closers, func() { _ = c.Enqueuer.Close() })

	c.AuditRepo = postgres.NewAuditRepository(db)
	c.Audit = audit.NewWriter(c.AuditRepo, cfg.FeatureFlags.AuditStream)
	if cfg.FeatureFlags.AuditStream {
		if c.AuditStream, err = kafka.NewProducer(cfg.Kafka); err != nil {
			return fmt.Errorf("audit stream: %w", err)
		}
		c.closers = append(c.closers, c.AuditStream.Close)
	}

	provider, err := infrakm.NewSoftwareProvider(cfg.KeyManager.MasterKey)
	if err != nil {
		return err
	}
	c.Keys = appkm.New(provider, postgres.NewEncryptionKeyRepository(db), c.Audit, appkm.Config{
		RotationPeriod: cfg.KeyManager.EncryptionRotationPeriod, ReencryptBatch: cfg.KeyManager.ReencryptBatch,
	})

	httpClient := &http.Client{Timeout: 5 * time.Second}
	if cfg.IAM.CAFile != "" {
		tc, err := tlsconfig.NewClient(tlsconfig.Client{CAFile: cfg.IAM.CAFile})
		if err != nil {
			return fmt.Errorf("IAM_CA_FILE: %w", err)
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: tc}
	}
	c.Verifier = jwt.NewVerifier(jwt.Config{Issuer: cfg.IAM.Issuer, Audience: cfg.IAM.Audience,
		ConsoleAudiences: cfg.IAM.ConsoleAudiences, CacheTTL: cfg.IAM.JWKSCacheTTL, ClockSkew: cfg.IAM.ClockSkew, HTTPClient: httpClient})

	clients, err := config.ParseServiceClients(cfg.IAM.ServiceClients)
	if err != nil {
		return err
	}
	grants := make([]access.ServiceGrant, 0, len(clients))
	for _, sc := range clients {
		grants = append(grants, access.ServiceGrant{ClientID: sc.ClientID, TopicPatterns: sc.TopicPatterns, Tenant: sc.Tenant})
	}
	c.Grants = access.NewServiceGrants(grants)

	if cfg.E2EHooks.Enabled {
		c.E2ESink = mailer.NewE2ESink(rdb.Client)
		c.Platform = c.E2ESink
	} else {
		relay, err := mailer.NewPlatformSMTP(cfg.SMTP, cfg.App.AllowsPlaintext(), mailer.Options{AllowPlaintext: cfg.App.AllowsPlaintext()})
		if err != nil {
			return fmt.Errorf("platform smtp: %w", err)
		}
		if relay != nil {
			c.Platform = relay
		}
	}
	return nil
}

// buildCore wires tenants, authentication, the audit log and the key
// manager's routes and schedule.
func (c *Container) buildCore(ctx context.Context) error {
	cfg := c.Cfg
	if err := c.Keys.Bootstrap(ctx); err != nil {
		return fmt.Errorf("key manager: %w", err)
	}
	c.TenantRepo = postgres.NewTenantRepository(c.DB)
	c.Tenants = tenant.NewService(c.TenantRepo, c.Audit, time.Minute)
	c.Auth = &middleware.Auth{
		Verifier: c.Verifier, DPoP: dpop.NewVerifier(c.Redis, time.Minute), Tenants: c.Tenants, Audit: c.Audit,
		TrustForwarded: len(cfg.HTTP.TrustedProxies) > 0,
	}
	c.Guard = middleware.Guard{StepUp: access.StepUpPolicy{MaxAge: cfg.StepUp.MaxAge, ACR: cfg.StepUp.ACR}, Audit: c.Audit}
	c.GRPCAuth = &grpctransport.Auth{Verifier: c.Verifier}

	c.Routes = append(c.Routes,
		handler.NewTenantHandler(c.Tenants, c.TenantRepo, c.Keys),
		handler.NewAuditLogHandler(auditlog.NewService(c.AuditRepo, c.Audit)),
	)
	c.Tasks = append(c.Tasks, func(s *worker.Server) error {
		s.HandleFunc(worker.TypeKeyManagerTick, worker.KeyManagerTick(c.Keys))
		s.HandleFunc(worker.TypeAuditRetention, worker.AuditRetention(c.AuditRepo, cfg.Audit.RetentionDays))
		if err := s.Every("@every 1m", worker.TypeKeyManagerTick, 50*time.Second); err != nil {
			return err
		}
		if err := s.Every("@every 1h", worker.TypeAuditRetention, 50*time.Minute); err != nil {
			return err
		}
		if c.AuditStream != nil {
			s.HandleFunc(worker.TypeAuditOutboxRelay, worker.AuditOutboxRelay(c.AuditRepo, c.AuditStream, cfg.Audit.StreamTopic))
			return s.Every("@every 5s", worker.TypeAuditOutboxRelay, 4*time.Second)
		}
		return nil
	})
	return nil
}

// Ready checks Postgres and Redis.
func (c *Container) Ready(ctx context.Context) error {
	if err := c.DB.Health(ctx); err != nil {
		return err
	}
	return c.Redis.Health(ctx)
}

// Close releases everything, last opened first.
func (c *Container) Close() {
	for i := len(c.closers) - 1; i >= 0; i-- {
		c.closers[i]()
	}
	c.closers = nil
}
