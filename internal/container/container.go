package container

import (
	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/postgres"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/rediscache"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

type Container struct {
	cfg   *config.Config
	DB    *postgres.Pool
	Redis *rediscache.Client
	Pub   port.Publisher
	Con   port.Consumer

	Repos        *Repositories
	Adapters     *Adapters
	Services     *Services
	HTTPHandlers *HTTPHandlers
	GRPCHandlers *GRPCHandlers
	Workers      *Workers
}

func New(cfg *config.Config, db *postgres.Pool, redis *rediscache.Client, pub port.Publisher, con port.Consumer) *Container {
	c := &Container{cfg: cfg, DB: db, Redis: redis, Pub: pub, Con: con}

	c.Repos = c.buildRepositories()
	c.Adapters = c.buildAdapters()
	c.Services = c.buildServices()
	c.HTTPHandlers = c.buildHTTPHandlers()
	c.GRPCHandlers = c.buildGRPCHandlers()
	c.Workers = c.buildWorkers()

	logger.Info("container initialized successfully")
	return c
}
