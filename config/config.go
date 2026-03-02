// Package config defines the application configuration structures and
// loading logic. Configuration is read from YAML files with environment
// variable overrides via cleanenv.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	App        App        `yaml:"app"`
	HTTP       HTTP       `yaml:"http"`
	GRPC       GRPC       `yaml:"grpc"`
	CORS       CORS       `yaml:"cors"`
	Postgres   Postgres   `yaml:"postgres"`
	Redis      Redis      `yaml:"redis"`
	Queue      Queue      `yaml:"queue"`
	SMTP       SMTP       `yaml:"smtp"`
	Encryption Encryption `yaml:"encryption"`
	RateLimit  RateLimit  `yaml:"rate_limit"`
	Worker     Worker     `yaml:"worker"`
}

// CORS holds allowed origins (comma-separated in env).
type CORS struct {
	Origins string `yaml:"origins" env:"CORS_ORIGINS" env-default:"http://localhost:3000,http://127.0.0.1:3000"`
}

// Origins returns the list of allowed origins, split by comma.
func (c CORS) OriginsList() []string {
	if c.Origins == "" {
		return []string{"*"}
	}
	parts := strings.Split(c.Origins, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

type App struct {
	Env      string `yaml:"env" env:"APP_ENV" env-default:"local"`
	LogLevel string `yaml:"log_level" env:"APP_LOG_LEVEL" env-default:"debug"`
}

// IsProduction returns true when the application is running in a production environment.
func (a App) IsProduction() bool {
	return a.Env == "production"
}

type HTTP struct {
	Host                 string        `yaml:"host" env:"HTTP_HOST" env-default:"0.0.0.0"`
	Port                 int           `yaml:"port" env:"HTTP_PORT" env-default:"8080"`
	ReadTimeout          time.Duration `yaml:"read_timeout" env:"HTTP_READ_TIMEOUT" env-default:"10s"`
	WriteTimeout         time.Duration `yaml:"write_timeout" env:"HTTP_WRITE_TIMEOUT" env-default:"5m"`
	IdleTimeout          time.Duration `yaml:"idle_timeout" env:"HTTP_IDLE_TIMEOUT" env-default:"60s"`
	BatchSendConcurrency int           `yaml:"batch_send_concurrency" env:"HTTP_BATCH_SEND_CONCURRENCY" env-default:"20"`
}

func (h HTTP) Addr() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

type GRPC struct {
	Host string `yaml:"host" env:"GRPC_HOST" env-default:"0.0.0.0"`
	Port int    `yaml:"port" env:"GRPC_PORT" env-default:"9090"`
}

func (g GRPC) Addr() string {
	return fmt.Sprintf("%s:%d", g.Host, g.Port)
}

type Postgres struct {
	Host     string `yaml:"host" env:"POSTGRES_HOST" env-default:"localhost"`
	Port     int    `yaml:"port" env:"POSTGRES_PORT" env-default:"5432"`
	User     string `yaml:"user" env:"POSTGRES_USER" env-default:"postgres"`
	Password string `yaml:"password" env:"POSTGRES_PASSWORD" env-default:""`
	Database string `yaml:"database" env:"POSTGRES_DB" env-default:"mail_os"`
	SSLMode  string `yaml:"ssl_mode" env:"POSTGRES_SSL_MODE" env-default:"disable"`
	MaxConns int32  `yaml:"max_conns" env:"POSTGRES_MAX_CONNS" env-default:"25"`
	MinConns int32  `yaml:"min_conns" env:"POSTGRES_MIN_CONNS" env-default:"5"`
}

func (p Postgres) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password, p.Host, p.Port, p.Database, p.SSLMode,
	)
}

type Redis struct {
	Host     string `yaml:"host" env:"REDIS_HOST" env-default:"localhost"`
	Port     int    `yaml:"port" env:"REDIS_PORT" env-default:"6379"`
	Password string `yaml:"password" env:"REDIS_PASSWORD" env-default:""`
	DB       int    `yaml:"db" env:"REDIS_DB" env-default:"0"`
}

func (r Redis) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

type Queue struct {
	Backend      string `yaml:"backend" env:"QUEUE_BACKEND" env-default:"pgqueue"`
	RabbitURL    string `yaml:"rabbit_url" env:"QUEUE_RABBIT_URL"`
	NatsURL      string `yaml:"nats_url" env:"QUEUE_NATS_URL"`
	KafkaBrokers string `yaml:"kafka_brokers" env:"QUEUE_KAFKA_BROKERS"`
}

type SMTP struct {
	Enabled  bool   `yaml:"enabled" env:"SMTP_ENABLED" env-default:"false"`
	Host     string `yaml:"host" env:"SMTP_HOST"`
	Port     int    `yaml:"port" env:"SMTP_PORT" env-default:"587"`
	Username string `yaml:"username" env:"SMTP_USERNAME"`
	Password string `yaml:"password" env:"SMTP_PASSWORD"`
	FromAddr string `yaml:"from_addr" env:"SMTP_FROM_ADDR"`
}

type Encryption struct {
	Key        string `yaml:"key" env:"ENCRYPTION_KEY"`
	HMACSecret string `yaml:"hmac_secret" env:"HMAC_SECRET"`
}

type RateLimit struct {
	PerOrg int `yaml:"per_org" env:"RATE_LIMIT_PER_ORG" env-default:"100"`
	Burst  int `yaml:"burst" env:"RATE_LIMIT_BURST" env-default:"20"`
}

type Worker struct {
	EmailConcurrency    int           `yaml:"email_concurrency" env:"WORKER_EMAIL_CONCURRENCY" env-default:"10"`
	CampaignConcurrency int           `yaml:"campaign_concurrency" env:"WORKER_CAMPAIGN_CONCURRENCY" env-default:"5"`
	StatsFlushInterval  time.Duration `yaml:"stats_flush_interval" env:"WORKER_STATS_FLUSH_INTERVAL" env-default:"10s"`
	SchedulerInterval   time.Duration `yaml:"scheduler_interval" env:"WORKER_SCHEDULER_INTERVAL" env-default:"30s"`
}

func Load(configPath string) (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{}

	if err := cleanenv.ReadConfig(configPath, cfg); err != nil {
		return nil, fmt.Errorf("config.Load: %w", err)
	}

	return cfg, nil
}
