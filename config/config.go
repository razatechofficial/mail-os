// Package config defines the typed configuration and its loading. Values come
// from environments/{APP_ENV}.yaml (or CONFIG_DIR) overridden by environment
// variables, then validate refuses settings that are unsafe for the
// environment: plaintext transports outside local and test, a missing master
// key, an IAM issuer that is not an https origin in production.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

// Config is the whole service configuration.
type Config struct {
	App          App          `yaml:"app"`
	HTTP         HTTP         `yaml:"http"`
	GRPC         GRPC         `yaml:"grpc"`
	CORS         CORS         `yaml:"cors"`
	Postgres     Postgres     `yaml:"postgres"`
	Redis        Redis        `yaml:"redis"`
	IAM          IAM          `yaml:"iam"`
	StepUp       StepUp       `yaml:"step_up"`
	Kafka        Kafka        `yaml:"kafka"`
	Audit        Audit        `yaml:"audit"`
	KeyManager   KeyManager   `yaml:"key_manager"`
	Retention    Retention    `yaml:"retention"`
	Worker       Worker       `yaml:"worker"`
	RateLimit    RateLimit    `yaml:"rate_limit"`
	SMTP         SMTP         `yaml:"smtp"`
	Telemetry    Telemetry    `yaml:"telemetry"`
	Metrics      Metrics      `yaml:"metrics"`
	E2EHooks     E2EHooks     `yaml:"e2e_hooks"`
	FeatureFlags FeatureFlags `yaml:"feature_flags"`
	Shutdown     Shutdown     `yaml:"shutdown"`
}

// App identifies the deployment.
type App struct {
	Name     string `yaml:"name" env:"APP_NAME" env-default:"mailos"`
	Env      string `yaml:"env" env:"APP_ENV" env-default:""`
	Version  string `yaml:"version" env:"APP_VERSION" env-default:"dev"`
	LogLevel string `yaml:"log_level" env:"APP_LOG_LEVEL" env-default:"info"`
	// LogFormat is json or console; production always logs JSON.
	LogFormat string `yaml:"log_format" env:"APP_LOG_FORMAT" env-default:"json"`
}

// IsProduction reports a production deployment.
func (a App) IsProduction() bool { return strings.EqualFold(a.Env, "production") }

// plaintextEnvironments are the only APP_ENV values in which MailOS serves or
// dials without TLS (contract §2: none of the transports falls back to
// plaintext outside local and test; e2e is the black-box test run).
var plaintextEnvironments = map[string]bool{"local": true, "test": true, "e2e": true}

// AllowsPlaintext reports whether plaintext transports are allowed.
func (a App) AllowsPlaintext() bool {
	return plaintextEnvironments[strings.ToLower(strings.TrimSpace(a.Env))]
}

// HTTP is the REST listener.
type HTTP struct {
	Host         string        `yaml:"host" env:"HTTP_HOST" env-default:"0.0.0.0"`
	Port         int           `yaml:"port" env:"HTTP_PORT" env-default:"8080"`
	ReadTimeout  time.Duration `yaml:"read_timeout" env:"HTTP_READ_TIMEOUT" env-default:"10s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"HTTP_WRITE_TIMEOUT" env-default:"60s"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" env:"HTTP_IDLE_TIMEOUT" env-default:"60s"`
	// MaxBodyBytes caps request bodies (0 = 2 MiB). Drafts carry up to 1 MiB
	// of HTML plus 512 KiB of design.
	MaxBodyBytes int64 `yaml:"max_body_bytes" env:"HTTP_MAX_BODY_BYTES" env-default:"0"`
	// TrustedProxies are the CIDRs whose X-Forwarded-For is believed.
	TrustedProxies []string  `yaml:"trusted_proxies" env:"HTTP_TRUSTED_PROXIES" env-separator:","`
	TLS            ServerTLS `yaml:"tls" env-prefix:"HTTP_TLS_"`
}

// Addr is host:port.
func (h HTTP) Addr() string { return fmt.Sprintf("%s:%d", h.Host, h.Port) }

// BodyLimit is MaxBodyBytes with its default.
func (h HTTP) BodyLimit() int64 {
	if h.MaxBodyBytes <= 0 {
		return 2 << 20
	}
	return h.MaxBodyBytes
}

// GRPC is the gRPC listener.
type GRPC struct {
	Host string    `yaml:"host" env:"GRPC_HOST" env-default:"0.0.0.0"`
	Port int       `yaml:"port" env:"GRPC_PORT" env-default:"9090"`
	TLS  ServerTLS `yaml:"tls" env-prefix:"GRPC_TLS_"`
}

// Addr is host:port.
func (g GRPC) Addr() string { return fmt.Sprintf("%s:%d", g.Host, g.Port) }

// CORS lists the browser origins allowed to call the API directly. The
// console calls through its BFF, so production normally lists none.
type CORS struct {
	Origins []string `yaml:"origins" env:"CORS_ORIGINS" env-separator:","`
}

// Postgres is the primary store.
type Postgres struct {
	Host     string `yaml:"host" env:"POSTGRES_HOST" env-default:"localhost"`
	Port     int    `yaml:"port" env:"POSTGRES_PORT" env-default:"5432"`
	User     string `yaml:"user" env:"POSTGRES_USER" env-default:"postgres"`
	Password string `yaml:"password" env:"POSTGRES_PASSWORD" env-default:""`
	Database string `yaml:"database" env:"POSTGRES_DB" env-default:"mail_os"`
	SSLMode  string `yaml:"ssl_mode" env:"POSTGRES_SSL_MODE" env-default:"disable"`
	MaxConns int32  `yaml:"max_conns" env:"POSTGRES_MAX_CONNS" env-default:"25"`
	MinConns int32  `yaml:"min_conns" env:"POSTGRES_MIN_CONNS" env-default:"2"`
}

// DSN is the pgx connection URL.
func (p Postgres) DSN() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(p.User, p.Password),
		Host:     fmt.Sprintf("%s:%d", p.Host, p.Port),
		Path:     p.Database,
		RawQuery: "sslmode=" + url.QueryEscape(p.SSLMode),
	}
	return u.String()
}

// Redis backs the asynq queues, the replay guards and rate limits.
type Redis struct {
	Host     string `yaml:"host" env:"REDIS_HOST" env-default:"localhost"`
	Port     int    `yaml:"port" env:"REDIS_PORT" env-default:"6379"`
	Password string `yaml:"password" env:"REDIS_PASSWORD" env-default:""`
	DB       int    `yaml:"db" env:"REDIS_DB" env-default:"0"`
	PoolSize int    `yaml:"pool_size" env:"REDIS_POOL_SIZE" env-default:"20"`
	// TLS dials Redis over TLS (required in production).
	TLS    bool   `yaml:"tls" env:"REDIS_TLS" env-default:"false"`
	CAFile string `yaml:"ca_file" env:"REDIS_TLS_CA_FILE" env-default:""`
}

// Addr is host:port.
func (r Redis) Addr() string { return fmt.Sprintf("%s:%d", r.Host, r.Port) }

// IAM is the identity provider whose tokens MailOS accepts (contract §1, §5).
type IAM struct {
	// Issuer is the IAM origin (RFC 8414); its discovery document names the JWKS.
	Issuer string `yaml:"issuer" env:"IAM_ISSUER" env-default:""`
	// Audience is MailOS's resource identifier: service tokens must carry
	// exactly it, user tokens it or one of ConsoleAudiences.
	Audience string `yaml:"audience" env:"IAM_AUDIENCE" env-default:"mailos"`
	// ConsoleAudiences are the MailOS console's OAuth client IDs. A console
	// user's access token is issued to that client, so its aud names it.
	ConsoleAudiences []string      `yaml:"console_audiences" env:"IAM_CONSOLE_AUDIENCES" env-separator:","`
	JWKSCacheTTL     time.Duration `yaml:"jwks_cache_ttl" env:"IAM_JWKS_CACHE_TTL" env-default:"10m"`
	ClockSkew        time.Duration `yaml:"clock_skew" env:"IAM_CLOCK_SKEW" env-default:"60s"`
	// CAFile verifies the IAM origin's certificate when it is not publicly trusted.
	CAFile string `yaml:"ca_file" env:"IAM_CA_FILE" env-default:""`
	// ServiceClients is the §4 allow-list: client_id=prefix|prefix[@tenant];...
	ServiceClients string `yaml:"service_clients" env:"MAILOS_SERVICE_CLIENTS" env-default:""`
}

// StepUp is the fresh-MFA rule for sensitive operations (contract §5).
type StepUp struct {
	MaxAge time.Duration `yaml:"max_age" env:"STEP_UP_MAX_AGE" env-default:"5m"`
	// ACR is the weakest sign-in that satisfies step-up.
	ACR string `yaml:"acr" env:"STEP_UP_ACR" env-default:"urn:iam:acr:mfa"`
}

// Kafka is the broker MailOS consumes signed IAM events from and, with the
// audit stream on, publishes its audit events to (contract §2).
type Kafka struct {
	Brokers []string `yaml:"brokers" env:"KAFKA_BROKERS" env-separator:","`
	GroupID string   `yaml:"group_id" env:"KAFKA_GROUP_ID" env-default:"mailos-events"`
	// Topics to consume; empty means every topic in the template catalogue.
	Topics []string  `yaml:"topics" env:"KAFKA_TOPICS" env-separator:","`
	TLS    ClientTLS `yaml:"tls" env-prefix:"KAFKA_TLS_"`
	SASL   SASL      `yaml:"sasl" env-prefix:"KAFKA_SASL_"`
}

// SASL mechanisms for Kafka.
const (
	SASLNone        = "none"
	SASLScramSHA512 = "SCRAM-SHA-512"
	SASLOAuthBearer = "OAUTHBEARER"
)

// SASL authenticates MailOS to the broker. OAUTHBEARER uses MailOS's own
// client credentials at IAM.
type SASL struct {
	Mechanism    string `yaml:"mechanism" env:"MECHANISM" env-default:"none"`
	Username     string `yaml:"username" env:"USERNAME" env-default:""`
	Password     string `yaml:"password" env:"PASSWORD" env-default:""`
	TokenURL     string `yaml:"token_url" env:"TOKEN_URL" env-default:""`
	ClientID     string `yaml:"client_id" env:"CLIENT_ID" env-default:""`
	ClientSecret string `yaml:"client_secret" env:"CLIENT_SECRET" env-default:""`
	Scope        string `yaml:"scope" env:"SCOPE" env-default:""`
}

// Audit is the audit log (contract §6).
type Audit struct {
	// StreamTopic is where FEATURE_AUDIT_STREAM publishes events for the SIEM.
	StreamTopic string `yaml:"stream_topic" env:"AUDIT_STREAM_TOPIC" env-default:"mailos.audit.events"`
	// RetentionDays keeps audit rows (PCI DSS 10.5.1: at least a year).
	RetentionDays int `yaml:"retention_days" env:"AUDIT_RETENTION_DAYS" env-default:"365"`
}

// KeyManager seals stored secrets with per-purpose data keys wrapped under
// a master key from Vault (IAM key-manager design).
type KeyManager struct {
	MasterKey                string        `yaml:"master_key" env:"KEY_MANAGER_MASTER_KEY" env-default:""`
	EncryptionRotationPeriod time.Duration `yaml:"encryption_rotation_period" env:"KEY_MANAGER_ENCRYPTION_ROTATION_PERIOD" env-default:"8760h"`
	ReencryptBatch           int           `yaml:"reencrypt_batch" env:"KEY_MANAGER_REENCRYPT_BATCH" env-default:"500"`
}

// Retention purges message bodies (contract §6: default 30 days).
type Retention struct {
	MessageDays   int           `yaml:"message_days" env:"MESSAGE_RETENTION_DAYS" env-default:"30"`
	PurgeInterval time.Duration `yaml:"purge_interval" env:"MESSAGE_RETENTION_INTERVAL" env-default:"1h"`
	PurgeBatch    int           `yaml:"purge_batch" env:"MESSAGE_RETENTION_BATCH" env-default:"1000"`
}

// Worker runs the asynq queues.
type Worker struct {
	Concurrency int `yaml:"concurrency" env:"WORKER_CONCURRENCY" env-default:"10"`
	// MaxRetry is how often a send is retried before the message fails.
	MaxRetry int `yaml:"max_retry" env:"WORKER_MAX_RETRY" env-default:"8"`
	// SendTimeout bounds one provider call.
	SendTimeout time.Duration `yaml:"send_timeout" env:"WORKER_SEND_TIMEOUT" env-default:"30s"`
	// SchedulerInterval is how often scheduled messages and campaigns are released.
	SchedulerInterval time.Duration `yaml:"scheduler_interval" env:"WORKER_SCHEDULER_INTERVAL" env-default:"30s"`
}

// RateLimit protects the API per tenant, and the costly template endpoints per user.
type RateLimit struct {
	Enabled          bool `yaml:"enabled" env:"RATE_LIMIT_ENABLED" env-default:"true"`
	PerTenant        int  `yaml:"per_tenant" env:"RATE_LIMIT_PER_TENANT" env-default:"100"`
	Burst            int  `yaml:"burst" env:"RATE_LIMIT_BURST" env-default:"50"`
	PreviewPerMinute int  `yaml:"preview_per_minute" env:"RATE_LIMIT_PREVIEW_PER_MINUTE" env-default:"60"`
	TestSendPerHour  int  `yaml:"test_send_per_hour" env:"RATE_LIMIT_TEST_SEND_PER_HOUR" env-default:"10"`
}

// SMTP TLS modes.
const (
	SMTPTLSStartTLS = "starttls"
	SMTPTLSImplicit = "implicit"
	SMTPTLSNone     = "none"
)

// SMTP is the platform's default relay, used when a tenant has no provider.
// Its password comes from Vault through the environment and is never stored.
type SMTP struct {
	Enabled  bool   `yaml:"enabled" env:"SMTP_ENABLED" env-default:"false"`
	Host     string `yaml:"host" env:"SMTP_HOST" env-default:""`
	Port     int    `yaml:"port" env:"SMTP_PORT" env-default:"587"`
	Username string `yaml:"username" env:"SMTP_USERNAME" env-default:""`
	Password string `yaml:"password" env:"SMTP_PASSWORD" env-default:""`
	TLSMode  string `yaml:"tls_mode" env:"SMTP_TLS_MODE" env-default:"starttls"`
	FromName string `yaml:"from_name" env:"SMTP_FROM_NAME" env-default:"MailOS"`
	FromAddr string `yaml:"from_addr" env:"SMTP_FROM_ADDR" env-default:""`
}

// Telemetry exports traces over OTLP/gRPC.
type Telemetry struct {
	Enabled      bool    `yaml:"enabled" env:"TELEMETRY_ENABLED" env-default:"false"`
	OTLPEndpoint string  `yaml:"otlp_endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT" env-default:""`
	Insecure     bool    `yaml:"insecure" env:"OTEL_EXPORTER_OTLP_INSECURE" env-default:"false"`
	SampleRatio  float64 `yaml:"sample_ratio" env:"TELEMETRY_SAMPLE_RATIO" env-default:"0.1"`
}

// Metrics serves Prometheus metrics on its own listener, reachable only by
// the scraper (NetworkPolicy), never through the API ingress.
type Metrics struct {
	Enabled bool   `yaml:"enabled" env:"METRICS_ENABLED" env-default:"true"`
	Addr    string `yaml:"addr" env:"METRICS_ADDR" env-default:":9102"`
}

// FeatureFlags switch new behaviour on per environment. Each is off by
// default and ships dark.
type FeatureFlags struct {
	// PubSubIngest consumes signed IAM events from Kafka.
	PubSubIngest bool `yaml:"pubsub_ingest" env:"FEATURE_PUBSUB_INGEST" env-default:"false"`
	// AuditStream publishes audit events to Kafka for the SIEM.
	AuditStream bool `yaml:"audit_stream" env:"FEATURE_AUDIT_STREAM" env-default:"false"`
	// RawHTMLBlocks lets administrators save sanitised raw HTML design nodes.
	RawHTMLBlocks bool `yaml:"raw_html_blocks" env:"FEATURE_RAW_HTML_BLOCKS" env-default:"false"`
}

// Shutdown bounds graceful shutdown.
type Shutdown struct {
	Timeout time.Duration `yaml:"timeout" env:"SHUTDOWN_TIMEOUT" env-default:"30s"`
}

// Load reads .env, environments/{APP_ENV}.yaml and the environment, then
// validates the result.
func Load() (*Config, error) {
	var cfg Config
	_ = godotenv.Load(".env")

	env := getEnvironment()
	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "environments"
	}
	configFile := filepath.Join(configDir, env+".yaml")
	if fileExists(configFile) {
		if err := cleanenv.ReadConfig(configFile, &cfg); err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", configFile, err)
		}
	}
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, fmt.Errorf("failed to read environment: %w", err)
	}
	if cfg.App.Env == "" {
		cfg.App.Env = env
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	return &cfg, nil
}

// getEnvironment detects the current environment, local when unset.
func getEnvironment() string {
	for _, key := range []string{"APP_ENV", "ENV", "ENVIRONMENT"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return "local"
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// Validate checks configuration for errors and security issues.
func (c *Config) Validate() error {
	plaintext := c.App.AllowsPlaintext()

	if err := c.HTTP.TLS.validate("HTTP", plaintext); err != nil {
		return err
	}
	if err := c.GRPC.TLS.validate("GRPC", plaintext); err != nil {
		return err
	}
	if c.HTTP.ReadTimeout < time.Second || c.HTTP.WriteTimeout < time.Second || c.HTTP.IdleTimeout < time.Second {
		return fmt.Errorf("http timeouts must be at least 1s")
	}
	const maxBody = 16 << 20
	if c.HTTP.MaxBodyBytes < 0 || c.HTTP.MaxBodyBytes > maxBody {
		return fmt.Errorf("HTTP_MAX_BODY_BYTES must be 0 (default 2 MiB) to 16 MiB")
	}

	if !plaintext {
		switch c.Postgres.SSLMode {
		case "require", "verify-ca", "verify-full":
		default:
			return fmt.Errorf("POSTGRES_SSL_MODE must be require, verify-ca or verify-full outside local and test")
		}
	}
	if c.Postgres.MaxConns < 1 || c.Postgres.MinConns < 0 || c.Postgres.MinConns > c.Postgres.MaxConns {
		return fmt.Errorf("postgres max_conns/min_conns must be valid (max >= 1, 0 <= min <= max)")
	}
	if c.Redis.PoolSize < 1 {
		return fmt.Errorf("REDIS_POOL_SIZE must be positive")
	}

	if c.App.IsProduction() {
		if strings.TrimSpace(c.Postgres.Password) == "" {
			return fmt.Errorf("POSTGRES_PASSWORD is required in production")
		}
		if !c.Redis.TLS {
			return fmt.Errorf("REDIS_TLS must be true in production")
		}
		for _, o := range c.CORS.Origins {
			if strings.TrimSpace(o) == "*" {
				return fmt.Errorf("CORS origin \"*\" is not allowed in production")
			}
		}
	}

	if err := validateIssuer(c.IAM.Issuer, c.App.IsProduction(), plaintext); err != nil {
		return err
	}
	if strings.TrimSpace(c.IAM.Audience) == "" {
		return fmt.Errorf("IAM_AUDIENCE is required")
	}
	if c.IAM.ClockSkew < 0 || c.IAM.ClockSkew > 5*time.Minute {
		return fmt.Errorf("IAM_CLOCK_SKEW must be between 0 and 5m")
	}
	if _, err := ParseServiceClients(c.IAM.ServiceClients); err != nil {
		return fmt.Errorf("MAILOS_SERVICE_CLIENTS: %w", err)
	}

	if c.StepUp.MaxAge < time.Minute || c.StepUp.MaxAge > 5*time.Minute {
		return fmt.Errorf("STEP_UP_MAX_AGE must be between 1m and 5m (contract §5)")
	}
	if strings.TrimSpace(c.StepUp.ACR) == "" {
		return fmt.Errorf("STEP_UP_ACR is required")
	}

	if err := c.KeyManager.validate(); err != nil {
		return err
	}
	if c.Retention.MessageDays < 1 || c.Retention.MessageDays > 3650 {
		return fmt.Errorf("MESSAGE_RETENTION_DAYS must be between 1 and 3650")
	}
	if c.Retention.PurgeInterval < time.Minute || c.Retention.PurgeBatch < 1 {
		return fmt.Errorf("MESSAGE_RETENTION_INTERVAL must be at least 1m and MESSAGE_RETENTION_BATCH positive")
	}
	if c.Audit.RetentionDays < 365 && c.App.IsProduction() {
		return fmt.Errorf("AUDIT_RETENTION_DAYS must be at least 365 in production (PCI DSS 10.5.1)")
	}
	if c.Worker.Concurrency < 1 || c.Worker.MaxRetry < 0 || c.Worker.SendTimeout < time.Second {
		return fmt.Errorf("worker concurrency, max_retry and send_timeout must be valid")
	}
	if c.RateLimit.Enabled && (c.RateLimit.PerTenant < 1 || c.RateLimit.Burst < 1 ||
		c.RateLimit.PreviewPerMinute < 1 || c.RateLimit.TestSendPerHour < 1) {
		return fmt.Errorf("rate limits must be positive when RATE_LIMIT_ENABLED is true")
	}

	if c.FeatureFlags.PubSubIngest || c.FeatureFlags.AuditStream {
		if err := c.Kafka.validate(plaintext); err != nil {
			return err
		}
	}
	if err := c.SMTP.validate(plaintext); err != nil {
		return err
	}
	if c.Telemetry.Enabled {
		if strings.TrimSpace(c.Telemetry.OTLPEndpoint) == "" {
			return fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT is required when TELEMETRY_ENABLED is true")
		}
		if c.Telemetry.Insecure && !plaintext {
			return fmt.Errorf("OTEL_EXPORTER_OTLP_INSECURE is refused outside local and test")
		}
	}
	if err := c.E2EHooks.validate(c.App.Env); err != nil {
		return err
	}
	if c.Shutdown.Timeout < time.Second {
		return fmt.Errorf("SHUTDOWN_TIMEOUT must be at least 1s")
	}
	return nil
}

// validateIssuer enforces RFC 8414: the issuer is an absolute origin, https
// outside local and test, and not loopback in production.
func validateIssuer(raw string, production, plaintext bool) error {
	iss := strings.TrimSpace(raw)
	if iss == "" {
		return fmt.Errorf("IAM_ISSUER is required (the IAM origin, RFC 8414)")
	}
	u, err := url.Parse(iss)
	if err != nil || u.Host == "" {
		return fmt.Errorf("IAM_ISSUER must be an absolute origin (https://host), got %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("IAM_ISSUER must not include userinfo, query, or fragment")
	}
	if path := strings.TrimRight(u.Path, "/"); path != "" {
		return fmt.Errorf("IAM_ISSUER must be an origin with no path, got %q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !plaintext {
			return fmt.Errorf("IAM_ISSUER must be https outside local and test")
		}
	default:
		return fmt.Errorf("IAM_ISSUER must be an http(s) origin")
	}
	if production {
		switch strings.ToLower(u.Hostname()) {
		case "localhost", "127.0.0.1", "::1", "0.0.0.0":
			return fmt.Errorf("IAM_ISSUER must not be loopback in production")
		}
	}
	return nil
}
