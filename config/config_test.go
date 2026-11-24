package config

import (
	"strings"
	"testing"
)

const testMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes

// productionEnv is a complete, valid production configuration.
func productionEnv() map[string]string {
	return map[string]string{
		"APP_ENV":                  "production",
		"CONFIG_DIR":               "testdata/none",
		"HTTP_TLS_CERT_FILE":       "/tls/tls.crt",
		"HTTP_TLS_KEY_FILE":        "/tls/tls.key",
		"GRPC_TLS_CERT_FILE":       "/tls/tls.crt",
		"GRPC_TLS_KEY_FILE":        "/tls/tls.key",
		"GRPC_TLS_CLIENT_AUTH":     "require",
		"GRPC_TLS_CLIENT_CA_FILE":  "/tls/ca.crt",
		"POSTGRES_SSL_MODE":        "verify-full",
		"POSTGRES_PASSWORD":        "from-vault",
		"REDIS_TLS":                "true",
		"IAM_ISSUER":               "https://iam.example.com",
		"IAM_SERVICE_CLIENT_ID":    "mailos-iam",
		"IAM_SERVICE_TENANT_ID":    "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10",
		"KEY_MANAGER_MASTER_KEY":   testMasterKey,
		"AUDIT_DIGEST_SIGNING_KEY": testMasterKey,
	}
}

func load(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	return Load()
}

func TestLoadProduction(t *testing.T) {
	cfg, err := load(t, productionEnv())
	if err != nil {
		t.Fatalf("valid production config refused: %v", err)
	}
	if cfg.IAM.Audience != "mailos" || cfg.StepUp.MaxAge.Minutes() != 5 || cfg.Retention.MessageDays != 30 {
		t.Fatalf("defaults: %+v %+v %+v", cfg.IAM, cfg.StepUp, cfg.Retention)
	}
	if cfg.FeatureFlags.PubSubIngest || cfg.FeatureFlags.AuditStream || cfg.FeatureFlags.RawHTMLBlocks {
		t.Fatal("feature flags must be off by default")
	}
}

// Every unsafe production setting is refused at startup.
func TestLoadRefusesUnsafeProduction(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"plaintext HTTP", map[string]string{"HTTP_TLS_CERT_FILE": "", "HTTP_TLS_KEY_FILE": ""}, "HTTP_TLS_CERT_FILE"},
		{"plaintext gRPC", map[string]string{"GRPC_TLS_CERT_FILE": "", "GRPC_TLS_KEY_FILE": "", "GRPC_TLS_CLIENT_AUTH": "none", "GRPC_TLS_CLIENT_CA_FILE": ""}, "GRPC_TLS_CERT_FILE"},
		{"mTLS without CA", map[string]string{"GRPC_TLS_CLIENT_CA_FILE": ""}, "mutual TLS"},
		{"database without TLS", map[string]string{"POSTGRES_SSL_MODE": "disable"}, "POSTGRES_SSL_MODE"},
		{"http issuer", map[string]string{"IAM_ISSUER": "http://iam.example.com"}, "https"},
		{"issuer with path", map[string]string{"IAM_ISSUER": "https://iam.example.com/realms/x"}, "no path"},
		{"loopback issuer", map[string]string{"IAM_ISSUER": "https://localhost"}, "loopback"},
		{"no master key", map[string]string{"KEY_MANAGER_MASTER_KEY": ""}, "KEY_MANAGER_MASTER_KEY"},
		{"short master key", map[string]string{"KEY_MANAGER_MASTER_KEY": "c2hvcnQ="}, "KEY_MANAGER_MASTER_KEY"},
		{"stale step-up", map[string]string{"STEP_UP_MAX_AGE": "15m"}, "STEP_UP_MAX_AGE"},
		{"wildcard topic grant", map[string]string{"IAM_SERVICE_TOPICS": "*"}, "topic pattern"},
		{"raw for IAM", map[string]string{"IAM_SERVICE_TOPICS": "iam.*,raw"}, "topic pattern"},
		{"no IAM client", map[string]string{"IAM_SERVICE_CLIENT_ID": "", "IAM_SERVICE_TENANT_ID": ""}, "IAM_SERVICE_CLIENT_ID"},
		{"IAM client without tenant", map[string]string{"IAM_SERVICE_TENANT_ID": ""}, "set together"},
		{"IAM tenant not a UUID", map[string]string{"IAM_SERVICE_TENANT_ID": "bank"}, "not a UUID"},
		{"idempotency for a month", map[string]string{"IDEMPOTENCY_KEY_TTL": "720h"}, "IDEMPOTENCY_KEY_TTL"},
		{"kafka plaintext", map[string]string{"FEATURE_PUBSUB_INGEST": "true", "KAFKA_BROKERS": "kafka:9093", "KAFKA_SASL_MECHANISM": "SCRAM-SHA-512", "KAFKA_SASL_USERNAME": "u", "KAFKA_SASL_PASSWORD": "p"}, "KAFKA_TLS_ENABLED"},
		{"kafka without SASL", map[string]string{"FEATURE_PUBSUB_INGEST": "true", "KAFKA_BROKERS": "kafka:9093", "KAFKA_TLS_ENABLED": "true"}, "KAFKA_SASL_MECHANISM"},
		{"smtp without TLS", map[string]string{"SMTP_ENABLED": "true", "SMTP_HOST": "relay", "SMTP_FROM_ADDR": "a@b.c", "SMTP_TLS_MODE": "none"}, "SMTP_TLS_MODE"},
		{"e2e hooks", map[string]string{"MAILOS_E2E_HOOKS": "true", "MAILOS_E2E_HOOKS_TOKEN": strings.Repeat("x", 40)}, "test-only"},
		{"redis without TLS", map[string]string{"REDIS_TLS": "false"}, "REDIS_TLS"},
		{"short audit retention", map[string]string{"AUDIT_RETENTION_DAYS": "90"}, "AUDIT_RETENTION_DAYS"},
		{"unsigned audit log", map[string]string{"AUDIT_DIGEST_SIGNING_KEY": ""}, "AUDIT_DIGEST_SIGNING_KEY"},
		{"message retention past 90 days", map[string]string{"MESSAGE_RETENTION_DAYS": "91"}, "MESSAGE_RETENTION_DAYS"},
		{"secret kept past 24 h", map[string]string{"MESSAGE_SECRET_TTL": "24h1m"}, "MESSAGE_SECRET_TTL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := productionEnv()
			for k, v := range c.set {
				env[k] = v
			}
			_, err := load(t, env)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// Local and test runs may use plaintext, but never without the master key.
func TestLoadLocalAllowsPlaintext(t *testing.T) {
	_, err := load(t, map[string]string{
		"APP_ENV": "local", "CONFIG_DIR": "testdata/none",
		"IAM_ISSUER": "http://127.0.0.1:8080", "KEY_MANAGER_MASTER_KEY": testMasterKey,
	})
	if err != nil {
		t.Fatalf("local config refused: %v", err)
	}
	t.Setenv("KEY_MANAGER_MASTER_KEY", "")
	if _, err := Load(); err == nil {
		t.Fatal("local config without a master key accepted")
	}
}

func TestStagingIsNotPlaintext(t *testing.T) {
	_, err := load(t, map[string]string{
		"APP_ENV": "staging", "CONFIG_DIR": "testdata/none",
		"IAM_ISSUER": "https://iam.example.com", "KEY_MANAGER_MASTER_KEY": testMasterKey,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP_TLS_CERT_FILE") {
		t.Fatalf("staging without TLS: %v", err)
	}
}

// The system application defaults to IAM's topics.
func TestSystemApplicationDefaults(t *testing.T) {
	cfg, err := load(t, productionEnv())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IAM.ServiceTopics) != 1 || cfg.IAM.ServiceTopics[0] != "iam.*" || cfg.Idempotency.TTL.Hours() != 24 {
		t.Fatalf("%+v %+v", cfg.IAM, cfg.Idempotency)
	}
}

// ACS is optional (the platform API answers 503 without it); configured,
// it needs MailOS's client certificate and an https token endpoint, and
// plaintext only where the deployment allows it.
func TestACS(t *testing.T) {
	acs := map[string]string{"ACS_ENDPOINT": "acs.internal:9443", "ACS_CLIENT_ID": "mailos-acs",
		"ACS_TOKEN_URL": "https://iam.example.com/oauth/token", "ACS_CERT_FILE": "/tls/acs.crt", "ACS_KEY_FILE": "/tls/acs.key",
		"PLATFORM_CLIENT_IDS": "6f1d0c2a-4b7e-4d8a-9a51-3c2e7f0b9d14"}
	with := func(base map[string]string, set map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range set {
			out[k] = v
		}
		return out
	}
	cfg, err := load(t, productionEnv())
	if err != nil || cfg.ACS.Enabled() {
		t.Fatalf("ACS is optional: %v %+v", err, cfg.ACS)
	}
	cfg, err = load(t, with(productionEnv(), acs))
	if err != nil || !cfg.ACS.Enabled() || cfg.ACS.Timeout.Seconds() != 3 || cfg.ACS.Insecure {
		t.Fatalf("configured ACS: %v %+v", err, cfg.ACS)
	}
	for name, c := range map[string]struct {
		set  map[string]string
		want string
	}{
		"endpoint without port":  {map[string]string{"ACS_ENDPOINT": "acs.internal"}, "host:port"},
		"no client":              {map[string]string{"ACS_CLIENT_ID": ""}, "ACS_CLIENT_ID"},
		"no token endpoint":      {map[string]string{"ACS_TOKEN_URL": ""}, "ACS_TOKEN_URL"},
		"plaintext token":        {map[string]string{"ACS_TOKEN_URL": "http://iam.example.com/oauth/token"}, "https"},
		"no client certificate":  {map[string]string{"ACS_KEY_FILE": ""}, "ACS_CERT_FILE"},
		"insecure in production": {map[string]string{"ACS_INSECURE": "true"}, "ACS_INSECURE"},
		"timeout":                {map[string]string{"ACS_TIMEOUT": "1m"}, "ACS_TIMEOUT"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, with(with(productionEnv(), acs), c.set))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	t.Run("insecure locally", func(t *testing.T) {
		_, err := load(t, map[string]string{"APP_ENV": "local", "CONFIG_DIR": "testdata/none", "IAM_ISSUER": "http://127.0.0.1:8080",
			"KEY_MANAGER_MASTER_KEY": testMasterKey, "ACS_ENDPOINT": "127.0.0.1:9090", "ACS_CLIENT_ID": "mailos-acs",
			"ACS_TOKEN_URL": "http://127.0.0.1:8080/oauth/token", "ACS_INSECURE": "true", "PLATFORM_CLIENT_IDS": "mailos-platform-console"})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// The platform sign-in rule (contract C2): with the platform API on
// (ACS_ENDPOINT), the platform console's client is required and may not
// be a workspace console client; the sign-in may be at most 8 hours old.
func TestPlatformSignIn(t *testing.T) {
	acs := map[string]string{"ACS_ENDPOINT": "acs.internal:9443", "ACS_CLIENT_ID": "mailos-acs",
		"ACS_TOKEN_URL": "https://iam.example.com/oauth/token", "ACS_CERT_FILE": "/tls/acs.crt", "ACS_KEY_FILE": "/tls/acs.key"}
	env := func(sets ...map[string]string) map[string]string {
		out := productionEnv()
		for _, set := range sets {
			for k, v := range set {
				out[k] = v
			}
		}
		return out
	}
	cfg, err := load(t, env())
	if err != nil || cfg.Platform.MaxAge.Hours() != 8 || len(cfg.Platform.AllowedClients()) != 0 {
		t.Fatalf("platform API off: %v %+v", err, cfg.Platform)
	}
	cfg, err = load(t, env(acs, map[string]string{"PLATFORM_CLIENT_IDS": " pc-1 , ,pc-2", "PLATFORM_AUTH_MAX_AGE": "4h"}))
	if err != nil || strings.Join(cfg.Platform.AllowedClients(), "|") != "pc-1|pc-2" || cfg.Platform.MaxAge.Hours() != 4 {
		t.Fatalf("configured: %v %+v", err, cfg.Platform)
	}
	for name, c := range map[string]struct {
		set  map[string]string
		want string
	}{
		"no client with ACS":    {map[string]string{"PLATFORM_CLIENT_IDS": ""}, "PLATFORM_CLIENT_IDS"},
		"blank clients":         {map[string]string{"PLATFORM_CLIENT_IDS": " , "}, "PLATFORM_CLIENT_IDS"},
		"a workspace client":    {map[string]string{"PLATFORM_CLIENT_IDS": "pc-1,Console-1", "IAM_CONSOLE_AUDIENCES": "console-1"}, "IAM_CONSOLE_AUDIENCES"},
		"longer than a session": {map[string]string{"PLATFORM_CLIENT_IDS": "pc-1", "PLATFORM_AUTH_MAX_AGE": "9h"}, "PLATFORM_AUTH_MAX_AGE"},
		"too short":             {map[string]string{"PLATFORM_CLIENT_IDS": "pc-1", "PLATFORM_AUTH_MAX_AGE": "30s"}, "PLATFORM_AUTH_MAX_AGE"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, env(acs, c.set))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
