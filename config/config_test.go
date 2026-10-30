package config

import (
	"strings"
	"testing"
)

const testMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes

// productionEnv is a complete, valid production configuration.
func productionEnv() map[string]string {
	return map[string]string{
		"APP_ENV":                 "production",
		"CONFIG_DIR":              "testdata/none",
		"HTTP_TLS_CERT_FILE":      "/tls/tls.crt",
		"HTTP_TLS_KEY_FILE":       "/tls/tls.key",
		"GRPC_TLS_CERT_FILE":      "/tls/tls.crt",
		"GRPC_TLS_KEY_FILE":       "/tls/tls.key",
		"GRPC_TLS_CLIENT_AUTH":    "require",
		"GRPC_TLS_CLIENT_CA_FILE": "/tls/ca.crt",
		"POSTGRES_SSL_MODE":       "verify-full",
		"POSTGRES_PASSWORD":       "from-vault",
		"REDIS_TLS":               "true",
		"IAM_ISSUER":              "https://iam.example.com",
		"MAILOS_SERVICE_CLIENTS":  "mailos-iam=iam.*",
		"KEY_MANAGER_MASTER_KEY":  testMasterKey,
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
		{"wildcard topic grant", map[string]string{"MAILOS_SERVICE_CLIENTS": "mailos-iam=*"}, "topic pattern"},
		{"kafka plaintext", map[string]string{"FEATURE_PUBSUB_INGEST": "true", "KAFKA_BROKERS": "kafka:9093", "KAFKA_SASL_MECHANISM": "SCRAM-SHA-512", "KAFKA_SASL_USERNAME": "u", "KAFKA_SASL_PASSWORD": "p"}, "KAFKA_TLS_ENABLED"},
		{"kafka without SASL", map[string]string{"FEATURE_PUBSUB_INGEST": "true", "KAFKA_BROKERS": "kafka:9093", "KAFKA_TLS_ENABLED": "true"}, "KAFKA_SASL_MECHANISM"},
		{"smtp without TLS", map[string]string{"SMTP_ENABLED": "true", "SMTP_HOST": "relay", "SMTP_FROM_ADDR": "a@b.c", "SMTP_TLS_MODE": "none"}, "SMTP_TLS_MODE"},
		{"e2e hooks", map[string]string{"MAILOS_E2E_HOOKS": "true", "MAILOS_E2E_HOOKS_TOKEN": strings.Repeat("x", 40)}, "test-only"},
		{"redis without TLS", map[string]string{"REDIS_TLS": "false"}, "REDIS_TLS"},
		{"short audit retention", map[string]string{"AUDIT_RETENTION_DAYS": "90"}, "AUDIT_RETENTION_DAYS"},
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

func TestParseServiceClients(t *testing.T) {
	got, err := ParseServiceClients(" mailos-iam=iam.* ; core=bank.otp.*|bank.alert.sent@6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ClientID != "mailos-iam" || got[0].TopicPatterns[0] != "iam.*" ||
		got[1].Tenant != "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10" || len(got[1].TopicPatterns) != 2 {
		t.Fatalf("parsed %+v", got)
	}
	for _, bad := range []string{"=iam.*", "a=", "a=iam.*;a=bank.*", "a=iam.*@not-a-uuid", "a=IAM.*", "a=iam.**"} {
		if _, err := ParseServiceClients(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
