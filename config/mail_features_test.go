package config

import (
	"strings"
	"testing"
)

func TestUnsubscribeAndAttachmentDefaults(t *testing.T) {
	cfg, err := load(t, productionEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Unsubscribe.Enabled() {
		t.Fatal("unsubscribe links must be off without a base URL")
	}
	a := cfg.Attachments
	if a.MaxBytes != 5<<20 || a.MaxTotalBytes != 10<<20 || a.MaxCount != 10 {
		t.Fatalf("attachment defaults: %+v", a)
	}
	if cfg.GRPC.RecvLimit() != 4<<20 {
		t.Fatalf("gRPC receive limit %d", cfg.GRPC.RecvLimit())
	}
}

func TestGRPCRecvLimit(t *testing.T) {
	env := productionEnv()
	env["GRPC_MAX_RECV_BYTES"] = "16777216"
	cfg, err := load(t, env)
	if err != nil || cfg.GRPC.RecvLimit() != 16<<20 {
		t.Fatalf("limit %v %v", cfg, err)
	}
	env["GRPC_MAX_RECV_BYTES"] = "999999999"
	if _, err := load(t, env); err == nil || !strings.Contains(err.Error(), "GRPC_MAX_RECV_BYTES") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsubscribeConfig(t *testing.T) {
	env := productionEnv()
	env["UNSUBSCRIBE_BASE_URL"] = "https://mail.example.com"
	env["UNSUBSCRIBE_SIGNING_KEY"] = testMasterKey
	env["UNSUBSCRIBE_MAILTO"] = "unsubscribe@example.com"
	cfg, err := load(t, env)
	if err != nil {
		t.Fatalf("valid unsubscribe config refused: %v", err)
	}
	if k, err := cfg.Unsubscribe.Key(); err != nil || len(k) != 32 {
		t.Fatalf("key = %d bytes, %v", len(k), err)
	}
	hexKey := strings.Repeat("ab", 32)
	if k, err := (Unsubscribe{SigningKey: hexKey}).Key(); err != nil || len(k) != 32 {
		t.Fatalf("hex key = %d bytes, %v", len(k), err)
	}
}

func TestUnsubscribeConfigRefused(t *testing.T) {
	cases := map[string]map[string]string{
		"http in production": {"UNSUBSCRIBE_BASE_URL": "http://mail.example.com", "UNSUBSCRIBE_SIGNING_KEY": testMasterKey},
		"no key":             {"UNSUBSCRIBE_BASE_URL": "https://mail.example.com"},
		"short key":          {"UNSUBSCRIBE_BASE_URL": "https://mail.example.com", "UNSUBSCRIBE_SIGNING_KEY": "c2hvcnQ="},
		"short ttl":          {"UNSUBSCRIBE_BASE_URL": "https://mail.example.com", "UNSUBSCRIBE_SIGNING_KEY": testMasterKey, "UNSUBSCRIBE_TOKEN_TTL": "1h"},
		"bad mailto":         {"UNSUBSCRIBE_BASE_URL": "https://mail.example.com", "UNSUBSCRIBE_SIGNING_KEY": testMasterKey, "UNSUBSCRIBE_MAILTO": "Bob <b@example.com>"},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			env := productionEnv()
			for k, v := range set {
				env[k] = v
			}
			if _, err := load(t, env); err == nil || !strings.Contains(err.Error(), "UNSUBSCRIBE_") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestAttachmentConfigRefused(t *testing.T) {
	cases := map[string]map[string]string{
		"total below one":  {"ATTACHMENTS_MAX_BYTES": "100", "ATTACHMENTS_MAX_TOTAL_BYTES": "50"},
		"too many":         {"ATTACHMENTS_MAX_COUNT": "1000"},
		"bad allowed type": {"ATTACHMENTS_ALLOWED_TYPES": "pdf"},
		"over the ceiling": {"ATTACHMENTS_MAX_TOTAL_BYTES": "999999999"},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			env := productionEnv()
			for k, v := range set {
				env[k] = v
			}
			if _, err := load(t, env); err == nil || !strings.Contains(err.Error(), "ATTACHMENT") && !strings.Contains(err.Error(), "attachment") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	ok := productionEnv()
	ok["ATTACHMENTS_ALLOWED_TYPES"] = "application/pdf,image/*"
	if _, err := load(t, ok); err != nil {
		t.Fatalf("type wildcard refused: %v", err)
	}
}
