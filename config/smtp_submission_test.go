package config

import (
	"strings"
	"testing"
)

func TestSMTPSubmissionIsOffByDefault(t *testing.T) {
	cfg, err := load(t, productionEnv())
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.SMTPSubmission
	if s.Enabled || s.Port != 587 || s.ImplicitTLSPort != 0 || s.MaxMessageBytes != 4<<20 || !s.PasswordAuth || s.MinTLSVersion != "1.2" {
		t.Fatalf("defaults: %+v", s)
	}
	if s.ImplicitAddr() != "" || s.Addr() != "0.0.0.0:587" {
		t.Fatalf("addresses %q %q", s.Addr(), s.ImplicitAddr())
	}
}

func TestSMTPSubmissionValidation(t *testing.T) {
	on := map[string]string{"SMTP_SUBMISSION_ENABLED": "true", "SMTP_SUBMISSION_HOSTNAME": "smtp.mailos.bank.example",
		"SMTP_SUBMISSION_TLS_CERT_FILE": "/tls/smtp.crt", "SMTP_SUBMISSION_TLS_KEY_FILE": "/tls/smtp.key",
		"SMTP_SUBMISSION_IMPLICIT_TLS_PORT": "465"}
	env := productionEnv()
	for k, v := range on {
		env[k] = v
	}
	cfg, err := load(t, env)
	if err != nil {
		t.Fatalf("a valid listener: %v", err)
	}
	if cfg.SMTPSubmission.ImplicitAddr() != "0.0.0.0:465" {
		t.Fatalf("implicit %q", cfg.SMTPSubmission.ImplicitAddr())
	}
	for name, c := range map[string]struct{ set, want string }{
		"no certificate":  {"SMTP_SUBMISSION_TLS_CERT_FILE=", "never runs without TLS"},
		"same ports":      {"SMTP_SUBMISSION_IMPLICIT_TLS_PORT=587", "SMTP_SUBMISSION_PORT"},
		"old TLS":         {"SMTP_SUBMISSION_TLS_MIN_VERSION=1.1", "1.2 or 1.3"},
		"huge messages":   {"SMTP_SUBMISSION_MAX_MESSAGE_BYTES=104857600", "16 MiB"},
		"no recipients":   {"SMTP_SUBMISSION_MAX_RECIPIENTS=0", "MAX_RECIPIENTS"},
		"per IP over all": {"SMTP_SUBMISSION_MAX_CONNECTIONS_PER_IP=500", "per IP"},
		"short timeout":   {"SMTP_SUBMISSION_READ_TIMEOUT=1s", "timeouts"},
	} {
		t.Run(name, func(t *testing.T) {
			e := map[string]string{}
			for k, v := range env {
				e[k] = v
			}
			k, v, _ := strings.Cut(c.set, "=")
			e[k] = v
			if _, err := load(t, e); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}
