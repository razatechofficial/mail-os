package logger

import (
	"strings"
	"testing"
)

func TestIsSecretFieldKey(t *testing.T) {
	for _, k := range []string{"password", "api_key", "redis_password", "Authorization", "code", "email_otp", "template_data"} {
		if !IsSecretFieldKey(k) {
			t.Errorf("expected secret %q", k)
		}
	}
	for _, k := range []string{"password_configured", "service.name", "path", "status_code"} {
		if IsSecretFieldKey(k) {
			t.Errorf("expected safe %q", k)
		}
	}
}

func TestRedactURLFailClosed(t *testing.T) {
	got := RedactURL("postgres://user:secret@db\x00.example/mailos")
	if strings.Contains(got, "secret") || strings.Contains(got, "user") {
		t.Fatalf("leaked credentials: %q", got)
	}
}
