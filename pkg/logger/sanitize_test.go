package logger

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestIsSecretFieldKey(t *testing.T) {
	for _, k := range []string{"password", "api_key", "redis_password", "Authorization", "code", "email_otp", "template_data", "link", "reset_link", "verify_link",
		"session", "sid", "session_id", "SessionID", "iam_session", "user.sid"} {
		if !IsSecretFieldKey(k) {
			t.Errorf("expected secret %q", k)
		}
	}
	for _, k := range []string{"password_configured", "service.name", "path", "status_code", "session_count", "considered", "linked_accounts"} {
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

// Loggers built on the sanitising core redact secret keys on every write,
// not only through the package functions: a FromContext logger too.
func TestSanitizeCoreRedactsDirectLogs(t *testing.T) {
	var buf bytes.Buffer
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buf), zapcore.DebugLevel)
	l := zap.New(wrapSanitize(core))
	l.Info("direct", zap.String("password", "hunter2"), zap.String("reset_link", "https://iam.example.com/reset-password?token=t1"))
	l.With(zap.String("api_key", "k-123")).Warn("child")
	if out := buf.String(); strings.Contains(out, "hunter2") || strings.Contains(out, "token=t1") || strings.Contains(out, "k-123") {
		t.Fatalf("sanitiser bypassed: %s", out)
	}
}
