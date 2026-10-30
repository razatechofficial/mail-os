package logger

import (
	"context"
	"testing"
)

func init() {
	_ = InitSimple("debug", "console")
}

func TestFromContext(t *testing.T) {
	ctx := context.Background()
	if l := FromContext(ctx); l == nil {
		t.Fatal("FromContext without request_id should return the global logger")
	}
	ctx = WithRequestIDContext(ctx, "req-123")
	if RequestIDFromContext(ctx) != "req-123" {
		t.Fatal("request id not stored")
	}
	if l := FromContext(ctx); l == nil || l == Log {
		t.Fatal("FromContext with request_id should return a child logger")
	}
}

func TestSanitizeFieldsMasksOneTimeCodes(t *testing.T) {
	out := sanitizeFields([]Field{String("code", "482913"), String("topic", "iam.auth.mfa_email_code_requested")})
	if out[0].String != redactedValue {
		t.Fatalf("code logged: %q", out[0].String)
	}
	if out[1].String != "iam.auth.mfa_email_code_requested" {
		t.Fatalf("topic changed: %q", out[1].String)
	}
}
