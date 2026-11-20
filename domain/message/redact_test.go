package message

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tpl "github.com/razatechofficial/mail-os/domain/template"
)

func TestDescriptor(t *testing.T) {
	code := tpl.Variable{Key: "code", Kind: tpl.KindSecret}
	if got := Descriptor(code, "482913"); got != "[redacted: code, 6 characters]" {
		t.Fatalf("code = %q", got)
	}
	reset := tpl.Variable{Key: "reset_link", Kind: tpl.KindSecretURL, RedactPrefix: "/reset-password"}
	for raw, want := range map[string]string{
		"https://iam.example.com/reset-password?token=tok-123":     "https://iam.example.com/reset-password/[redacted]",
		"https://iam.example.com:8443/reset-password/tok-123#x=1":  "https://iam.example.com:8443/reset-password/[redacted]",
		"https://iam.example.com/other/tok-123":                    "https://iam.example.com/[redacted]",
		"https://user:pw@iam.example.com/reset-password?token=abc": "https://iam.example.com/reset-password/[redacted]",
		"not a url tok-123":                                        "[redacted: reset_link]",
		"javascript:alert(1)":                                      "[redacted: reset_link]",
	} {
		if got := Descriptor(reset, raw); got != want {
			t.Errorf("%s = %q, want %q", raw, got, want)
		}
		if got := Descriptor(reset, raw); strings.Contains(got, "tok-123") || strings.Contains(got, "pw") {
			t.Errorf("%s leaks: %q", raw, got)
		}
	}
	invite := tpl.Variable{Key: "link", Kind: tpl.KindSecretURL, RedactPrefix: "/invite/"}
	if got := Descriptor(invite, "https://iam.example.com/invite/accept?token=t"); got != "https://iam.example.com/invite/[redacted]" {
		t.Fatalf("invite = %q", got)
	}
}

func TestSplitSecrets(t *testing.T) {
	data := map[string]any{"email": "amna@example.com", "code": "482913", "purpose": "sign_in", "expires_in_minutes": float64(10),
		"brand": map[string]any{"name": "Bank"}}
	stored, live := SplitSecrets(tpl.TopicMFAEmailCode, data)
	if stored["code"] != "[redacted: code, 6 characters]" || stored["purpose"] != "sign_in" || live["code"] != "482913" {
		t.Fatalf("stored %v live %v", stored, live)
	}
	if data["code"] != "482913" {
		t.Fatal("input mutated")
	}
	// A short value is still a secret (values under 4 characters, F6).
	_, live = SplitSecrets(tpl.TopicMFAEmailCode, map[string]any{"code": "12"})
	if live["code"] != "12" {
		t.Fatalf("short code not taken: %v", live)
	}
	// A number is taken as its text.
	_, live = SplitSecrets(tpl.TopicMFAEmailCode, map[string]any{"code": float64(482913)})
	if live["code"] != "482913" {
		t.Fatalf("number code = %v", live)
	}
	// Redacting stored data again changes nothing.
	again, live := SplitSecrets(tpl.TopicMFAEmailCode, stored)
	if live != nil || again["code"] != stored["code"] {
		t.Fatalf("not idempotent: %v %v", again, live)
	}
	// Topics with no secret pass through.
	plain := map[string]any{"approval_link": "https://iam.example.com/approvals/1"}
	if out, live := SplitSecrets(tpl.TopicApprovalRequested, plain); live != nil || out["approval_link"] != plain["approval_link"] {
		t.Fatalf("plain = %v %v", out, live)
	}
	// Merge puts the live value back in a copy.
	merged := Secrets{"code": "482913"}.Merge(stored)
	if merged["code"] != "482913" || stored["code"] == "482913" {
		t.Fatalf("merge = %v, stored %v", merged, stored)
	}
}

func TestSecretsNested(t *testing.T) {
	// Dotted keys reach nested values (setPath, lookup).
	data := map[string]any{"a": map[string]any{"b": "secret-value"}}
	m := map[string]any{}
	setPath(m, "a.b", "x")
	if v, _ := lookup(m, "a.b"); v != "x" {
		t.Fatalf("setPath = %v", m)
	}
	merged := Secrets{"a.b": "live"}.Merge(data)
	if v, _ := lookup(merged, "a.b"); v != "live" {
		t.Fatalf("nested merge = %v", merged)
	}
	if v, _ := lookup(data, "a.b"); v != "secret-value" {
		t.Fatal("nested input mutated")
	}
}

func TestScrub(t *testing.T) {
	s := Secrets{"code": "12", "reset_link": "https://iam.example.com/reset-password?token=a&b=c"}
	in := `code 12; link https://iam.example.com/reset-password?token=a&amp;b=c; q https%3A%2F%2Fiam.example.com%2Freset-password%3Ftoken%3Da%26b%3Dc`
	got := s.Scrub(in)
	for _, leak := range []string{"12", "token=a", "token%3Da"} {
		if strings.Contains(got, leak) {
			t.Fatalf("scrub left %q: %s", leak, got)
		}
	}
	if Secrets(nil).Scrub("x 12") != "x 12" {
		t.Fatal("nil secrets changed text")
	}
}

func TestSecretExpiry(t *testing.T) {
	now := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	if got := SecretExpiry(nil, now, 0); !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("default = %v", got)
	}
	if got := SecretExpiry(nil, now, 3*time.Hour); !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("ttl above an hour = %v", got)
	}
	if got := SecretExpiry(map[string]any{"expires_in_minutes": float64(10)}, now, time.Hour); !got.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("minutes = %v", got)
	}
	at := now.Add(20 * time.Minute)
	if got := SecretExpiry(map[string]any{"expires_at": at.Format(time.RFC3339)}, now, time.Hour); !got.Equal(at) {
		t.Fatalf("expires_at = %v", got)
	}
	late := now.Add(48 * time.Hour).Format(time.RFC3339)
	if got := SecretExpiry(map[string]any{"expires_at": late}, now, time.Hour); !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("late expires_at = %v", got)
	}
}

func TestAuthClassMessage(t *testing.T) {
	m := Message{Topic: tpl.TopicPasswordReset}
	if !m.AuthClass() {
		t.Fatal("reset not authentication-class")
	}
	m.Topic = tpl.TopicApprovalRequested
	if m.AuthClass() {
		t.Fatal("approval is authentication-class")
	}
}

func TestScrubError(t *testing.T) {
	s := Secrets{"code": "482913"}
	se := &SendError{Provider: "smtp", Reason: ReasonRejected, Status: 550, Detail: "content 482913 refused",
		Err: errors.New("550 body 482913")}
	got := s.ScrubError(se)
	out, ok := AsSendError(got)
	if !ok || out.Reason != ReasonRejected || out.Status != 550 || out.Provider != "smtp" {
		t.Fatalf("classification lost: %#v", got)
	}
	if strings.Contains(got.Error(), "482913") || strings.Contains(out.Err.Error(), "482913") || strings.Contains(SafeDetail(got), "482913") {
		t.Fatalf("scrubbed error leaks: %v / %v", got, out.Err)
	}
	if se.Detail != "content 482913 refused" {
		t.Fatal("original mutated")
	}
	wrapped := s.ScrubError(fmt.Errorf("send: %w (code 482913)", context.Canceled))
	if !errors.Is(wrapped, context.Canceled) || strings.Contains(wrapped.Error(), "482913") {
		t.Fatalf("plain error: %v", wrapped)
	}
	if Secrets(nil).ScrubError(se) != error(se) {
		t.Fatal("nil secrets changed the error")
	}
}
