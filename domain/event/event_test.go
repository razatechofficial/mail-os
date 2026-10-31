package event

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const iamEvent = `{
	"id": "6f1c1f1e-8f43-4a8e-9a43-0b3c1d6c2a10",
	"type": "iam.auth.password_reset_requested",
	"source": "iam",
	"data": {"email": "a@example.com", "token": "secret"},
	"metadata": {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
	"timestamp": "2026-10-31T10:00:00Z",
	"tenant_uuid": "8D3B1F7A-2C4E-4F6A-9B1D-3E5F7A9C1B2D",
	"organization_uuid": "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
}`

func TestParseIAMEnvelope(t *testing.T) {
	e, err := Parse([]byte(iamEvent))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e.Type != "iam.auth.password_reset_requested" || e.Source != "iam" || e.ID == "" {
		t.Fatalf("envelope = %+v", e)
	}
	if e.TenantUUID != "8d3b1f7a-2c4e-4f6a-9b1d-3e5f7a9c1b2d" {
		t.Fatalf("tenant not lower-cased: %q", e.TenantUUID)
	}
	if e.Timestamp.IsZero() || e.Metadata["traceparent"] == "" {
		t.Fatalf("timestamp or metadata lost: %+v", e)
	}
	if !strings.Contains(string(e.Data), `"email"`) {
		t.Fatalf("data = %s", e.Data)
	}
}

func TestParseWithoutID(t *testing.T) {
	if _, err := Parse([]byte(`{"type":"iam.auth.login","data":{}}`)); err != nil {
		t.Fatalf("id is optional: %v", err)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	big := fmt.Sprintf(`{"type":"iam.auth.login","data":{"x":"%s"}}`, strings.Repeat("a", MaxSize))
	cases := map[string]string{
		"not json":         `{"type":`,
		"array":            `[]`,
		"trailing data":    `{"type":"iam.auth.login","data":{}} {}`,
		"no type":          `{"data":{}}`,
		"one segment type": `{"type":"login","data":{}}`,
		"upper case type":  `{"type":"IAM.auth.login","data":{}}`,
		"empty segment":    `{"type":"iam..login","data":{}}`,
		"type too long":    `{"type":"iam.` + strings.Repeat("a", maxTypeLen) + `","data":{}}`,
		"no data":          `{"type":"iam.auth.login"}`,
		"null data":        `{"type":"iam.auth.login","data":null}`,
		"array data":       `{"type":"iam.auth.login","data":[1]}`,
		"string data":      `{"type":"iam.auth.login","data":"x"}`,
		"bad tenant":       `{"type":"iam.auth.login","data":{},"tenant_uuid":"acme"}`,
		"bad organization": `{"type":"iam.auth.login","data":{},"organization_uuid":"1"}`,
		"control in id":    `{"type":"iam.auth.login","data":{},"id":"a\nb"}`,
		"over the limit":   big,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(raw))
			reason, ok := ReasonOf(err)
			if !ok || reason != ReasonMalformed {
				t.Fatalf("err = %v, want a malformed rejection", err)
			}
			if strings.Contains(err.Error(), "a@example.com") {
				t.Fatalf("rejection quotes the body: %v", err)
			}
		})
	}
}

func TestRejectionIsPermanent(t *testing.T) {
	err := fmt.Errorf("handle: %w", Reject(ReasonReplay, errors.New("jti seen")))
	var p interface{ Permanent() bool }
	if !errors.As(err, &p) || !p.Permanent() {
		t.Fatal("a wrapped rejection does not report Permanent")
	}
	if r, ok := ReasonOf(err); !ok || r != ReasonReplay {
		t.Fatalf("ReasonOf = %q, %v", r, ok)
	}
	if _, ok := ReasonOf(errors.New("other")); ok {
		t.Fatal("ReasonOf found a reason in a plain error")
	}
	if got := Reject(ReasonExpired, nil).Error(); got != "message rejected: expired" {
		t.Fatalf("Error() = %q", got)
	}
	transient := &Rejection{Reason: ReasonReplayGuardUnavailable, Transient: true}
	if transient.Permanent() {
		t.Fatal("a transient rejection reports Permanent")
	}
}

func TestValidType(t *testing.T) {
	for _, ok := range []string{"iam.auth.login", "iam.auth.password_reset_requested", "iam.account.security_notice"} {
		if !ValidType(ok) {
			t.Errorf("ValidType(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "iam", "iam.", ".iam", "iam.Auth", "iam.auth-login", "iam.1auth"} {
		if ValidType(bad) {
			t.Errorf("ValidType(%q) = true", bad)
		}
	}
}
