package message

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func otpMessage() *Message {
	m := &Message{
		ID: "msg-1", OrgID: "org-1", ToEmail: " user@example.com ", FromEmail: "noreply@bank.example",
		Subject: "Your code is 482913", HTMLBody: "<p>Code: 482913</p>", TextBody: "Code: 482913",
		TemplateData: map[string]any{"otp": "482913", "user": map[string]any{"name": "Ana", "pin": 9071}},
		SecretKeys:   []string{"otp", "user.pin", "missing"},
		Tags:         []string{"otp", "login"},
		Actor:        Actor{Type: ActorService, ID: "iam"},
		CreatedAt:    now,
	}
	m.Normalize()
	return m
}

func codes(err error) []string {
	var out []string
	for _, d := range apperrors.DetailsOf(err) {
		out = append(out, d.Field+":"+d.Code)
	}
	return out
}

func TestNormalizeAndValidate(t *testing.T) {
	m := otpMessage()
	if m.Type != TypeTransactional || m.Priority != PriorityNormal || m.Status != StatusQueued || m.ToEmail != "user@example.com" {
		t.Fatalf("defaults: %+v", m)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(codes(err))
	}
}

func TestValidateRefuses(t *testing.T) {
	m := &Message{ToEmail: "not-an-address", Subject: "a\r\nBcc: x@evil.example", Type: "spam", Status: StatusScheduled,
		Priority: 11, Tags: []string{"a", "a"}, Locale: "en-", TemplateVersionID: "v1",
		Actor: Actor{Type: ActorUser}, ReplyTo: "x"}
	got := codes(m.Validate())
	for _, w := range []string{"org_id:required", "to_email:invalid", "subject:invalid", "body:required", "type:invalid",
		"scheduled_at:required", "priority:out_of_range", "tags:invalid", "locale:invalid",
		"template_version_id:not_allowed", "actor:required", "reply_to:invalid"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %s in %v", w, got)
		}
	}
}

func TestTemplateMessageNeedsNoBody(t *testing.T) {
	m := &Message{OrgID: "o", ToEmail: "a@example.com", TemplateID: "t1", TemplateVersionID: "v1", Locale: "pt-BR"}
	m.Normalize()
	if err := m.Validate(); err != nil {
		t.Fatal(codes(err))
	}
}

func TestTransitions(t *testing.T) {
	m := otpMessage()
	if err := m.Transition(StatusDelivered, now); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("queued -> delivered: %v", err)
	}
	if err := m.Transition(StatusSending, now); err != nil || m.Attempts != 1 || m.LastAttemptAt == nil {
		t.Fatal("sending", err)
	}
	if err := m.MarkSent("p1", "pm-1", now); err != nil || m.SentAt == nil || m.ProviderMessageID != "pm-1" {
		t.Fatal("sent", err)
	}
	for _, to := range []Status{StatusDelivered, StatusBounced} {
		if err := m.Transition(to, now); err != nil {
			t.Fatal(to, err)
		}
	}
	for _, from := range []Status{StatusBounced, StatusCancelled, StatusSuppressed} {
		for _, to := range Statuses {
			if CanTransition(from, to) {
				t.Errorf("%s is final but may become %s", from, to)
			}
		}
	}
}

func TestRecordSendFailure(t *testing.T) {
	cases := []struct {
		err   error
		want  Status
		retry bool
	}{
		{NewSendError("smtp", ReasonUnavailable, 451, "try later"), StatusQueued, true},
		{errors.New("dial tcp 10.0.0.1:25: connection refused"), StatusQueued, true},
		{NewSendError("ses", ReasonRejected, 400, "content"), StatusFailed, false},
		{NewSendError("smtp", ReasonInvalidRecipient, 550, "no such user"), StatusBounced, false},
	}
	for _, c := range cases {
		m := otpMessage()
		_ = m.Transition(StatusSending, now)
		retry, err := m.RecordSendFailure(c.err, 5, now)
		if err != nil || retry != c.retry || m.Status != c.want {
			t.Errorf("%v: retry=%v status=%s err=%v", c.err, retry, m.Status, err)
		}
	}
	m := otpMessage()
	m.Attempts = 4
	_ = m.Transition(StatusSending, now)
	if retry, _ := m.RecordSendFailure(NewSendError("smtp", ReasonNetwork, 0, "timeout"), 5, now); retry || m.Status != StatusFailed {
		t.Fatal("attempts not bounded")
	}
	if strings.Contains(m.LastError, "10.0.0") {
		t.Fatal("raw error stored")
	}
}

func TestSecretsMasked(t *testing.T) {
	m := otpMessage()
	data := m.MaskedTemplateData()
	if data["otp"] != Mask || data["user"].(map[string]any)["pin"] != Mask || data["user"].(map[string]any)["name"] != "Ana" {
		t.Fatalf("masked: %v", data)
	}
	if m.TemplateData["otp"] != "482913" {
		t.Fatal("masking changed the stored data")
	}
	if got := m.Redact(m.HTMLBody); strings.Contains(got, "482913") || !strings.Contains(got, Mask) {
		t.Fatalf("redact: %s", got)
	}
	if got := m.Redact("pin 9071"); got != "pin "+Mask {
		t.Fatalf("numeric secret: %s", got)
	}
}

func TestPurgeBody(t *testing.T) {
	m := otpMessage()
	if m.BodyPurgeDue(time.Hour, now.Add(2*time.Hour)) {
		t.Fatal("queued message purged")
	}
	_ = m.Transition(StatusSending, now)
	_ = m.MarkSent("p", "x", now)
	if m.BodyPurgeDue(DefaultBodyRetention, now.Add(24*time.Hour)) {
		t.Fatal("purged before retention")
	}
	if !m.BodyPurgeDue(DefaultBodyRetention, now.Add(DefaultBodyRetention)) {
		t.Fatal("not due after retention")
	}
	m.PurgeBody(now)
	if m.HTMLBody != "" || m.TextBody != "" || m.TemplateData != nil || strings.Contains(m.Subject, "482913") || m.BodyPurgedAt == nil {
		t.Fatalf("purge left data: %+v", m)
	}
	if _, err := m.Outgoing(); !errors.Is(err, ErrBodyPurged) {
		t.Fatal("purged message is sendable")
	}
}

func TestOutgoingValidate(t *testing.T) {
	o, err := otpMessage().Outgoing()
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Outgoing){
		func(o *Outgoing) { o.Headers = map[string]string{"Bcc": "x@evil.example"} },
		func(o *Outgoing) { o.Headers = map[string]string{"Content-Type": "text/plain"} },
		func(o *Outgoing) { o.Headers = map[string]string{"X-Ok": "a\r\nBcc: x@evil.example"} },
		func(o *Outgoing) { o.Headers = map[string]string{"X Bad": "v"} },
		func(o *Outgoing) { o.Subject = "a\nb" },
		func(o *Outgoing) { o.HTML, o.Text = "", "" },
		func(o *Outgoing) { o.From.Email = "" },
	}
	for i, f := range bad {
		c := o
		f(&c)
		err := c.Validate()
		if se, ok := AsSendError(err); !ok || se.Reason != ReasonInvalid || !IsPermanent(err) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	c := o
	c.To.Email = "nobody"
	if se, _ := AsSendError(c.Validate()); se == nil || se.Reason != ReasonInvalidRecipient {
		t.Fatal("bad recipient not classified")
	}
	c = o
	c.From = Address{}
	if got := c.WithDefaultFrom(Address{Name: "Bank", Email: "no-reply@bank.example"}); got.From.Email != "no-reply@bank.example" || got.From.Name != "Bank" {
		t.Fatalf("default from: %+v", got.From)
	}
	if got := (Address{Name: "Zoë", Email: "z@example.com"}).String(); !strings.HasPrefix(got, "=?utf-8?") {
		t.Fatalf("name not encoded: %s", got)
	}
}

func TestSendErrorClassification(t *testing.T) {
	for _, r := range []Reason{ReasonInvalidRecipient, ReasonRejected, ReasonInvalid} {
		if !r.Permanent() || r.ProviderFault() {
			t.Errorf("%s", r)
		}
	}
	for _, r := range []Reason{ReasonAuth, ReasonConfig} {
		if !r.Permanent() || !r.ProviderFault() {
			t.Errorf("%s", r)
		}
	}
	for _, r := range []Reason{ReasonRateLimited, ReasonUnavailable, ReasonNetwork} {
		if r.Permanent() || !r.ProviderFault() {
			t.Errorf("%s", r)
		}
	}
	err := fmt.Errorf("wrapped: %w", &SendError{Provider: "postmark", Reason: ReasonRateLimited, Status: 429, RetryAfter: 3 * time.Second})
	if IsPermanent(err) || RetryAfterOf(err) != 3*time.Second {
		t.Fatal("wrapped error not classified")
	}
	if SafeDetail(context.DeadlineExceeded) != "the send was interrupted" || SafeDetail(err) != "postmark: rate_limited (429)" {
		t.Fatalf("safe detail: %q", SafeDetail(err))
	}
}

// A sandbox message is captured from sending, and captured is final.
func TestCapturedIsFinal(t *testing.T) {
	if !CanTransition(StatusSending, StatusCaptured) || CanTransition(StatusQueued, StatusCaptured) || CanTransition(StatusCaptured, StatusQueued) {
		t.Fatal("captured transitions")
	}
	if !StatusCaptured.Final() || !StatusCaptured.Valid() {
		t.Fatal("captured is a final, known status")
	}
	m := Message{OrgID: "t", ToEmail: "a@example.com", Subject: "s", TextBody: "b"}
	m.Normalize()
	if m.Stream != StreamTransactional {
		t.Fatalf("default stream %q", m.Stream)
	}
}
