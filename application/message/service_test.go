package message

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
	"github.com/razatechofficial/mail-os/domain/suppression"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

const tenant = "0192f0c4-0000-7000-8000-000000000001"

type fixture struct {
	svc      *Service
	repo     *memRepo
	queue    *memQueue
	sups     *memSuppressions
	sender   *memSender
	notifier *memNotifier
	stats    *memStats
	audit    *memAudit
	secrets  *memSecrets
	// apps are the registry's applications: core (live, iam.auth.* topics,
	// raw content) and sandbox (sandboxed, broadcast).
	core, sandbox domainapp.Application
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{repo: newMemRepo(), queue: &memQueue{}, sups: &memSuppressions{list: map[string]suppression.Type{}},
		sender: &memSender{}, notifier: &memNotifier{}, stats: &memStats{counts: map[string]int{}}, audit: &memAudit{},
		secrets: newMemSecrets()}
	tpls := memTemplates{
		tpl: domaintemplate.Template{ID: "tpl-1", Slug: "mfa-code", Topic: domaintemplate.TopicMFAEmailCode, Category: domaintemplate.CategoryTransactional},
		ver: domaintemplate.Version{ID: "ver-3", TemplateID: "tpl-1", Locale: "en", Subject: "{{brand.company_name}} code {{code}}",
			HTMLBody: "<p>Your code is {{code}}</p>", TextBody: "Your code is {{code}}"},
	}
	f.core = appstest.Server("core", tenant, "iam.auth.*", "raw")
	f.core.System, f.core.Senders, f.core.DefaultFromEmail, f.core.RatePerMinute, f.core.DailyQuota =
		false, []string{"*@bank.example"}, "otp@bank.example", 100, 2
	f.sandbox = appstest.Server("sandbox", tenant, "mfa-code")
	f.sandbox.Environment, f.sandbox.Stream = domainapp.EnvSandbox, domainapp.StreamBroadcast
	f.svc = NewService(Deps{Applications: appstest.New(f.core, f.sandbox), Repo: f.repo, Queue: f.queue, Suppressions: f.sups, Tenants: memTenants{}, Templates: tpls,
		Versions: tpls, Branding: tpls, Render: fakeRender, Sender: f.sender, Signer: memSigner{},
		Webhooks: f.notifier, Stats: f.stats, Audit: f.audit, Secrets: f.secrets, SecretCipher: fakeCipher{}},
		Config{MaxAttempts: 3, RetentionDays: 30})
	return f
}

func userCtx() context.Context {
	return access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindUser, Subject: "user-1", TenantID: tenant,
		Roles: []access.Role{access.RoleOperator}})
}

func direct() SendInput {
	return SendInput{TenantID: tenant, FromEmail: "noreply@bank.example", ToEmail: "ana@example.com", Subject: "Hello", HTML: "<p>Hi</p>"}
}

func TestSendQueuesAndAudits(t *testing.T) {
	f := newFixture(t)
	r, err := f.svc.Send(userCtx(), direct())
	if err != nil || r.Status != "queued" || len(f.queue.ids) != 1 {
		t.Fatalf("%+v %v %v", r, err, f.queue.ids)
	}
	m, _ := f.repo.Get(context.Background(), tenant, r.MessageID)
	if m.Actor != (domainmsg.Actor{Type: domainmsg.ActorUser, ID: "user-1"}) || m.Type != domainmsg.TypeTransactional {
		t.Fatalf("message %+v", m)
	}
	if !f.audit.has("message.queued") || strings.Contains(f.audit.meta[0]["to"].(string), "ana@") {
		t.Fatal("queue not audited, or the recipient unmasked")
	}
}

func TestSendSanitisesWrittenHTML(t *testing.T) {
	f := newFixture(t)
	in := direct()
	in.HTML = `<p onclick="steal()">Hi</p><script>alert(1)</script><a href="javascript:x()">link</a>`
	r, err := f.svc.Send(userCtx(), in)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := f.repo.Get(context.Background(), tenant, r.MessageID)
	for _, bad := range []string{"<script", "onclick", "javascript:"} {
		if strings.Contains(m.HTMLBody, bad) {
			t.Fatalf("stored HTML keeps %q: %s", bad, m.HTMLBody)
		}
	}
	if !strings.Contains(m.HTMLBody, "Hi") {
		t.Fatalf("content lost: %s", m.HTMLBody)
	}
}

func TestSendValidationAndIdempotency(t *testing.T) {
	f := newFixture(t)
	bad := direct()
	bad.ToEmail = "not-an-address"
	if _, err := f.svc.Send(userCtx(), bad); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("got %v", err)
	}
	in := direct()
	in.IdempotencyKey = "order-42"
	a, _ := f.svc.Send(userCtx(), in)
	b, err := f.svc.Send(userCtx(), in)
	if err != nil || a.MessageID != b.MessageID || len(f.queue.ids) != 1 {
		t.Fatalf("idempotency: %v %v %v", a, b, err)
	}
}

func TestSuppressedRecipientIsRecordedNotSent(t *testing.T) {
	f := newFixture(t)
	f.sups.list["ana@example.com"] = suppression.TypeBounce
	r, err := f.svc.Send(userCtx(), direct())
	if err != nil || r.Status != "suppressed" || len(f.queue.ids) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	// An unsubscribe does not stop transactional mail.
	f.sups.list["ana@example.com"] = suppression.TypeUnsubscribe
	if r, _ := f.svc.Send(userCtx(), direct()); r.Status != "queued" {
		t.Fatal(r.Status)
	}
}

func TestScheduleAndRelease(t *testing.T) {
	f := newFixture(t)
	in := direct()
	at := time.Now().Add(time.Hour)
	in.ScheduleAt = &at
	r, _ := f.svc.Send(userCtx(), in)
	if r.Status != "scheduled" || len(f.queue.ids) != 0 {
		t.Fatal(r.Status)
	}
	if n, _ := f.svc.ReleaseScheduled(context.Background()); n != 0 {
		t.Fatal("released early")
	}
	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour).UTC() }
	if n, err := f.svc.ReleaseScheduled(context.Background()); n != 1 || err != nil || len(f.queue.ids) != 1 {
		t.Fatal(n, err)
	}
	far := time.Now().Add(40 * 24 * time.Hour)
	in.ScheduleAt = &far
	if _, err := f.svc.Send(userCtx(), in); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatal("scheduled beyond 30 days")
	}
}

func otpSend() TemplatedSend {
	return TemplatedSend{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode, To: "ana@example.com", EventID: "evt-1",
		Source: "iam", FromEmail: "noreply@bank.example",
		Data: map[string]any{"email": "ana@example.com", "code": "482913", "purpose": "sign_in", "expires_in_minutes": 10.0}}
}

// stored is everything a message row holds, as text.
func stored(t *testing.T, m domainmsg.Message) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTemplatedSendStoresRedacted(t *testing.T) {
	f := newFixture(t)
	m, err := f.svc.SendTemplated(context.Background(), otpSend())
	if err != nil {
		t.Fatal(err)
	}
	if m.TemplateVersionID != "ver-3" || m.Topic != domaintemplate.TopicMFAEmailCode || len(m.SecretKeys) != 1 || m.Actor.Type != domainmsg.ActorSystem {
		t.Fatalf("message %+v", m)
	}
	// Repo.Create got descriptors, never the value.
	row, _ := f.repo.Get(context.Background(), tenant, m.ID)
	if strings.Contains(stored(t, row), "482913") {
		t.Fatalf("stored row holds the code: %s", stored(t, row))
	}
	if row.TemplateData["code"] != "[redacted: code, 6 characters]" || row.Subject != "Bank of Tests code [redacted: code, 6 characters]" ||
		row.TemplateData["purpose"] != "sign_in" {
		t.Fatalf("stored %q %v", row.Subject, row.TemplateData)
	}
	// The live value is sealed in the secret store, for at most its own
	// expiry (10 minutes here).
	r := f.secrets.rows[m.ID]
	if plain, _ := (fakeCipher{}).Open(context.Background(), r.sealed); string(plain) != `{"code":"482913"}` || strings.Contains(r.sealed, "482913") {
		t.Fatalf("sealed %q", r.sealed)
	}
	if d := r.expires.Sub(row.CreatedAt); d != 10*time.Minute {
		t.Fatalf("secret kept %v", d)
	}
	v, _ := f.svc.Get(context.Background(), tenant, m.ID)
	if !v.AuthClass || v.Subject != row.Subject {
		t.Fatalf("view %+v", v)
	}
	// Data the topic refuses is a 422 that never quotes the value.
	_, err = f.svc.SendTemplated(context.Background(), TemplatedSend{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode,
		To: "ana@example.com", Data: map[string]any{"email": "ana@example.com"}})
	if apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatal(err)
	}
}

// Without the secret store, authentication mail is refused and nothing is
// stored; a failing store stores neither the message nor its secrets.
func TestAuthMailNeedsTheSecretStore(t *testing.T) {
	f := newFixture(t)
	f.svc.d.Secrets = nil
	if _, err := f.svc.SendTemplated(context.Background(), otpSend()); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("sent without a secret store: %v", err)
	}
	if len(f.repo.msgs) != 0 || len(f.queue.ids) != 0 {
		t.Fatal("stored or queued without a secret store")
	}
	// Ordinary mail does not need it.
	if _, err := f.svc.Send(userCtx(), direct()); err != nil {
		t.Fatal(err)
	}
}

func TestDeliverRendersSignsAndCounts(t *testing.T) {
	f := newFixture(t)
	f.svc.d.Signer = memSigner{key: &sendingdomain.SigningKey{Domain: "bank.example", Selector: "mailos"}}
	m, _ := f.svc.SendTemplated(context.Background(), TemplatedSend{TenantID: tenant, TemplateSlug: "mfa-code", To: "ana@example.com",
		FromEmail: "noreply@bank.example", Data: map[string]any{"email": "ana@example.com", "code": "482913", "purpose": "sign_in", "expires_in_minutes": 10.0}})
	if err := f.svc.Deliver(context.Background(), tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.repo.Get(context.Background(), tenant, m.ID)
	if got.Status != domainmsg.StatusSent || got.ProviderMessageID != "pm-"+m.ID || got.ProviderID != "p1" || got.Attempts != 1 {
		t.Fatalf("after deliver %+v", got)
	}
	// The relay got the full message, without tracking; the row keeps the
	// redacted render.
	out := f.sender.sent[0]
	if out.HTML != "<p>Your code is 482913</p>" || out.Subject != "Bank of Tests code 482913" || out.DKIM == nil || !out.NoTracking {
		t.Fatalf("outgoing %+v", out)
	}
	if got.HTMLBody != "<p>Your code is [redacted: code, 6 characters]</p>" || strings.Contains(stored(t, got), "482913") {
		t.Fatalf("stored body %q", got.HTMLBody)
	}
	if f.secrets.has(m.ID) {
		t.Fatal("secrets kept after the message was sent")
	}
	if f.stats.counts["sent"] != 1 || f.notifier.events[0] != "message.sent" {
		t.Fatal(f.stats.counts, f.notifier.events)
	}
	// A second run of the task (asynq redelivery) does nothing.
	if err := f.svc.Deliver(context.Background(), tenant, m.ID); err != nil || len(f.sender.sent) != 1 {
		t.Fatal("redelivery sent twice")
	}
	// Ordinary mail goes with the account's tracking.
	r, _ := f.svc.Send(userCtx(), direct())
	_ = f.svc.Deliver(context.Background(), tenant, r.MessageID)
	if f.sender.sent[1].NoTracking {
		t.Fatal("ordinary mail sent untracked")
	}
}

// A failed send of authentication mail is retried with the live code from
// the sealed store; a provider error quoting the code is scrubbed from the
// row, the webhook and the retry error; the secrets go at the final status.
func TestAuthMailRetriesWithTheLiveSecret(t *testing.T) {
	f := newFixture(t)
	m, _ := f.svc.SendTemplated(context.Background(), otpSend())
	echo := &domainmsg.SendError{Provider: "smtp", Reason: domainmsg.ReasonUnavailable, Status: 451,
		Detail: "try later; body was: Your code is 482913", Err: errors.New("451 482913")}
	f.sender.errs = []error{echo, domainmsg.NewSendError("smtp", domainmsg.ReasonRejected, 554, "content 482913 rejected")}
	err := f.svc.Deliver(context.Background(), tenant, m.ID)
	re, ok := err.(*RetryError)
	if !ok || strings.Contains(re.Error(), "482913") || strings.Contains(fmt.Sprint(re.Unwrap()), "482913") {
		t.Fatalf("retry error %v", err)
	}
	row, _ := f.repo.Get(context.Background(), tenant, m.ID)
	if row.Status != domainmsg.StatusQueued || strings.Contains(stored(t, row), "482913") || !f.secrets.has(m.ID) {
		t.Fatalf("after a transient failure %+v", row)
	}
	// The second attempt is refused for good: the code never reaches the
	// stored error or the webhook.
	if err := f.svc.Deliver(context.Background(), tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	row, _ = f.repo.Get(context.Background(), tenant, m.ID)
	if row.Status != domainmsg.StatusFailed || strings.Contains(stored(t, row), "482913") || f.secrets.has(m.ID) {
		t.Fatalf("after a permanent failure %+v", row)
	}
	if hook, _ := json.Marshal(f.notifier.data); strings.Contains(string(hook), "482913") || !strings.Contains(string(hook), "[redacted]") {
		t.Fatalf("webhook payload %s", hook)
	}

	// A retry that succeeds sends the live code.
	m2, _ := f.svc.SendTemplated(context.Background(), TemplatedSend{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode,
		To: "bo@example.com", Data: map[string]any{"email": "bo@example.com", "code": "771204", "purpose": "sign_in", "expires_in_minutes": 10.0}})
	f.sender.errs = []error{&domainmsg.SendError{Reason: domainmsg.ReasonNetwork}}
	if _, ok := f.svc.Deliver(context.Background(), tenant, m2.ID).(*RetryError); !ok {
		t.Fatal("not retried")
	}
	if err := f.svc.Deliver(context.Background(), tenant, m2.ID); err != nil {
		t.Fatal(err)
	}
	if last := f.sender.sent[len(f.sender.sent)-1]; !strings.Contains(last.Text, "771204") {
		t.Fatalf("retry sent %q", last.Text)
	}
}

// Secrets past their expiry are never sent: the message fails with
// secret_expired.
func TestAuthMailFailsWhenItsSecretExpired(t *testing.T) {
	f := newFixture(t)
	m, _ := f.svc.SendTemplated(context.Background(), otpSend())
	f.svc.now = func() time.Time { return time.Now().Add(11 * time.Minute).UTC() }
	if err := f.svc.Deliver(context.Background(), tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	row, _ := f.repo.Get(context.Background(), tenant, m.ID)
	if row.Status != domainmsg.StatusFailed || row.LastError != SecretExpired || len(f.sender.sent) != 0 {
		t.Fatalf("%s %q sent %d", row.Status, row.LastError, len(f.sender.sent))
	}
	if f.notifier.events[len(f.notifier.events)-1] != "message.failed" || f.secrets.has(m.ID) {
		t.Fatal("expiry not reported, or secrets kept")
	}
}

// The delivery path's log lines never hold the live secrets.
func TestDeliverLogsNoSecret(t *testing.T) {
	var buf bytes.Buffer
	prev := logger.Log
	logger.Log = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buf), zapcore.DebugLevel))
	defer func() { logger.Log = prev }()
	f := newFixture(t)
	f.svc.d.Signer = memSigner{err: fmt.Errorf("kms says no for 482913")}
	f.svc.d.Webhooks = failingNotifier{}
	m, _ := f.svc.SendTemplated(context.Background(), otpSend())
	_ = f.svc.Deliver(context.Background(), tenant, m.ID)
	f.svc.d.Signer = memSigner{}
	f.sender.errs = []error{domainmsg.NewSendError("smtp", domainmsg.ReasonRejected, 554, "content 482913 rejected")}
	_ = f.svc.Deliver(context.Background(), tenant, m.ID)
	if buf.Len() == 0 {
		t.Fatal("nothing logged")
	}
	if strings.Contains(buf.String(), "482913") {
		t.Fatalf("log holds the code:\n%s", buf.String())
	}
}

type failingNotifier struct{}

func (failingNotifier) Notify(context.Context, string, string, string, string, map[string]any) error {
	return errors.New("webhook down; payload had 482913")
}

func TestDeliverRetriesTransientThenFails(t *testing.T) {
	f := newFixture(t)
	r, _ := f.svc.Send(userCtx(), direct())
	transient := &domainmsg.SendError{Reason: domainmsg.ReasonRateLimited, Status: 429, RetryAfter: 30 * time.Second}
	f.sender.errs = []error{transient, transient, transient}
	for i := 1; i <= 2; i++ {
		err := f.svc.Deliver(context.Background(), tenant, r.MessageID)
		re, ok := err.(*RetryError)
		if !ok || re.RetryAfter() != 30*time.Second {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if m, _ := f.repo.Get(context.Background(), tenant, r.MessageID); m.Status != domainmsg.StatusQueued || m.Attempts != i {
			t.Fatalf("attempt %d: %s %d", i, m.Status, m.Attempts)
		}
	}
	if err := f.svc.Deliver(context.Background(), tenant, r.MessageID); err != nil {
		t.Fatalf("last attempt: %v", err)
	}
	if m, _ := f.repo.Get(context.Background(), tenant, r.MessageID); m.Status != domainmsg.StatusFailed || f.stats.counts["failed"] != 1 {
		t.Fatalf("after max attempts: %s", m.Status)
	}
}

func TestDeliverWaitsForAnUnavailableDKIMKey(t *testing.T) {
	f := newFixture(t)
	f.svc.d.Signer = memSigner{err: errDown}
	r, _ := f.svc.Send(userCtx(), direct())
	for i := 1; i <= 2; i++ {
		if _, ok := f.svc.Deliver(context.Background(), tenant, r.MessageID).(*RetryError); !ok {
			t.Fatalf("attempt %d: not retried", i)
		}
		if m, _ := f.repo.Get(context.Background(), tenant, r.MessageID); m.Status != domainmsg.StatusQueued || m.Attempts != i {
			t.Fatalf("attempt %d: %s %d", i, m.Status, m.Attempts)
		}
	}
	if len(f.sender.sent) != 0 {
		t.Fatal("sent unsigned while the DKIM key was unavailable")
	}
	if err := f.svc.Deliver(context.Background(), tenant, r.MessageID); err != nil {
		t.Fatalf("last attempt: %v", err)
	}
	m, _ := f.repo.Get(context.Background(), tenant, r.MessageID)
	if m.Status != domainmsg.StatusFailed || len(f.sender.sent) != 0 || !strings.Contains(m.LastError, "DKIM") {
		t.Fatalf("after max attempts: %s %q", m.Status, m.LastError)
	}
}

func TestDeliverPermanentBounceSuppresses(t *testing.T) {
	f := newFixture(t)
	r, _ := f.svc.Send(userCtx(), direct())
	f.sender.errs = []error{domainmsg.NewSendError("smtp", domainmsg.ReasonInvalidRecipient, 550, "no such user")}
	if err := f.svc.Deliver(context.Background(), tenant, r.MessageID); err != nil {
		t.Fatal("permanent failure retried:", err)
	}
	m, _ := f.repo.Get(context.Background(), tenant, r.MessageID)
	if m.Status != domainmsg.StatusBounced || len(f.sups.bounced) != 1 || f.notifier.events[0] != "message.bounced" {
		t.Fatalf("%s %v %v", m.Status, f.sups.bounced, f.notifier.events)
	}
}

func TestCancelResendAndBody(t *testing.T) {
	f := newFixture(t)
	r, _ := f.svc.Send(userCtx(), direct())
	if _, err := f.svc.Resend(userCtx(), tenant, r.MessageID); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatal("resent a queued message")
	}
	if _, err := f.svc.Cancel(userCtx(), tenant, r.MessageID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Cancel(userCtx(), tenant, r.MessageID); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatal("cancelled twice")
	}
	if err := f.svc.Deliver(context.Background(), tenant, r.MessageID); err != nil || len(f.sender.sent) != 0 {
		t.Fatal("a cancelled message was sent")
	}
	again, err := f.svc.Resend(userCtx(), tenant, r.MessageID)
	if err != nil || again.ID == r.MessageID || again.Metadata["resent_from"] != r.MessageID || !f.audit.has("message.resent") {
		t.Fatalf("%+v %v", again, err)
	}
	b, err := f.svc.Body(userCtx(), tenant, again.ID)
	if err != nil || b.HTML != "<p>Hi</p>" || !f.audit.has("message.body_viewed") {
		t.Fatal(b, err)
	}
	if _, err := f.svc.Body(userCtx(), "other-tenant", again.ID); apperrors.KindOf(err) != apperrors.KindNotFound {
		t.Fatal("another tenant read the body")
	}
	// Authentication mail is never resent, by anyone.
	otp, _ := f.svc.SendTemplated(context.Background(), otpSend())
	if err := f.svc.Deliver(context.Background(), tenant, otp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Resend(userCtx(), tenant, otp.ID); err != ErrAuthResend || apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("resent authentication mail: %v", err)
	}
	if b, err := f.svc.Body(userCtx(), tenant, otp.ID); err != nil || strings.Contains(b.HTML+b.Text, "482913") {
		t.Fatalf("auth body %+v %v", b, err)
	}
}

func TestPurgeHonoursTenantRetention(t *testing.T) {
	f := newFixture(t)
	days := 7
	f.svc.d.Tenants = memTenants{days: &days}
	m, _ := f.svc.SendTemplated(context.Background(), TemplatedSend{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode, To: "ana@example.com",
		Data: map[string]any{"email": "ana@example.com", "code": "482913", "purpose": "sign_in", "expires_in_minutes": 10.0}})
	_ = f.svc.Deliver(context.Background(), tenant, m.ID)
	if n, _ := f.svc.Purge(context.Background()); n[tenant] != 0 {
		t.Fatal("purged inside retention")
	}
	f.svc.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour).UTC() }
	n, err := f.svc.Purge(context.Background())
	if err != nil || n[tenant] != 1 || !f.audit.has("messages.purged") {
		t.Fatal(n, err)
	}
	got, _ := f.repo.Get(context.Background(), tenant, m.ID)
	if got.HTMLBody != "" || got.TemplateData != nil || got.BodyPurgedAt == nil || strings.Contains(got.Subject, "482913") || got.ToEmail == "" {
		t.Fatalf("purge %+v", got)
	}
	if _, err := f.svc.Body(userCtx(), tenant, m.ID); err != ErrBodyGone {
		t.Fatal("purged body served")
	}
}

func TestPurgeDeletesDeliveryRecordsAtTheTenantRetention(t *testing.T) {
	f := newFixture(t)
	days := 7
	f.svc.d.Tenants = memTenants{days: &days}
	now := time.Now().UTC()
	f.svc.now = func() time.Time { return now }
	f.repo.records = map[string]int64{"other-tenant": 4}
	n, err := f.svc.Purge(context.Background())
	if err != nil || len(n) != 0 {
		t.Fatal(n, err)
	}
	if got := f.repo.recordsBefore["other-tenant"]; !got.Equal(now.Add(-7 * 24 * time.Hour)) {
		t.Fatalf("records purged before %v", got)
	}
	if !f.audit.has("messages.purged") || f.audit.meta[len(f.audit.meta)-1]["records"] != int64(4) {
		t.Fatal("record purge not audited", f.audit.meta)
	}
}

func TestSweepRequeuesLostWork(t *testing.T) {
	f := newFixture(t)
	f.queue.err = errDown
	r, err := f.svc.Send(userCtx(), direct())
	if err != nil || r.Status != "queued" {
		t.Fatal("a lost enqueue failed the send", err)
	}
	f.queue.err = nil
	f.svc.now = func() time.Time { return time.Now().Add(5 * time.Minute).UTC() }
	if n, _ := f.svc.Sweep(context.Background()); n != 1 || len(f.queue.ids) != 1 {
		t.Fatal("lost message not requeued", n)
	}
}

// The sweep deletes live secrets past their expiry, even of a message
// that never reached a final status.
func TestSweepDeletesExpiredSecrets(t *testing.T) {
	f := newFixture(t)
	m, _ := f.svc.SendTemplated(context.Background(), otpSend())
	if _, err := f.svc.Sweep(context.Background()); err != nil || !f.secrets.has(m.ID) {
		t.Fatal("live secrets swept early", err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(61 * time.Minute).UTC() }
	if _, err := f.svc.Sweep(context.Background()); err != nil || f.secrets.has(m.ID) {
		t.Fatal("expired secrets kept", err)
	}
}

func TestBatchLimitsAndPartialFailure(t *testing.T) {
	f := newFixture(t)
	bad := direct()
	bad.ToEmail = "x"
	res, err := f.svc.Batch(userCtx(), tenant, []SendInput{direct(), bad})
	if err != nil || res.SuccessCount != 1 || res.FailCount != 1 || res.Results[1].Error == "" {
		t.Fatal(res, err)
	}
	if _, err := f.svc.Batch(userCtx(), tenant, make([]SendInput, MaxBatch+1)); err == nil {
		t.Fatal("oversized batch accepted")
	}
	id, status, err := f.svc.SendTest(userCtx(), TestMessage{TenantID: tenant, FromEmail: "a@bank.example", To: "t@example.com", Subject: "T", Text: "t"})
	m, _ := f.repo.Get(context.Background(), tenant, id)
	if err != nil || status != "queued" || m.Tags[len(m.Tags)-1] != "test" {
		t.Fatal(id, status, err)
	}
}

func TestDispatchAndCampaignSend(t *testing.T) {
	f := newFixture(t)
	id, err := f.svc.Dispatch(context.Background(), inbound.Delivery{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode,
		EventID: "evt-9", Source: "iam", ClientID: "iam-service", OrgID: "org-1",
		Data: map[string]any{"email": "ana@example.com", "code": "482913", "purpose": "sign_in", "expires_in_minutes": json.Number("10")}})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := f.repo.Get(context.Background(), tenant, id)
	if m.ToEmail != "ana@example.com" || m.EventID != "evt-9" || m.Actor != (domainmsg.Actor{Type: domainmsg.ActorService, ID: "iam-service"}) ||
		m.Metadata["iam_org_id"] != "org-1" || m.Metadata["source"] != "iam" {
		t.Fatalf("%+v", m)
	}
	if _, err := f.svc.Dispatch(context.Background(), inbound.Delivery{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode,
		Data: map[string]any{"code": "1"}}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatal("event without a recipient accepted")
	}
	id, err = f.svc.SendCampaignMessage(context.Background(), campaign.CampaignMessage{TenantID: tenant, CampaignID: "c1",
		TemplateID: "tpl-1", To: "bob@example.com", FromEmail: "news@bank.example",
		Data: map[string]any{"contact": map[string]any{"email": "bob@example.com"}, "campaign": map[string]any{"name": "Autumn"}}})
	if err != nil {
		t.Fatal(err)
	}
	m, _ = f.repo.Get(context.Background(), tenant, id)
	if m.Type != domainmsg.TypeMarketing || m.CampaignID != "c1" || m.Topic != domaintemplate.TopicCampaign {
		t.Fatalf("%+v", m)
	}
}

func appCtx(a domainapp.Application) context.Context {
	return access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindService, Subject: "client:" + a.ClientID,
		ClientID: a.ClientID, TenantID: tenant, ApplicationID: a.ID})
}

// An application's send takes its default sender, carries its id, and is
// refused outside its message types and senders and over its quota.
func TestApplicationSendRules(t *testing.T) {
	f := newFixture(t)
	ctx := appCtx(f.core)
	in := direct()
	in.FromEmail = ""
	r, err := f.svc.Send(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	m := f.repo.msgs[r.MessageID]
	if m.ApplicationID != f.core.ID || m.FromEmail != "otp@bank.example" || m.Stream != domainmsg.StreamTransactional || m.Sandbox {
		t.Fatalf("%+v", m)
	}
	tpl := SendInput{TenantID: tenant, TemplateSlug: "mfa-code", ToEmail: "ana@example.com", TemplateData: mfaData()}
	if _, err := f.svc.Send(ctx, tpl); err != nil {
		t.Fatalf("topic allowed by prefix: %v", err)
	}
	if _, err := f.svc.Send(ctx, in); apperrors.KindOf(err) != apperrors.KindRateLimited || domainapp.Reason(err) != "quota_exceeded" {
		t.Fatalf("third send over a quota of 2: %v", err)
	}
	if n := len(f.repo.msgs); n != 2 {
		t.Fatalf("%d messages stored", n)
	}
	in.FromEmail = "ceo@other.example"
	if _, err := f.svc.Send(ctx, in); domainapp.Reason(err) != "sender_not_allowed" {
		t.Fatalf("sender: %v", err)
	}
	sb := appCtx(f.sandbox)
	if _, err := f.svc.Send(sb, direct()); domainapp.Reason(err) != "raw_content_not_allowed" {
		t.Fatalf("raw from an application without raw: %v", err)
	}
}

// A sandbox application's message is rendered and captured: no provider,
// no webhook, no stats; a broadcast application's mail is marketing.
func TestSandboxCapturesWithoutDelivering(t *testing.T) {
	f := newFixture(t)
	r, err := f.svc.Send(appCtx(f.sandbox), SendInput{TenantID: tenant, TemplateSlug: "mfa-code", ToEmail: "ana@example.com",
		TemplateData: mfaData()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Deliver(context.Background(), tenant, r.MessageID); err != nil {
		t.Fatal(err)
	}
	m := f.repo.msgs[r.MessageID]
	if m.Status != domainmsg.StatusCaptured || !m.Sandbox || m.Type != domainmsg.TypeMarketing || m.Stream != domainmsg.StreamBroadcast {
		t.Fatalf("%+v", m)
	}
	// Captured authentication mail keeps the redacted copy only.
	if !strings.Contains(m.HTMLBody, "[redacted: code, 6 characters]") || strings.Contains(m.HTMLBody, "123456") ||
		f.secrets.has(r.MessageID) || len(f.sender.sent) != 0 || len(f.notifier.events) != 0 {
		t.Fatalf("captured body %q, sent %d, events %v", m.HTMLBody, len(f.sender.sent), f.notifier.events)
	}
}

// An application-scoped suppression stops that application's mail, and
// webhooks are told which application sent.
func TestApplicationSuppressionAndWebhookScope(t *testing.T) {
	f := newFixture(t)
	f.sups.list[f.core.ID+"/scoped@example.com"] = suppression.TypeManual
	in := direct()
	in.FromEmail, in.ToEmail = "", "scoped@example.com"
	r, err := f.svc.Send(appCtx(f.core), in)
	if err != nil || r.Status != string(domainmsg.StatusSuppressed) {
		t.Fatalf("%+v %v", r, err)
	}
	console, err := f.svc.Send(userCtx(), SendInput{TenantID: tenant, FromEmail: "noreply@bank.example", ToEmail: "scoped@example.com",
		Subject: "Hi", Text: "x"})
	if err != nil || console.Status != "queued" {
		t.Fatalf("an application's suppression stopped the tenant's own mail: %+v %v", console, err)
	}
	in.ToEmail = "ok@example.com"
	ok, _ := f.svc.Send(appCtx(f.core), in)
	if err := f.svc.Deliver(context.Background(), tenant, ok.MessageID); err != nil {
		t.Fatal(err)
	}
	if len(f.notifier.apps) != 1 || f.notifier.apps[0] != f.core.ID {
		t.Fatalf("webhook scope %v", f.notifier.apps)
	}
}

func mfaData() map[string]any {
	return map[string]any{"email": "ana@example.com", "code": "123456", "purpose": "sign_in", "expires_in_minutes": 10.0}
}

// A topic's derived variables render in the subject and the delivered
// bodies, worded from the event: IAM's mfa_reset notice is not printed as
// its key.
func TestTemplatedSendRendersDerivedVariables(t *testing.T) {
	f := newFixture(t)
	f.svc.d.Templates = memTemplates{
		tpl: domaintemplate.Template{ID: "tpl-2", Slug: "notice", Topic: domaintemplate.TopicSecurityNotice, Category: domaintemplate.CategoryTransactional},
		ver: domaintemplate.Version{ID: "ver-7", TemplateID: "tpl-2", Locale: "en", Subject: "Security notice: {{kind_text}}",
			HTMLBody: "<p>{{kind_text}}. {{advice_text}}</p>", TextBody: "{{kind_text}}"},
	}
	f.svc.d.Versions = f.svc.d.Templates.(memTemplates)
	m, err := f.svc.Dispatch(context.Background(), inbound.Delivery{TenantID: tenant, Topic: domaintemplate.TopicSecurityNotice,
		EventID: "evt-n", Source: "iam", Data: map[string]any{"email": "ana@example.com", "user_uuid": "u1", "kind": "mfa_reset",
			"occurred_at": "2026-11-10T09:30:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.repo.Get(context.Background(), tenant, m)
	if got.Subject != "Security notice: Your multi-factor authentication was reset" {
		t.Fatalf("subject = %q", got.Subject)
	}
	if _, stored := got.TemplateData["kind_text"]; stored {
		t.Fatal("derived wording stored with the event data")
	}
	if err := f.svc.Deliver(context.Background(), tenant, m); err != nil {
		t.Fatal(err)
	}
	if out := f.sender.sent[0]; out.Text != "Your multi-factor authentication was reset" || !strings.Contains(out.HTML, "contact them immediately") {
		t.Fatalf("outgoing %q / %q", out.Text, out.HTML)
	}
}
