package message

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

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
	// apps are the registry's applications: core (live, iam.auth.* topics,
	// raw content) and sandbox (sandboxed, broadcast).
	core, sandbox domainapp.Application
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{repo: newMemRepo(), queue: &memQueue{}, sups: &memSuppressions{list: map[string]suppression.Type{}},
		sender: &memSender{}, notifier: &memNotifier{}, stats: &memStats{counts: map[string]int{}}, audit: &memAudit{}}
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
		Webhooks: f.notifier, Stats: f.stats, Audit: f.audit}, Config{MaxAttempts: 3, RetentionDays: 30})
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

func TestTemplatedSendPinsVersionAndMasks(t *testing.T) {
	f := newFixture(t)
	m, err := f.svc.SendTemplated(context.Background(), TemplatedSend{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode,
		To: "ana@example.com", EventID: "evt-1", Source: "iam",
		Data: map[string]any{"email": "ana@example.com", "code": "482913", "purpose": "sign_in", "expires_in_minutes": 10.0}})
	if err != nil {
		t.Fatal(err)
	}
	if m.TemplateVersionID != "ver-3" || m.Topic != domaintemplate.TopicMFAEmailCode || len(m.SecretKeys) != 1 || m.Actor.Type != domainmsg.ActorSystem {
		t.Fatalf("message %+v", m)
	}
	v, _ := f.svc.Get(context.Background(), tenant, m.ID)
	if strings.Contains(v.MaskedSubject, "482913") || v.MaskedTemplateData["code"] != domainmsg.Mask || v.MaskedSubject != "Bank of Tests code "+domainmsg.Mask {
		t.Fatalf("view leaks the code: %q %v", v.MaskedSubject, v.MaskedTemplateData)
	}
	// Data the topic refuses is a 422 that never quotes the value.
	_, err = f.svc.SendTemplated(context.Background(), TemplatedSend{TenantID: tenant, Topic: domaintemplate.TopicMFAEmailCode,
		To: "ana@example.com", Data: map[string]any{"email": "ana@example.com"}})
	if apperrors.KindOf(err) != apperrors.KindInvalidInput {
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
	out := f.sender.sent[0]
	if out.HTML != "<p>Your code is 482913</p>" || out.DKIM == nil {
		t.Fatalf("outgoing %+v", out)
	}
	if f.stats.counts["sent"] != 1 || f.notifier.events[0] != "message.sent" {
		t.Fatal(f.stats.counts, f.notifier.events)
	}
	// A second run of the task (asynq redelivery) does nothing.
	if err := f.svc.Deliver(context.Background(), tenant, m.ID); err != nil || len(f.sender.sent) != 1 {
		t.Fatal("redelivery sent twice")
	}
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
	if !strings.Contains(m.HTMLBody, "123456") || len(f.sender.sent) != 0 || len(f.notifier.events) != 0 {
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
