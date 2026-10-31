//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/analytics"
	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	appmessage "github.com/razatechofficial/mail-os/application/message"
	appprovider "github.com/razatechofficial/mail-os/application/provider"
	appsendingdomain "github.com/razatechofficial/mail-os/application/sendingdomain"
	appsuppression "github.com/razatechofficial/mail-os/application/suppression"
	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/application/tenant"
	appwebhook "github.com/razatechofficial/mail-os/application/webhook"
	"github.com/razatechofficial/mail-os/domain/access"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domainprovider "github.com/razatechofficial/mail-os/domain/provider"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	infrakm "github.com/razatechofficial/mail-os/infrastructure/keymanager"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/render"
)

type msgEnv struct {
	db       *postgres.Pool
	keys     *appkm.Service
	tenant   string
	tenants  *tenant.Service
	audit    *audit.Writer
	auditRep *postgres.AuditRepository
}

func newMsgEnv(t *testing.T) msgEnv {
	t.Helper()
	db := connectPostgres(t)
	ctx := context.Background()
	master := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	p, _ := infrakm.NewSoftwareProvider(master)
	keys := appkm.New(p, postgres.NewEncryptionKeyRepository(db), nil, appkm.Config{})
	if err := keys.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	ar := postgres.NewAuditRepository(db)
	w := audit.NewWriter(ar, false)
	ts := tenant.NewService(postgres.NewTenantRepository(db), w, time.Minute)
	id := uuid.NewString()
	if err := ts.Ensure(ctx, id); err != nil {
		t.Fatal(err)
	}
	return msgEnv{db: db, keys: keys, tenant: id, tenants: ts, audit: w, auditRep: ar}
}

func (e msgEnv) userCtx() context.Context {
	return access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindUser, Subject: uuid.NewString(),
		TenantID: e.tenant, Roles: []access.Role{access.RoleAdmin}})
}

func (e msgEnv) raw(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var v *string
	if err := e.db.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	if v == nil {
		return ""
	}
	return *v
}

// Provider credentials, DKIM keys and webhook secrets are km1 values at
// rest; the plaintext never reaches a column.
func TestSecretsSealedAtRest(t *testing.T) {
	e := newMsgEnv(t)
	ctx := e.userCtx()
	providers := appprovider.NewService(postgres.NewProviderRepository(e.db), e.keys.Cipher(domainkm.PurposeProvider), e.audit, appprovider.Config{})
	p, err := providers.Create(ctx, e.tenant, appprovider.Input{Name: "SendGrid", Kind: domainprovider.KindSendGrid,
		Credentials: domainprovider.Credentials{APIKey: "SG.plaintext-api-key-123456"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	sealed := e.raw(t, `SELECT credentials_sealed FROM providers WHERE id = $1`, p.ID)
	cfg := e.raw(t, `SELECT configuration::text FROM providers WHERE id = $1`, p.ID)
	if !domainkm.IsCiphertext(sealed) || strings.Contains(sealed+cfg, "plaintext-api-key") {
		t.Fatalf("provider at rest: %q %q", sealed, cfg)
	}
	active, err := providers.Active(ctx, e.tenant)
	if err != nil || len(active) != 1 || active[0].Credentials.APIKey != "SG.plaintext-api-key-123456" {
		t.Fatalf("open: %v %v", active, err)
	}
	if n, err := postgres.NewProviderRepository(e.db).SealedColumn().CountByKID(ctx, strings.Split(sealed, ".")[1]); err != nil || n < 1 {
		t.Fatalf("sealed column count %d %v", n, err)
	}

	domains := appsendingdomain.NewService(postgres.NewSendingDomainRepository(e.db), e.keys.Cipher(domainkm.PurposeDKIM),
		staticDNS{}, nil, e.audit, appsendingdomain.Config{})
	d, err := domains.Create(ctx, e.tenant, appsendingdomain.Input{Name: "mail-" + e.tenant[:8] + ".example"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if v := e.raw(t, `SELECT dkim_private_key_sealed FROM sending_domains WHERE id = $1`, d.ID); !domainkm.IsCiphertext(v) {
		t.Fatalf("dkim at rest %q", v)
	}
	if v := e.raw(t, `SELECT dkim_private_key FROM sending_domains WHERE id = $1`, d.ID); v != "" {
		t.Fatal("plaintext DKIM column written")
	}

	hooks := appwebhook.NewService(postgres.NewWebhookRepository(e.db), e.keys.Cipher(domainkm.PurposeWebhook), nopQueue{}, nil, e.audit, appwebhook.Config{})
	w, secret, err := hooks.Create(ctx, e.tenant, appwebhook.Input{URL: "https://hooks.bank.example/x", Events: []string{"message.sent"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if v := e.raw(t, `SELECT secret FROM webhooks WHERE id = $1`, w.ID); !domainkm.IsCiphertext(v) || strings.Contains(v, secret) {
		t.Fatalf("webhook secret at rest %q", v)
	}
	// The provider audit row redacts the credentials.
	events, _, _ := e.auditRep.List(context.Background(), postgres.AuditFilter{TenantUUID: uuid.MustParse(e.tenant), Limit: 50})
	for _, ev := range events {
		if strings.Contains(strings.Join([]string{ev.Action, toJSON(ev.Metadata)}, " "), "plaintext-api-key") {
			t.Fatalf("audit leaks a secret: %+v", ev)
		}
	}
}

// Plaintext secrets written before sealing are sealed once at startup and
// the plaintext cleared; a second run changes nothing.
func TestLegacyPlaintextConversion(t *testing.T) {
	e := newMsgEnv(t)
	ctx := context.Background()
	pid, did, wid := uuid.NewString(), uuid.NewString(), uuid.NewString()
	mustExec(t, e, `INSERT INTO providers (id, org_id, name, type, configuration) VALUES ($1, $2, 'old', 'smtp',
		'{"host":"smtp.bank.example","port":587,"username":"u","password":"legacy-pw","from_addr":"a@bank.example"}')`, pid, e.tenant)
	mustExec(t, e, `INSERT INTO sending_domains (id, org_id, domain, dkim_private_key, status) VALUES ($1, $2, $3,
		'-----BEGIN RSA PRIVATE KEY-----legacy', 'verified')`, did, e.tenant, "old-"+e.tenant[:8]+".example")
	mustExec(t, e, `INSERT INTO webhooks (id, org_id, url, secret, events) VALUES ($1, $2, 'https://h.example', 'legacy-webhook-secret', '{message.sent}')`, wid, e.tenant)

	providers := appprovider.NewService(postgres.NewProviderRepository(e.db), e.keys.Cipher(domainkm.PurposeProvider), e.audit, appprovider.Config{})
	domains := appsendingdomain.NewService(postgres.NewSendingDomainRepository(e.db), e.keys.Cipher(domainkm.PurposeDKIM), staticDNS{}, nil, e.audit, appsendingdomain.Config{})
	hooks := appwebhook.NewService(postgres.NewWebhookRepository(e.db), e.keys.Cipher(domainkm.PurposeWebhook), nopQueue{}, nil, e.audit, appwebhook.Config{})
	for _, run := range []func(context.Context) (int, error){providers.Bootstrap, domains.Bootstrap, hooks.Bootstrap} {
		if n, err := run(ctx); err != nil || n < 1 {
			t.Fatalf("conversion: %d %v", n, err)
		}
	}
	if cfg := e.raw(t, `SELECT configuration::text FROM providers WHERE id = $1`, pid); strings.Contains(cfg, "legacy-pw") || !strings.Contains(cfg, "a@bank.example") {
		t.Fatalf("provider configuration %s", cfg)
	}
	st, err := postgres.NewProviderRepository(e.db).Get(ctx, e.tenant, pid)
	if err != nil || !domainkm.IsCiphertext(st.Sealed) || !st.Provider.HasCredentials {
		t.Fatalf("%+v %v", st, err)
	}
	if v := e.raw(t, `SELECT dkim_private_key FROM sending_domains WHERE id = $1`, did); v != "" {
		t.Fatal("plaintext DKIM kept")
	}
	if v := e.raw(t, `SELECT dkim_private_key_sealed FROM sending_domains WHERE id = $1`, did); !domainkm.IsCiphertext(v) {
		t.Fatal("DKIM not sealed")
	}
	if v := e.raw(t, `SELECT secret FROM webhooks WHERE id = $1`, wid); !domainkm.IsCiphertext(v) {
		t.Fatal("webhook secret not sealed")
	}
	plain, _ := e.keys.Open(ctx, domainkm.PurposeWebhook, e.raw(t, `SELECT secret FROM webhooks WHERE id = $1`, wid))
	if string(plain) != "legacy-webhook-secret" {
		t.Fatal("sealed secret does not open to the original")
	}
	for _, run := range []func(context.Context) (int, error){providers.Bootstrap, domains.Bootstrap, hooks.Bootstrap} {
		if n, err := run(ctx); err != nil || n != 0 {
			t.Fatalf("second conversion: %d %v", n, err)
		}
	}
}

// flaky fails its first n sends with a transient error, then delegates.
type flaky struct {
	next  mailer.Sender
	fails atomic.Int32
}

func (f *flaky) Send(ctx context.Context, out domainmsg.Outgoing) (mailer.Result, error) {
	if f.fails.Add(-1) >= 0 {
		return mailer.Result{}, &domainmsg.SendError{Provider: "smtp", Reason: domainmsg.ReasonUnavailable, Status: 451, Detail: "try later"}
	}
	return f.next.Send(ctx, out)
}

type routerSender struct{ r *mailer.Router }

func (s routerSender) Send(ctx context.Context, out domainmsg.Outgoing) (appmessage.SendResult, error) {
	res, err := s.r.Send(ctx, out)
	return appmessage.SendResult{ProviderID: res.ProviderID, ProviderMessageID: res.ProviderMessageID}, err
}

type templates struct{}

var otpVersion = domaintemplate.Version{ID: uuid.NewString(), Locale: "en", Subject: "Your code {{code}}",
	HTMLBody: "<p>Code <b>{{code}}</b> for {{brand.company_name}}</p>", TextBody: "Code {{code}}"}

func (templates) ResolvePublished(context.Context, string, apptemplate.Ref, string) (domaintemplate.Template, domaintemplate.Version, error) {
	return domaintemplate.Template{ID: uuid.NewString(), Topic: domaintemplate.TopicMFAEmailCode, Category: domaintemplate.CategoryTransactional}, otpVersion, nil
}
func (templates) Version(context.Context, string, string) (domaintemplate.Version, error) {
	return otpVersion, nil
}
func (templates) Branding(context.Context, string) (domaintemplate.Branding, error) {
	return domaintemplate.Branding{CompanyName: "Integration Bank"}, nil
}

func renderContent(c appmessage.Content, data map[string]any) (appmessage.Content, error) {
	out, err := render.Render(render.Content{Subject: c.Subject, HTML: c.HTML, Text: c.Text}, data, render.Options{})
	return appmessage.Content{Subject: out.Subject, HTML: out.HTML, Text: out.Text}, err
}

func messageService(e msgEnv, platform mailer.Sender) *appmessage.Service {
	providers := appprovider.NewService(postgres.NewProviderRepository(e.db), e.keys.Cipher(domainkm.PurposeProvider), e.audit, appprovider.Config{})
	router := mailer.NewRouter(provSource{providers}, platform, mailer.Options{})
	return appmessage.NewService(appmessage.Deps{Repo: postgres.NewMessageRepository(e.db), Queue: nopQueue{},
		Suppressions: appsuppression.NewService(postgres.NewSuppressionRepository(e.db), e.audit), Tenants: e.tenants,
		Templates: templates{}, Versions: templates{}, Branding: templates{}, Render: renderContent, Sender: routerSender{router},
		Stats: analytics.NewService(postgres.NewStatsRepository(e.db)), Audit: e.audit},
		appmessage.Config{MaxAttempts: 3, RetentionDays: 30, DefaultFrom: "noreply@platform.example"})
}

// A templated OTP goes through the e2e sink after a transient failure: the
// retry is recorded, the body is rendered and stored, the view masks the
// code, and the purge erases body and data past retention.
func TestSendRetryAndPurge(t *testing.T) {
	e := newMsgEnv(t)
	rdb := connectRedis(t)
	sink := mailer.NewE2ESink(rdb.Client, domainmsg.Address{Email: "noreply@mailos.test"})
	platform := &flaky{next: sink}
	platform.fails.Store(1)
	svc := messageService(e, platform)
	ctx := context.Background()
	to := "otp-" + e.tenant[:8] + "@example.com"
	m, err := svc.SendTemplated(ctx, appmessage.TemplatedSend{TenantID: e.tenant, Topic: domaintemplate.TopicMFAEmailCode, To: to,
		FromEmail: "noreply@bank.example", EventID: "evt-1", Source: "iam",
		Data: map[string]any{"email": to, "code": "731904", "purpose": "sign_in", "expires_in_minutes": 10.0}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Deliver(ctx, e.tenant, m.ID); err == nil {
		t.Fatal("transient failure not returned for retry")
	}
	stored, _ := postgres.NewMessageRepository(e.db).Get(ctx, e.tenant, m.ID)
	if stored.Status != domainmsg.StatusQueued || stored.Attempts != 1 || stored.LastError == "" {
		t.Fatalf("after failure %+v", stored)
	}
	if err := svc.Deliver(ctx, e.tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	stored, _ = postgres.NewMessageRepository(e.db).Get(ctx, e.tenant, m.ID)
	if stored.Status != domainmsg.StatusSent || stored.Attempts != 2 || stored.ProviderMessageID != "e2e-"+m.ID {
		t.Fatalf("after send %+v", stored)
	}
	got, err := sink.List(ctx, to)
	if err != nil || len(got) != 1 || !strings.Contains(got[0].HTML, "<b>731904</b>") || !strings.Contains(got[0].HTML, "Integration Bank") {
		t.Fatalf("sink %+v %v", got, err)
	}
	v, _ := svc.Get(ctx, e.tenant, m.ID)
	if strings.Contains(v.MaskedSubject, "731904") || v.MaskedTemplateData["code"] != domainmsg.Mask {
		t.Fatalf("view %q %v", v.MaskedSubject, v.MaskedTemplateData)
	}
	body, err := svc.Body(e.userCtx(), e.tenant, m.ID)
	if err != nil || strings.Contains(body.HTML, "731904") || !strings.Contains(body.HTML, domainmsg.Mask) {
		t.Fatalf("body %+v %v", body, err)
	}

	mustExec(t, e, `UPDATE messages SET created_at = now() - interval '31 days' WHERE id = $1`, m.ID)
	counts, err := svc.Purge(ctx)
	if err != nil || counts[e.tenant] != 1 {
		t.Fatalf("purge %v %v", counts, err)
	}
	if v := e.raw(t, `SELECT COALESCE(html_body, '') || COALESCE(text_body, '') || COALESCE(template_data::text, '') || subject FROM messages WHERE id = $1`, m.ID); strings.Contains(v, "731904") {
		t.Fatalf("purge kept the code: %q", v)
	}
	if v := e.raw(t, `SELECT to_email FROM messages WHERE id = $1`, m.ID); v != to {
		t.Fatal("envelope not kept")
	}
	if _, err := svc.Body(e.userCtx(), e.tenant, m.ID); err != appmessage.ErrBodyGone {
		t.Fatalf("purged body: %v", err)
	}
	events, _, _ := e.auditRep.List(ctx, postgres.AuditFilter{TenantUUID: uuid.MustParse(e.tenant), Action: "messages.purged", Limit: 5})
	if len(events) != 1 {
		t.Fatalf("purge audit %d", len(events))
	}
}

// A direct send with an idempotency key stores one message, and a
// cancelled message is never delivered.
func TestIdempotencyAndCancel(t *testing.T) {
	e := newMsgEnv(t)
	sink := mailer.NewE2ESink(connectRedis(t).Client, domainmsg.Address{Email: "noreply@mailos.test"})
	svc := messageService(e, sink)
	ctx := e.userCtx()
	in := appmessage.SendInput{TenantID: e.tenant, FromEmail: "noreply@bank.example", ToEmail: "idem@example.com", Subject: "Hi",
		Text: "hello", IdempotencyKey: "order-" + e.tenant}
	a, err := svc.Send(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Send(ctx, in)
	if err != nil || a.MessageID != b.MessageID {
		t.Fatalf("%v %v %v", a, b, err)
	}
	if _, err := svc.Cancel(ctx, e.tenant, a.MessageID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Deliver(context.Background(), e.tenant, a.MessageID); err != nil {
		t.Fatal(err)
	}
	if v := e.raw(t, `SELECT status FROM messages WHERE id = $1`, a.MessageID); v != "cancelled" {
		t.Fatalf("status %s", v)
	}
}

type provSource struct{ svc *appprovider.Service }

func (p provSource) ActiveProviders(ctx context.Context, tenantID string) ([]mailer.Configured, error) {
	list, err := p.svc.Active(ctx, tenantID)
	out := make([]mailer.Configured, len(list))
	for i, o := range list {
		out[i] = mailer.Configured{Provider: o.Provider, Credentials: o.Credentials}
	}
	return out, err
}

type nopQueue struct{}

func (nopQueue) EnqueueSend(context.Context, domainmsg.Message) error { return nil }
func (nopQueue) EnqueueWebhook(context.Context, string) error         { return nil }

type staticDNS struct{}

func (staticDNS) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }

func mustExec(t *testing.T, e msgEnv, sql string, args ...any) {
	t.Helper()
	if _, err := e.db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func toJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
