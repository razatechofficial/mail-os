//go:build integration

package integration

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/analytics"
	"github.com/razatechofficial/mail-os/application/applications"
	appmessage "github.com/razatechofficial/mail-os/application/message"
	appprovider "github.com/razatechofficial/mail-os/application/provider"
	appsuppression "github.com/razatechofficial/mail-os/application/suppression"
	appwebhook "github.com/razatechofficial/mail-os/application/webhook"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/suppression"
	domainwebhook "github.com/razatechofficial/mail-os/domain/webhook"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// bankDomains verifies every sender on bank.example.
type bankDomains struct{}

func (bankDomains) VerifiedFrom(_ context.Context, _ string, from string) (bool, error) {
	return strings.HasSuffix(from, "@bank.example") || strings.HasSuffix(from, ".bank.example"), nil
}

type appsEnv struct {
	msgEnv
	repo *postgres.ApplicationRepository
	svc  *applications.Service
}

func newAppsEnv(t *testing.T) appsEnv {
	t.Helper()
	e := newMsgEnv(t)
	repo := postgres.NewApplicationRepository(e.db)
	return appsEnv{msgEnv: e, repo: repo,
		svc: applications.NewService(repo, bankDomains{}, connectRedis(t), e.tenants, e.audit, applications.Config{})}
}

func (e appsEnv) create(t *testing.T, mutate func(*applications.Input)) domainapp.Application {
	t.Helper()
	in := applications.Input{Name: "Core " + uuid.NewString()[:8], Kind: domainapp.KindServer, ClientID: "core-" + uuid.NewString(),
		Environment: domainapp.EnvLive, MessageTypes: []string{"raw", "bank.*"}, Senders: []string{"*@bank.example"},
		DefaultFromEmail: "otp@bank.example", RatePerMinute: 1000, DailyQuota: 1000}
	if mutate != nil {
		mutate(&in)
	}
	a, err := e.svc.Create(e.userCtx(), e.tenant, in, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func appCtx(a domainapp.Application) context.Context {
	return access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindService, Subject: "client:" + a.ClientID,
		ClientID: a.ClientID, TenantID: a.TenantID, ApplicationID: a.ID})
}

// The registry round-trips every field, refuses a client that is already
// an application (in any tenant) and a duplicate name, and finds an
// application by its client.
func TestApplicationRepository(t *testing.T) {
	e := newAppsEnv(t)
	ctx := e.userCtx()
	a := e.create(t, func(in *applications.Input) {
		in.Description, in.Stream, in.DefaultReplyTo = "Core banking alerts", domainapp.StreamBroadcast, "help@bank.example"
	})
	got, err := e.repo.ByClientID(ctx, a.ClientID)
	if err != nil || got.ID != a.ID || got.Stream != domainapp.StreamBroadcast || got.DefaultReplyTo != "help@bank.example" ||
		len(got.MessageTypes) != 2 || got.Senders[0] != "*@bank.example" || got.RatePerMinute != 1000 {
		t.Fatalf("%+v %v", got, err)
	}
	other := newAppsEnv(t)
	_, err = other.svc.Create(other.userCtx(), other.tenant, applications.Input{Name: "Copy", Kind: domainapp.KindServer,
		ClientID: a.ClientID, MessageTypes: []string{"raw"}, RatePerMinute: 1, DailyQuota: 1}, "admin")
	if apperrors.KindOf(err) != apperrors.KindConflict || !strings.Contains(err.Error(), "IAM client") {
		t.Fatalf("a client in two tenants: %v", err)
	}
	_, err = e.svc.Create(ctx, e.tenant, applications.Input{Name: strings.ToUpper(a.Name), Kind: domainapp.KindServer,
		ClientID: "x-" + uuid.NewString(), MessageTypes: []string{"raw"}, RatePerMinute: 1, DailyQuota: 1}, "admin")
	if apperrors.KindOf(err) != apperrors.KindConflict || !strings.Contains(err.Error(), "name") {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := e.svc.Suspend(ctx, e.tenant, a.ID, "rotation", "admin"); err != nil {
		t.Fatal(err)
	}
	list, total, err := e.repo.List(ctx, applications.Filter{TenantID: e.tenant, Status: "suspended", Limit: 10})
	if err != nil || total != 1 || list[0].SuspendedReason != "rotation" {
		t.Fatalf("%+v %d %v", list, total, err)
	}
	if err := e.svc.Delete(ctx, e.tenant, a.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.ByClientID(ctx, a.ClientID); err != applications.ErrNotFound {
		t.Fatalf("deleted: %v", err)
	}
}

// Replicas seeding the system application at once leave one row.
func TestSystemApplicationSeedIsIdempotent(t *testing.T) {
	e := newAppsEnv(t)
	client := "mailos-iam-" + uuid.NewString()
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.SeedSystem(context.Background(), applications.SystemSpec{ClientID: client, TenantID: e.tenant, Name: "IAM",
				Topics: []string{"iam.*"}})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, total, _ := e.repo.List(context.Background(), applications.Filter{TenantID: e.tenant, Limit: 10})
	if total != 1 {
		t.Fatalf("%d system applications", total)
	}
}

// The daily quota holds under concurrent sends on the shared Redis: no
// more messages are allowed than the quota, and the usage counts them.
func TestApplicationQuotaOnRedis(t *testing.T) {
	e := newAppsEnv(t)
	a := e.create(t, func(in *applications.Input) { in.DailyQuota = 5 })
	var allowed, limited atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.AuthorizeSend(appCtx(a), a.ID, applications.Ask{Raw: true})
			switch {
			case err == nil:
				allowed.Add(1)
			case apperrors.KindOf(err) == apperrors.KindRateLimited:
				limited.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 5 || limited.Load() != 15 {
		t.Fatalf("allowed %d, limited %d", allowed.Load(), limited.Load())
	}
	u, err := e.svc.Usage(context.Background(), e.tenant, a.ID, 1)
	if err != nil || u.QuotaUsedToday != 5 {
		t.Fatalf("%+v %v", u, err)
	}
}

func appMessageService(e appsEnv, platform mailer.Sender, webhooks appmessage.Notifier) *appmessage.Service {
	providers := appprovider.NewService(postgres.NewProviderRepository(e.db), e.keys.Cipher(domainkm.PurposeProvider), e.audit, appprovider.Config{})
	router := mailer.NewRouter(provSource{providers}, platform, mailer.Options{})
	return appmessage.NewService(appmessage.Deps{Applications: e.svc, Repo: postgres.NewMessageRepository(e.db), Queue: nopQueue{},
		Suppressions: appsuppression.NewService(postgres.NewSuppressionRepository(e.db), e.audit), Tenants: e.tenants,
		Templates: templates{}, Versions: templates{}, Branding: templates{}, Render: renderContent, Sender: routerSender{router},
		Webhooks: webhooks, Stats: analytics.NewService(postgres.NewStatsRepository(e.db)), Audit: e.audit},
		appmessage.Config{MaxAttempts: 3, RetentionDays: 30, DefaultFrom: "noreply@platform.example"})
}

// An application's messages carry its id, stream and sandbox flag in
// Postgres; a sandbox message is captured, an application-scoped
// suppression stops only that application, its webhooks get only its
// events, and the usage counts its messages.
func TestApplicationMessagesOnPostgres(t *testing.T) {
	e := newAppsEnv(t)
	rdb := connectRedis(t)
	sink := mailer.NewE2ESink(rdb.Client, domainmsg.Address{Email: "noreply@mailos.test"})
	whRepo := postgres.NewWebhookRepository(e.db)
	webhooks := appwebhook.NewService(whRepo, e.keys.Cipher(domainkm.PurposeWebhook), nopQueue{}, nil, e.audit,
		appwebhook.Config{AllowPlaintext: true})
	svc := appMessageService(e, sink, webhooks)
	live := e.create(t, nil)
	sandbox := e.create(t, func(in *applications.Input) { in.Environment = domainapp.EnvSandbox })

	if _, _, err := webhooks.Create(e.userCtx(), e.tenant, appwebhook.Input{ApplicationID: live.ID, URL: "http://127.0.0.1:9/live",
		Events: []string{domainwebhook.EventSent}}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := webhooks.Create(e.userCtx(), e.tenant, appwebhook.Input{ApplicationID: sandbox.ID, URL: "http://127.0.0.1:9/sb",
		Events: []string{domainwebhook.EventSent}}, "admin"); err != nil {
		t.Fatal(err)
	}

	send := func(a domainapp.Application, to string) appmessage.Result {
		t.Helper()
		r, err := svc.Send(appCtx(a), appmessage.SendInput{TenantID: e.tenant, ToEmail: to, Subject: "Hi", Text: "hello"})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	to := "app-" + e.tenant[:8] + "@example.com"
	r := send(live, to)
	if err := svc.Deliver(context.Background(), e.tenant, r.MessageID); err != nil {
		t.Fatal(err)
	}
	if got := e.raw(t, `SELECT application_id || ' ' || stream || ' ' || sandbox::text || ' ' || status FROM messages WHERE id = $1`, r.MessageID); got != live.ID+" transactional false sent" {
		t.Fatalf("live message row %q", got)
	}
	if n := e.raw(t, `SELECT count(*)::text FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE d.message_id = $1 AND w.application_id = $2`, r.MessageID, live.ID); n != "1" {
		t.Fatalf("the live application's webhook got %s deliveries", n)
	}
	if n := e.raw(t, `SELECT count(*)::text FROM webhook_deliveries WHERE message_id = $1`, r.MessageID); n != "1" {
		t.Fatalf("another application's webhook was told: %s deliveries", n)
	}

	s := send(sandbox, to)
	if err := svc.Deliver(context.Background(), e.tenant, s.MessageID); err != nil {
		t.Fatal(err)
	}
	if got := e.raw(t, `SELECT status || ' ' || sandbox::text FROM messages WHERE id = $1`, s.MessageID); got != "captured true" {
		t.Fatalf("sandbox message %q", got)
	}
	if mail, err := sink.List(context.Background(), to); err != nil || len(mail) != 1 {
		t.Fatalf("%d mails reached the sink; the sandbox one must not", len(mail))
	}

	sups := appsuppression.NewService(postgres.NewSuppressionRepository(e.db), e.audit)
	blocked := "blocked-" + e.tenant[:8] + "@example.com"
	if _, err := sups.Add(e.userCtx(), suppression.Suppression{OrgID: e.tenant, ApplicationID: live.ID, Email: blocked, Type: suppression.TypeManual}); err != nil {
		t.Fatal(err)
	}
	if _, err := sups.Add(e.userCtx(), suppression.Suppression{OrgID: e.tenant, Email: blocked, Type: suppression.TypeUnsubscribe}); err != nil {
		t.Fatal(err)
	}
	if r := send(live, blocked); r.Status != string(domainmsg.StatusSuppressed) {
		t.Fatalf("the application's own suppression: %s", r.Status)
	}
	if r := send(sandbox, blocked); r.Status != string(domainmsg.StatusQueued) {
		t.Fatalf("another application's suppression applied: %s", r.Status)
	}
	if _, total, _ := sups.List(context.Background(), appsuppression.Filter{TenantID: e.tenant, ApplicationID: live.ID, Limit: 10}); total != 1 {
		t.Fatalf("scoped list %d", total)
	}

	page, total, err := svc.List(context.Background(), appmessage.Filter{TenantID: e.tenant, ApplicationID: sandbox.ID, Limit: 10})
	if err != nil || total != 2 || page[0].ApplicationID != sandbox.ID {
		t.Fatalf("list by application: %d %v", total, err)
	}
	u, err := e.svc.Usage(context.Background(), e.tenant, live.ID, 7)
	if err != nil || u.Totals["sent"] != 1 || u.Totals["suppressed"] != 1 || u.Daily[6].Total != 2 {
		t.Fatalf("usage %+v %v", u, err)
	}
}

// Idempotency-Key responses: the first claim wins, a live key returns the
// stored response, a released key can be claimed again, and an expired
// one is taken over and purged.
func TestIdempotencyStoreOnPostgres(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	repo := postgres.NewIdempotencyRepository(db)
	scope, key := "app-"+uuid.NewString(), "order-1"
	if _, fresh, err := repo.Claim(ctx, scope, key, "h1", time.Now().Add(time.Hour)); err != nil || !fresh {
		t.Fatalf("first claim: %v %v", fresh, err)
	}
	rec, fresh, err := repo.Claim(ctx, scope, key, "h1", time.Now().Add(time.Hour))
	if err != nil || fresh || rec.Status != 0 || rec.RequestSHA256 != "h1" {
		t.Fatalf("in progress: %+v %v %v", rec, fresh, err)
	}
	if err := repo.Complete(ctx, scope, key, 201, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if rec, _, _ := repo.Claim(ctx, scope, key, "h2", time.Now().Add(time.Hour)); rec.Status != 201 || string(rec.Body) != `{"ok":true}` || rec.RequestSHA256 != "h1" {
		t.Fatalf("stored: %+v", rec)
	}
	if err := repo.Release(ctx, scope, key); err != nil {
		t.Fatal(err)
	}
	if _, fresh, _ := repo.Claim(ctx, scope, key, "h3", time.Now().Add(-time.Second)); !fresh {
		t.Fatal("a released key was not claimable")
	}
	if _, fresh, _ := repo.Claim(ctx, scope, key, "h4", time.Now().Add(time.Hour)); !fresh {
		t.Fatal("an expired key was not taken over")
	}
	if _, err := db.Exec(ctx, `UPDATE idempotency_keys SET expires_at = now() - interval '1 minute' WHERE scope = $1`, scope); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.PurgeExpired(ctx); err != nil || n < 1 {
		t.Fatalf("purge %d %v", n, err)
	}
}
