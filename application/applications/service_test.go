package applications

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/application"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

const (
	tenantA = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"
	tenantB = "0b6c1c3e-6a38-4a8f-9a59-2b9d3b6a8a11"
)

type env struct {
	svc     *Service
	repo    *memRepo
	counter *memCounter
	audit   *memAudit
	tenants *nopTenants
}

func newEnv() *env {
	e := &env{repo: newMemRepo(), counter: newCounter(), audit: &memAudit{}, tenants: &nopTenants{}}
	e.svc = NewService(e.repo, fakeDomains{verified: []string{"bank.example"}}, e.counter, e.tenants, e.audit,
		Config{ReservedClients: []string{"mailos-console"}})
	e.svc.now = func() time.Time { return time.Date(2026, 10, 31, 12, 0, 30, 0, time.UTC) }
	return e
}

func serverInput() Input {
	return Input{Name: "Core banking", Kind: domain.KindServer, ClientID: "core-banking", Environment: domain.EnvLive,
		MessageTypes: []string{"bank.otp.*", "welcome"}, Senders: []string{"otp@bank.example", "*@alerts.bank.example"},
		DefaultFromEmail: "otp@bank.example", DefaultFromName: "Bank", RatePerMinute: 2, DailyQuota: 3}
}

func spaInput() Input {
	return Input{Name: "Portal", Kind: domain.KindSPA, ClientID: "portal-web", Environment: domain.EnvLive,
		MessageTypes: []string{"verify-email"}, Senders: []string{"hello@bank.example"}, DefaultFromEmail: "hello@bank.example",
		RatePerMinute: 100, DailyQuota: 100, BrowserTemplates: []string{"verify-email"}, UserRatePerHour: 2,
		AllowedOrigins: []string{"https://portal.bank.example"}}
}

func (e *env) create(t *testing.T, in Input) domain.Application {
	t.Helper()
	a, err := e.svc.Create(context.Background(), tenantA, in, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func svcCtx(a domain.Application) context.Context {
	return access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindService, ClientID: a.ClientID,
		TenantID: a.TenantID, ApplicationID: a.ID})
}

func TestCreateValidatesAndAudits(t *testing.T) {
	e := newEnv()
	a := e.create(t, serverInput())
	if a.Status != domain.StatusActive || a.TenantID != tenantA || e.audit.last().Action != "application.created" {
		t.Fatalf("%+v %v", a, e.audit.last())
	}
	in := serverInput()
	in.Senders = []string{"otp@other.example"}
	in.ClientID, in.Name, in.DefaultFromEmail = "other", "Other", ""
	if _, err := e.svc.Create(context.Background(), tenantA, in, "admin"); apperrors.DetailsOf(err)[0].Code != "unverified_domain" {
		t.Fatalf("unverified sender domain: %v", err)
	}
	in = serverInput()
	in.ClientID, in.Name = "mailos-console", "Console"
	if _, err := e.svc.Create(context.Background(), tenantA, in, "admin"); apperrors.DetailsOf(err)[0].Code != "reserved" {
		t.Fatalf("console client: %v", err)
	}
	in = serverInput()
	in.Name = "Second"
	if _, err := e.svc.Create(context.Background(), tenantB, in, "admin"); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("a client is one application across tenants: %v", err)
	}
	in = serverInput()
	in.Environment = ""
	in.ClientID, in.Name = "c2", "Defaults"
	b, err := e.svc.Create(context.Background(), tenantA, in, "admin")
	if err != nil || b.Environment != domain.EnvSandbox || b.Stream != domain.StreamTransactional {
		t.Fatalf("defaults: %+v %v", b, err)
	}
}

func TestSystemApplicationIsManagedByConfig(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	spec := SystemSpec{ClientID: "mailos-iam", TenantID: tenantA, Name: "IAM", Topics: []string{"iam.*"}}
	a, err := e.svc.SeedSystem(ctx, spec)
	if err != nil || !a.System || a.Environment != domain.EnvLive || a.RatePerMinute != 0 || len(e.tenants.ensured) != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	again, err := e.svc.SeedSystem(ctx, spec)
	if err != nil || again.ID != a.ID || len(e.repo.apps) != 1 {
		t.Fatalf("second seed: %+v %v", again, err)
	}
	if _, err := e.svc.Suspend(ctx, tenantA, a.ID, "incident", "admin"); err != nil {
		t.Fatal(err)
	}
	spec.Topics = []string{"iam.*", "iam2.*"}
	updated, err := e.svc.SeedSystem(ctx, spec)
	if err != nil || len(updated.MessageTypes) != 2 || updated.Status != domain.StatusSuspended {
		t.Fatalf("seed keeps the administrator's status: %+v %v", updated, err)
	}
	if _, err := e.svc.Update(ctx, tenantA, a.ID, serverInput(), "admin"); !errors.Is(err, ErrManagedByConfig) {
		t.Fatalf("update of a system application: %v", err)
	}
	if err := e.svc.Delete(ctx, tenantA, a.ID, "admin"); !errors.Is(err, ErrManagedByConfig) {
		t.Fatalf("delete of a system application: %v", err)
	}
	if _, err := e.svc.SeedSystem(ctx, SystemSpec{ClientID: "mailos-iam", TenantID: tenantB, Name: "IAM", Topics: []string{"iam.*"}}); err == nil {
		t.Fatal("seeding the client for another tenant took the application over")
	}
	plain := e.create(t, serverInput())
	if _, err := e.svc.SeedSystem(ctx, SystemSpec{ClientID: plain.ClientID, TenantID: tenantA, Name: "IAM", Topics: []string{"iam.*"}}); err == nil {
		t.Fatal("configuration took over a tenant application")
	}
}

func TestSuspendActivateDelete(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	a := e.create(t, serverInput())
	s, err := e.svc.Suspend(ctx, tenantA, a.ID, "compromised", "admin")
	if err != nil || s.Status != domain.StatusSuspended || s.SuspendedReason != "compromised" || e.audit.last().Action != "application.suspended" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, _, err := e.svc.ResolveService(ctx, access.Principal{Kind: access.KindService, ClientID: a.ClientID}); !errors.Is(err, domain.ErrSuspended) {
		t.Fatalf("suspended application called: %v", err)
	}
	r, err := e.svc.Activate(ctx, tenantA, a.ID, "admin")
	if err != nil || r.Status != domain.StatusActive || r.SuspendedReason != "" || e.audit.last().Action != "application.activated" {
		t.Fatalf("%+v %v", r, err)
	}
	if err := e.svc.Delete(ctx, tenantA, a.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.ResolveService(ctx, access.Principal{Kind: access.KindService, ClientID: a.ClientID}); !errors.Is(err, domain.ErrUnknownClient) {
		t.Fatalf("deleted application called: %v", err)
	}
}

func TestResolveService(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	a := e.create(t, serverInput())
	spa := e.create(t, spaInput())
	for name, c := range map[string]struct {
		p    access.Principal
		want error
	}{
		"unknown":       {access.Principal{Kind: access.KindService, ClientID: "intruder"}, domain.ErrUnknownClient},
		"no client":     {access.Principal{Kind: access.KindService}, domain.ErrUnknownClient},
		"user":          {access.Principal{Kind: access.KindUser, ClientID: a.ClientID}, domain.ErrNotService},
		"spa client":    {access.Principal{Kind: access.KindService, ClientID: spa.ClientID}, domain.ErrKindMismatch},
		"other tenant":  {access.Principal{Kind: access.KindService, ClientID: a.ClientID, TenantID: tenantB}, domain.ErrTenantMismatch},
		"token tenant":  {access.Principal{Kind: access.KindService, ClientID: a.ClientID, TenantID: tenantA}, nil},
		"no tid at all": {access.Principal{Kind: access.KindService, ClientID: a.ClientID}, nil},
	} {
		_, p, err := e.svc.ResolveService(ctx, c.p)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
			continue
		}
		if c.want == nil && (p.TenantID != tenantA || p.ApplicationID != a.ID) {
			t.Errorf("%s: principal %+v", name, p)
		}
	}
}

func TestResolveBrowser(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	server := e.create(t, serverInput())
	spa := e.create(t, spaInput())
	user := access.Principal{Kind: access.KindUser, Subject: "u1", TenantID: tenantA, Roles: []access.Role{access.RoleAdmin},
		Scopes: []string{"openid", domain.SelfSendScope}}

	console := user
	console.ClientID = "mailos-console"
	if _, p, ok, err := e.svc.ResolveBrowser(ctx, console); ok || err != nil || len(p.Roles) != 1 {
		t.Fatalf("console user: ok=%v err=%v", ok, err)
	}
	u := user
	u.ClientID = spa.ClientID
	_, p, ok, err := e.svc.ResolveBrowser(ctx, u)
	if !ok || err != nil || !p.SelfService || len(p.Roles) != 0 || p.ApplicationID != spa.ID || p.Can(access.PermTemplatesEdit) {
		t.Fatalf("spa user keeps more than self-send: %+v ok=%v err=%v", p, ok, err)
	}
	u.Scopes = []string{"openid"}
	if _, _, _, err := e.svc.ResolveBrowser(ctx, u); !errors.Is(err, domain.ErrScopeMissing) {
		t.Fatalf("no scope: %v", err)
	}
	u.Scopes, u.TenantID = []string{domain.SelfSendScope}, tenantB
	if _, _, _, err := e.svc.ResolveBrowser(ctx, u); !errors.Is(err, domain.ErrTenantMismatch) {
		t.Fatalf("other tenant: %v", err)
	}
	u = user
	u.ClientID = server.ClientID
	if _, _, ok, err := e.svc.ResolveBrowser(ctx, u); !ok || !errors.Is(err, domain.ErrKindMismatch) {
		t.Fatalf("user token from a server application: %v", err)
	}
}

func TestAuthorizeEvent(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	a := e.create(t, serverInput())
	p := access.Principal{Kind: access.KindService, ClientID: a.ClientID}
	if _, got, err := e.svc.AuthorizeEvent(ctx, p, "bank.otp.login", tenantA); err != nil || got.TenantID != tenantA {
		t.Fatalf("%+v %v", got, err)
	}
	if _, _, err := e.svc.AuthorizeEvent(ctx, p, "iam.user.created", ""); !errors.Is(err, domain.ErrTypeNotAllowed) {
		t.Fatalf("topic: %v", err)
	}
	if _, _, err := e.svc.AuthorizeEvent(ctx, p, "bank.otp.login", tenantB); !errors.Is(err, domain.ErrTenantMismatch) {
		t.Fatalf("event for another tenant: %v", err)
	}
}

func refusal(t *testing.T, err error) (string, int) {
	t.Helper()
	status := http.StatusForbidden
	if apperrors.KindOf(err) == apperrors.KindRateLimited {
		status = http.StatusTooManyRequests
	} else if apperrors.KindOf(err) != apperrors.KindForbidden {
		t.Fatalf("not a refusal: %v", err)
	}
	return domain.Reason(err), status
}

func TestAuthorizeSendRules(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Input)
		ask    Ask
		reason string
	}{
		"type":             {nil, Ask{Keys: []string{"iam.user.created", "iam-user"}}, "message_type_not_allowed"},
		"raw":              {nil, Ask{Raw: true}, "raw_content_not_allowed"},
		"sender":           {nil, Ask{Keys: []string{"welcome"}, FromEmail: "ceo@bank.example"}, "sender_not_allowed"},
		"sender required":  {func(in *Input) { in.DefaultFromEmail = "" }, Ask{Keys: []string{"welcome"}}, "sender_required"},
		"subdomain sender": {nil, Ask{Keys: []string{"welcome"}, FromEmail: "x@alerts.bank.example"}, ""},
		"stream":           {nil, Ask{Keys: []string{"welcome"}, Type: domainmsg.TypeMarketing}, "stream_mismatch"},
		"default and ok":   {nil, Ask{Keys: []string{"", "welcome"}}, ""},
		"explicit allowed": {nil, Ask{Keys: []string{"bank.otp.login"}, FromEmail: "news@alerts.bank.example"}, ""},
	}
	for name, c := range cases {
		e := newEnv()
		in := serverInput()
		if c.mutate != nil {
			c.mutate(&in)
		}
		a := e.create(t, in)
		g, err := e.svc.AuthorizeSend(svcCtx(a), a.ID, c.ask)
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if name == "default and ok" && (g.FromEmail != "otp@bank.example" || g.FromName != "Bank" || g.Sandbox || g.ApplicationID != a.ID) {
				t.Errorf("%s: grant %+v", name, g)
			}
			continue
		}
		if r, _ := refusal(t, err); r != c.reason {
			t.Errorf("%s: reason %q, want %q (%v)", name, r, c.reason, err)
		}
		last := e.audit.last()
		if last.Action != AuditSendRefused || last.Meta["reason"] != c.reason || last.Meta["application_id"] != a.ID {
			t.Errorf("%s: audit %+v", name, last)
		}
	}
}

func TestAuthorizeSendRefusesSenderOnUnverifiedDomain(t *testing.T) {
	e := newEnv()
	a := e.create(t, serverInput())
	// The domain was verified when the application was saved, then failed.
	e.svc.domains = fakeDomains{}
	_, err := e.svc.AuthorizeSend(svcCtx(a), a.ID, Ask{Keys: []string{"welcome"}})
	if r, _ := refusal(t, err); r != "sender_domain_unverified" {
		t.Fatalf("%q %v", r, err)
	}
}

func TestAuthorizeSendSandboxAndBroadcast(t *testing.T) {
	e := newEnv()
	in := serverInput()
	in.Environment, in.Stream = domain.EnvSandbox, domain.StreamBroadcast
	a := e.create(t, in)
	g, err := e.svc.AuthorizeSend(svcCtx(a), a.ID, Ask{Keys: []string{"welcome"}, Type: domainmsg.TypeTransactional})
	if err != nil || !g.Sandbox || g.Stream != domain.StreamBroadcast || g.Type != domainmsg.TypeMarketing {
		t.Fatalf("%+v %v", g, err)
	}
}

func TestAuthorizeSendLimits(t *testing.T) {
	e := newEnv()
	a := e.create(t, serverInput()) // 2 per minute, 3 per day
	ctx := svcCtx(a)
	ask := Ask{Keys: []string{"welcome"}}
	for i := 0; i < 2; i++ {
		if _, err := e.svc.AuthorizeSend(ctx, a.ID, ask); err != nil {
			t.Fatal(i, err)
		}
	}
	_, err := e.svc.AuthorizeSend(ctx, a.ID, ask)
	if r, status := refusal(t, err); r != "rate_limited" || status != 429 {
		t.Fatalf("rate: %q %d", r, status)
	}
	if used, _ := e.counter.Peek(context.Background(), quotaKey(a.ID, e.svc.now())); used != 2 {
		t.Fatalf("a rate-limited message kept its quota: %d", used)
	}
	e.svc.now = func() time.Time { return time.Date(2026, 10, 31, 12, 1, 30, 0, time.UTC) }
	if _, err := e.svc.AuthorizeSend(ctx, a.ID, ask); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.AuthorizeSend(ctx, a.ID, ask)
	if r, status := refusal(t, err); r != "quota_exceeded" || status != 429 {
		t.Fatalf("quota: %q %d", r, status)
	}
	var ae *apperrors.AppError
	if !errors.As(err, &ae) || ae.RetryAfterSeconds <= 0 || ae.RetryAfterSeconds > 86400 {
		t.Fatalf("retry after: %+v", ae)
	}
	e.counter.fail = true
	if _, err := e.svc.AuthorizeSend(ctx, a.ID, ask); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("counters down must fail closed: %v", err)
	}
	u, err := e.svc.Usage(context.Background(), tenantA, a.ID, 7)
	if err != nil || u.QuotaUsedToday != 3 || u.DailyQuota != 3 || len(u.Daily) != 7 {
		t.Fatalf("usage %+v %v", u, err)
	}
}

func TestAuthorizeSendSuspended(t *testing.T) {
	e := newEnv()
	a := e.create(t, serverInput())
	if _, err := e.svc.Suspend(context.Background(), tenantA, a.ID, "", "admin"); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.AuthorizeSend(svcCtx(a), a.ID, Ask{Keys: []string{"welcome"}})
	if r, _ := refusal(t, err); r != "application_suspended" {
		t.Fatalf("%q", r)
	}
}

func TestAuthorizeSelfSend(t *testing.T) {
	e := newEnv()
	a := e.create(t, spaInput())
	base := access.Principal{Kind: access.KindUser, Subject: "u1", ClientID: a.ClientID, TenantID: tenantA, SelfService: true,
		ApplicationID: a.ID, Email: "Person@Example.com", EmailVerified: true}
	good := SelfSend{TemplateSlug: "verify-email", Origin: "https://portal.bank.example"}
	for name, c := range map[string]struct {
		mutate func(*access.Principal, *SelfSend)
		reason string
	}{
		"origin":     {func(_ *access.Principal, s *SelfSend) { s.Origin = "https://evil.example" }, "origin_not_allowed"},
		"no origin":  {func(_ *access.Principal, s *SelfSend) { s.Origin = "" }, "origin_not_allowed"},
		"template":   {func(_ *access.Principal, s *SelfSend) { s.TemplateSlug = "password-reset" }, "template_not_browser_allowed"},
		"unverified": {func(p *access.Principal, _ *SelfSend) { p.EmailVerified = false }, "no_verified_email"},
		"no email":   {func(p *access.Principal, _ *SelfSend) { p.Email = "" }, "no_verified_email"},
	} {
		p, s := base, good
		c.mutate(&p, &s)
		_, err := e.svc.AuthorizeSelfSend(access.WithPrincipal(context.Background(), p), s)
		if r, _ := refusal(t, err); r != c.reason {
			t.Errorf("%s: %q, want %q", name, r, c.reason)
		}
	}
	ctx := access.WithPrincipal(context.Background(), base)
	for i := 0; i < 2; i++ {
		to, err := e.svc.AuthorizeSelfSend(ctx, good)
		if err != nil || to != "person@example.com" {
			t.Fatalf("%d: %q %v", i, to, err)
		}
	}
	_, err := e.svc.AuthorizeSelfSend(ctx, good)
	if r, status := refusal(t, err); r != "user_rate_limited" || status != 429 {
		t.Fatalf("per-user limit: %q %d", r, status)
	}
	other := base
	other.Subject = "u2"
	if _, err := e.svc.AuthorizeSelfSend(access.WithPrincipal(context.Background(), other), good); err != nil {
		t.Fatalf("the limit is per user: %v", err)
	}
	notSelf := base
	notSelf.SelfService = false
	if _, err := e.svc.AuthorizeSelfSend(access.WithPrincipal(context.Background(), notSelf), good); apperrors.KindOf(err) != apperrors.KindForbidden {
		t.Fatalf("console user self-send: %v", err)
	}
}

func TestUsageCounts(t *testing.T) {
	e := newEnv()
	a := e.create(t, serverInput())
	day := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	e.repo.counts = []StatusCount{{Day: day, Status: "sent", Count: 4}, {Day: day, Status: "failed", Count: 1},
		{Day: day.AddDate(0, 0, -1), Status: "captured", Count: 2}}
	u, err := e.svc.Usage(context.Background(), tenantA, a.ID, 0)
	if err != nil || u.Days != 30 || u.Totals["sent"] != 4 || u.Totals["captured"] != 2 || u.Totals["queued"] != 0 {
		t.Fatalf("%+v %v", u, err)
	}
	last := u.Daily[len(u.Daily)-1]
	if last.Day != "2026-10-31" || last.Total != 5 || last.Sent != 4 || last.Failed != 1 || u.Daily[len(u.Daily)-2].Captured != 2 {
		t.Fatalf("daily %+v", u.Daily[len(u.Daily)-2:])
	}
	if _, err := e.svc.Usage(context.Background(), tenantA, a.ID, 91); err == nil {
		t.Fatal("91 days accepted")
	}
}
