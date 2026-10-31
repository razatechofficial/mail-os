//go:build e2e

// Package applications drives the application registry end to end: an
// administrator registers a project's IAM client as an application of the
// tenant, the project sends with its own client-credentials token within
// the application's rules, retries are idempotent, limits and suspension
// hold, sandbox mail is captured, and a browser application's user sends
// only a browser-allowed template to their own verified address.
package applications

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "applications", &fx) }

// register creates an application of the package's tenant as admin, with
// overrides on top of a live server application sending raw content from
// the verified domain, and returns it.
func register(t *testing.T, domain string, over map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{
		"name": "Core banking " + harness.Unique(), "kind": "server", "client_id": "core-" + harness.Unique(),
		"environment": "live", "stream": "transactional", "message_types": []string{"raw", "bank.*"},
		"senders": []string{"*@" + domain}, "default_from_email": "alerts@" + domain, "default_from_name": "Bank alerts",
		"rate_limit_per_minute": 100, "daily_quota": 1000,
	}
	for k, v := range over {
		body[k] = v
	}
	return fx.Admin(t).Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/applications", body).Data()
}

func raw(to string) map[string]any {
	return map[string]any{"to_email": to, "subject": "Your statement is ready", "text_body": "Hello"}
}

func key(k string) http.Header { return http.Header{"Idempotency-Key": []string{k}} }

func TestServerApplicationSendsWithinItsRules(t *testing.T) {
	domain := fx.VerifiedDomain(t)
	app := register(t, domain, map[string]any{"daily_quota": 4})
	client, id := harness.Str(app, "client_id"), harness.Str(app, "id")
	svc := fx.Service(t, client)
	box := fx.Env.NewMailbox("statement")

	first := svc.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", raw(box.Address), key("stmt-1")).Data()
	again := svc.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", raw(box.Address), key("stmt-1"))
	if harness.Str(again.Data(), "message_id") != harness.Str(first, "message_id") || again.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("retry with the same key: %s", again)
	}
	svc.ExpectError(t, http.StatusConflict, "CONFLICT", http.MethodPost, "/api/v1/messages/send", raw("other@mailos.test"), key("stmt-1"))
	mail := box.WaitSubject(t, "Your statement is ready")
	if !strings.Contains(mail.From, "alerts@"+domain) {
		t.Fatalf("sent from %q, want the application's default sender", mail.From)
	}
	time.Sleep(time.Second)
	if n := len(box.Messages(t)); n != 1 {
		t.Fatalf("%d mails for one idempotent send", n)
	}

	// Outside its rules: another sender, a message type it does not have,
	// a token for another tenant.
	bad := raw(box.Address)
	bad["from_email"] = "ceo@" + domain + ".evil.test"
	r := svc.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/send", bad)
	if !strings.Contains(r.String(), "sender") {
		t.Fatalf("refusal does not say why: %s", r)
	}
	other := "statement-" + harness.Unique()
	publishPlain(t, other)
	r = svc.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/send",
		map[string]any{"to_email": box.Address, "template_slug": other})
	if !strings.Contains(r.String(), "message type") {
		t.Fatalf("type refusal: %s", r)
	}
	foreign := fx.Env.NewClient().WithBearer(fx.Env.ServiceToken(t, client, harness.NewID()))
	foreign.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/send", raw(box.Address))
	fx.Service(t, "unregistered-"+harness.Unique()).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost,
		"/api/v1/messages/send", raw(box.Address))

	// The service may send; it may not read the console's resources.
	svc.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/v1/applications", nil)

	// Suspended, nothing goes; active again, it does.
	admin := fx.Admin(t)
	admin.Expect(t, http.StatusOK, http.MethodPost, "/api/v1/applications/"+id+"/suspend", map[string]any{"reason": "key rotation"})
	fx.Service(t, client).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/send", raw(box.Address))
	admin.Expect(t, http.StatusOK, http.MethodPost, "/api/v1/applications/"+id+"/activate", nil)

	// The daily quota of 4: one sent, three more, then 429.
	svc = fx.Service(t, client)
	for i := 0; i < 3; i++ {
		svc.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", raw(box.Address))
	}
	r = svc.ExpectError(t, http.StatusTooManyRequests, "RATE_LIMITED", http.MethodPost, "/api/v1/messages/send", raw(box.Address))
	if r.Header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After on the quota refusal")
	}

	usage := admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/applications/"+id+"/usage?days=7", nil).Data()
	if usage["quota_used_today"] != float64(4) || usage["daily_quota"] != float64(4) {
		t.Fatalf("usage %v", usage)
	}
	msgs := admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages?application_id="+id, nil).Items()
	if len(msgs) != 4 || harness.Str(msgs[0], "application_id") != id {
		t.Fatalf("messages of the application: %d", len(msgs))
	}
	audit := string(admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs?resource=application&limit=100", nil).Body)
	for _, want := range []string{"sender_not_allowed", "quota_exceeded", "application.suspended"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit has no %s", want)
		}
	}
}

func TestOnlyAdministratorsManageApplications(t *testing.T) {
	domain := fx.VerifiedDomain(t)
	app := register(t, domain, nil)
	viewer, _ := fx.NewUser(t, harness.RoleViewer)
	viewer.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/applications/"+harness.Str(app, "id"), nil)
	operator, _ := fx.NewUser(t, harness.RoleOperator)
	operator.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/applications/"+harness.Str(app, "id")+"/suspend", nil)
	stale := fx.As(t, harness.User{Roles: []string{harness.RoleAdmin}, AuthAge: 10 * time.Minute})
	stale.ExpectError(t, http.StatusForbidden, "STEP_UP_REQUIRED", http.MethodPost, "/api/v1/applications", map[string]any{"name": "x"})

	// Senders must be on a verified domain.
	r := fx.Admin(t).ExpectError(t, http.StatusUnprocessableEntity, "VALIDATION", http.MethodPost, "/api/v1/applications", map[string]any{
		"name": "Unverified", "kind": "server", "client_id": "u-" + harness.Unique(), "message_types": []string{"raw"},
		"senders": []string{"*@not-verified.mailos.test"}, "rate_limit_per_minute": 1, "daily_quota": 1,
	})
	if !strings.Contains(r.String(), "unverified_domain") {
		t.Fatalf("unverified sender: %s", r)
	}
}

func TestSandboxCapturesWithoutDelivering(t *testing.T) {
	domain := fx.VerifiedDomain(t)
	app := register(t, domain, map[string]any{"environment": "sandbox"})
	box := fx.Env.NewMailbox("sandbox")
	res := fx.Service(t, harness.Str(app, "client_id")).Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send",
		raw(box.Address)).Data()
	admin := fx.Admin(t)
	harness.Eventually(t, "the message is captured", 20*time.Second, func() bool {
		m := admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+harness.Str(res, "message_id"), nil).Data()
		return harness.Str(m, "status") == "captured" && m["sandbox"] == true
	})
	box.Empty(t, time.Second)
}

// publishPlain publishes a template without a topic under slug.
func publishPlain(t *testing.T, slug string) {
	t.Helper()
	admin := fx.Admin(t)
	tpl := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{
		"name": "Verify " + slug, "slug": slug, "default_locale": "en",
	}).Data()
	id := harness.Str(tpl, "id")
	draft := admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": 0, "subject": "Confirm your address",
		"html_body": "<p>Confirm your address</p>", "text_body": "Confirm your address", "variables": []string{}, "design": nil,
	}).Data()
	admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{
		"locale": "en", "revision": draft["revision"],
	})
}

func TestBrowserUserSendsOnlyToThemselves(t *testing.T) {
	domain := fx.VerifiedDomain(t)
	slug := "verify-" + harness.Unique()
	publishPlain(t, slug)
	publishPlain(t, "statement-"+harness.Unique())
	const origin = "https://portal.mailos.test"
	app := register(t, domain, map[string]any{"kind": "spa", "message_types": []string{slug}, "browser_templates": []string{slug},
		"allowed_origins": []string{origin}, "user_rate_limit_per_hour": 2})
	client := harness.Str(app, "client_id")
	me := fx.Env.NewMailbox("me")
	subject := harness.NewID()
	user := func(extra map[string]any) *harness.Client {
		claims := map[string]any{"scope": "openid email mailos.send.self", "email": me.Address, "email_verified": true}
		for k, v := range extra {
			claims[k] = v
		}
		return fx.As(t, harness.User{Subject: subject, ClientID: client, Roles: []string{harness.RoleAdmin}, Extra: claims})
	}
	from := http.Header{"Origin": []string{origin}}
	body := map[string]any{"template": slug, "to_email": "victim@mailos.test"}

	user(nil).Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/self", body, from)
	me.WaitSubject(t, "Confirm your address")
	fx.Env.Mailbox("victim@mailos.test").Empty(t, time.Second)

	// Not from its origin, not a browser template, not verified, not
	// scoped, and its console role is gone.
	user(nil).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/self", body,
		http.Header{"Origin": []string{"https://evil.mailos.test"}})
	user(nil).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/self",
		map[string]any{"template": "statement"}, from)
	user(map[string]any{"email_verified": false}).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost,
		"/api/v1/messages/self", body, from)
	user(map[string]any{"scope": "openid"}).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost,
		"/api/v1/messages/self", body, from)
	user(nil).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/v1/templates", nil)
	user(nil).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/send", raw("victim@mailos.test"))

	// Two an hour per user.
	user(nil).Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/self", body, from)
	user(nil).ExpectError(t, http.StatusTooManyRequests, "RATE_LIMITED", http.MethodPost, "/api/v1/messages/self", body, from)
}
