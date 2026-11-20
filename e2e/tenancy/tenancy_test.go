//go:build e2e

// Package tenancy proves tenant isolation from outside: everything tenant A
// creates is invisible to tenant B's administrator, by id and in lists, and
// B can change or delete none of it, even with A's ids in hand.
package tenancy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "tenancy", &fx) }

// world is what tenant A owns.
type world struct {
	template, message, provider, domain, webhook, contact, list, campaign string
	suppressed, recipient                                                 string
}

func build(t *testing.T) world {
	t.Helper()
	a := fx.Admin(t)
	var w world
	w.template = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates",
		map[string]any{"name": "A only", "slug": "a-only-" + harness.Unique()}).Data(), "id")
	draft := a.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+w.template+"/draft", map[string]any{
		"locale": "en", "revision": 0, "subject": "Tenant A secret subject", "html_body": "<p>Hello {{name}}</p>", "text_body": "Hello {{name}}",
	}).Data()
	a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+w.template+"/publish",
		map[string]any{"locale": "en", "revision": draft["revision"]})

	w.recipient = harness.NewEmail("tenant-a")
	w.message = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", map[string]any{
		"to_email": w.recipient, "subject": "A's message", "text_body": "for A only",
	}).Data(), "message_id")
	w.provider = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/providers", map[string]any{
		"name": "A relay", "type": "sendgrid", "is_active": false, "configuration": map[string]any{"api_key": "SG.tenant-a-secret-" + harness.Unique()},
	}).Data(), "id")
	w.domain = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/sending-domains",
		map[string]any{"domain": "a-" + harness.Unique() + ".example.com"}).Data(), "id")
	w.webhook = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/webhooks",
		map[string]any{"url": "https://hooks.example.com/a", "events": []string{"message.sent"}}).Data(), "id")
	w.contact = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/contacts",
		map[string]any{"email": harness.NewEmail("contact-a"), "first_name": "Alice"}).Data(), "id")
	w.list = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/contact-lists",
		map[string]any{"name": "A list", "type": "static"}).Data(), "id")
	a.Expect(t, http.StatusNoContent, http.MethodPost, "/api/v1/contact-lists/"+w.list+"/members", map[string]any{"contact_ids": []string{w.contact}})
	w.campaign = harness.Str(a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/campaigns", map[string]any{
		"name": "A campaign", "subject": "Hi", "from_name": "A", "from_email": "news@a.example.com",
		"template_id": w.template, "contact_list_id": w.list, "type": "regular",
	}).Data(), "id")
	w.suppressed = harness.NewEmail("suppressed-a")
	a.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/suppressions", map[string]any{"email": w.suppressed, "type": "manual", "reason": "A asked"})
	return w
}

func other(t *testing.T) *harness.Client {
	t.Helper()
	return fx.As(t, harness.User{Tenant: harness.NewID(), Org: harness.NewID(), Roles: []string{harness.RoleAdmin}})
}

func TestAnotherTenantSeesNothingByID(t *testing.T) {
	w := build(t)
	b := other(t)
	for _, path := range []string{
		"/api/v1/templates/" + w.template, "/api/v1/templates/" + w.template + "/draft", "/api/v1/templates/" + w.template + "/versions",
		"/api/v1/templates/" + w.template + "/active-version", "/api/v1/messages/" + w.message, "/api/v1/messages/" + w.message + "/body",
		"/api/v1/providers/" + w.provider, "/api/v1/sending-domains/" + w.domain, "/api/v1/webhooks/" + w.webhook,
		"/api/v1/contacts/" + w.contact, "/api/v1/contact-lists/" + w.list, "/api/v1/contact-lists/" + w.list + "/members",
		"/api/v1/campaigns/" + w.campaign,
	} {
		r := b.Do(t, http.MethodGet, path, nil)
		if r.Status != http.StatusNotFound {
			t.Errorf("tenant B GET %s = %s, want 404", path, r)
		}
	}
}

func TestAnotherTenantChangesNothing(t *testing.T) {
	w := build(t)
	b := other(t)
	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/api/v1/templates/" + w.template, map[string]any{"name": "Taken over"}},
		{http.MethodPut, "/api/v1/templates/" + w.template + "/draft", map[string]any{"locale": "en", "revision": 1, "subject": "x", "html_body": "<p>x</p>", "text_body": "x"}},
		{http.MethodPost, "/api/v1/templates/" + w.template + "/publish", map[string]any{"locale": "en", "revision": 1}},
		{http.MethodPost, "/api/v1/templates/" + w.template + "/versions/1/restore", map[string]any{"locale": "en", "revision": 1}},
		{http.MethodPost, "/api/v1/templates/" + w.template + "/preview", map[string]any{"locale": "en"}},
		{http.MethodPost, "/api/v1/templates/" + w.template + "/test-send", map[string]any{"locale": "en", "to_email": harness.NewEmail("b")}},
		{http.MethodPost, "/api/v1/messages/" + w.message + "/resend", nil},
		{http.MethodPost, "/api/v1/messages/" + w.message + "/cancel", nil},
		{http.MethodPut, "/api/v1/providers/" + w.provider, map[string]any{"name": "Taken over"}},
		{http.MethodPost, "/api/v1/sending-domains/" + w.domain + "/verify", nil},
		{http.MethodPut, "/api/v1/webhooks/" + w.webhook, map[string]any{"url": "https://evil.example.com/steal"}},
		{http.MethodPut, "/api/v1/contacts/" + w.contact, map[string]any{"first_name": "Mallory"}},
		{http.MethodPut, "/api/v1/contact-lists/" + w.list, map[string]any{"name": "Taken over"}},
		{http.MethodPost, "/api/v1/contact-lists/" + w.list + "/members", map[string]any{"contact_ids": []string{w.contact}}},
		{http.MethodPut, "/api/v1/campaigns/" + w.campaign, map[string]any{"name": "Taken over"}},
		{http.MethodPost, "/api/v1/campaigns/" + w.campaign + "/launch", nil},
		{http.MethodDelete, "/api/v1/campaigns/" + w.campaign, nil},
		{http.MethodDelete, "/api/v1/contact-lists/" + w.list, nil},
		{http.MethodDelete, "/api/v1/contacts/" + w.contact, nil},
		{http.MethodDelete, "/api/v1/webhooks/" + w.webhook, nil},
		{http.MethodDelete, "/api/v1/sending-domains/" + w.domain, nil},
		{http.MethodDelete, "/api/v1/providers/" + w.provider, nil},
		{http.MethodDelete, "/api/v1/templates/" + w.template, nil},
	}
	for _, wr := range writes {
		r := b.Do(t, wr.method, wr.path, wr.body)
		if r.Status != http.StatusNotFound {
			t.Errorf("tenant B %s %s = %s, want 404", wr.method, wr.path, r)
		}
	}
	// B removing A's suppression by address removes nothing of A's.
	b.Do(t, http.MethodDelete, "/api/v1/suppressions?email="+w.suppressed, nil)

	a := fx.Admin(t)
	if name := harness.Str(a.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates/"+w.template, nil).Data(), "name"); name != "A only" {
		t.Errorf("A's template is now %q", name)
	}
	if u := harness.Str(a.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/webhooks/"+w.webhook, nil).Data(), "url"); u != "https://hooks.example.com/a" {
		t.Errorf("A's webhook now posts to %q", u)
	}
	for _, path := range []string{"/api/v1/providers/" + w.provider, "/api/v1/sending-domains/" + w.domain, "/api/v1/contacts/" + w.contact,
		"/api/v1/contact-lists/" + w.list, "/api/v1/campaigns/" + w.campaign} {
		a.Expect(t, http.StatusOK, http.MethodGet, path, nil)
	}
	if !strings.Contains(a.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/suppressions?limit=100", nil).String(), w.suppressed) {
		t.Error("tenant B removed A's suppression")
	}
}

func TestListsAreTenantScoped(t *testing.T) {
	w := build(t)
	b := other(t)
	for _, path := range []string{"/api/v1/templates", "/api/v1/messages", "/api/v1/providers", "/api/v1/sending-domains", "/api/v1/webhooks",
		"/api/v1/contacts", "/api/v1/contact-lists", "/api/v1/campaigns", "/api/v1/suppressions", "/api/v1/analytics/audit-logs",
		"/api/v1/analytics/audit-logs/export", "/api/v1/organizations"} {
		r := b.Expect(t, http.StatusOK, http.MethodGet, path+"?limit=100", nil)
		for _, leak := range []string{w.template, w.message, w.provider, w.domain, w.webhook, w.contact, w.list, w.campaign, w.suppressed, w.recipient, fx.TenantID} {
			if strings.Contains(r.String(), leak) {
				t.Errorf("tenant B %s shows A's %s", path, leak)
			}
		}
	}
	stats := b.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/stats", nil)
	if strings.Contains(stats.String(), `"sent":1`) {
		t.Errorf("tenant B's stats count A's mail: %s", stats)
	}
}

func TestSuppressionDoesNotCrossTenants(t *testing.T) {
	box := fx.Env.NewMailbox("shared")
	fx.Admin(t).Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/suppressions", map[string]any{"email": box.Address, "type": "manual"})
	b := other(t)
	b.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", map[string]any{
		"to_email": box.Address, "subject": "From tenant B", "text_body": "B may still mail this person",
	})
	box.WaitSubject(t, "From tenant B")
}

func TestServiceTokenTenantCannotBeOverridden(t *testing.T) {
	ev := map[string]any{"id": harness.NewID(), "type": "iam.auth.mfa_email_code_requested", "tenant_uuid": harness.NewID(),
		"data": map[string]any{"email": harness.NewEmail("x"), "code": "123456", "purpose": "sign_in", "expires_in_minutes": 5}}
	fx.Service(t, "mailos-iam").ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/events", ev)
}
