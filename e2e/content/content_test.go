//go:build e2e

// Package content covers what tenants author: the template lifecycle
// (revisions, versions, restore, preview, test send, delete), branding,
// and sending domains with their DNS records.
package content

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "content", &fx) }

func draft(t *testing.T, c *harness.Client, id string, rev any, subject, html string) map[string]any {
	t.Helper()
	return c.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": rev, "subject": subject, "html_body": html, "text_body": subject}).Data()
}

func TestTemplateLifecycle(t *testing.T) {
	ed, _ := fx.NewUser(t, harness.RoleTemplateEditor)
	pub, _ := fx.NewUser(t, harness.RoleTemplatePublisher)
	id := harness.Str(ed.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates",
		map[string]any{"name": "Statement", "slug": "statement-" + harness.Unique()}).Data(), "id")
	ed.ExpectError(t, http.StatusUnprocessableEntity, "VALIDATION", http.MethodPost, "/api/v1/templates",
		map[string]any{"name": "Dup", "slug": harness.Str(ed.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates/"+id, nil).Data(), "slug")})

	d1 := draft(t, ed, id, 0, "Version one", "<p>One {{name}}</p>")
	ed.ExpectError(t, http.StatusConflict, "", http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": 0, "subject": "Stale", "html_body": "<p>x</p>", "text_body": "x"})
	pub.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{"locale": "en", "revision": d1["revision"]})
	pub.ExpectError(t, http.StatusConflict, "", http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{"locale": "en", "revision": 99})

	d2 := draft(t, ed, id, d1["revision"], "Version two", "<p>Two {{name}}</p>")
	pub.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{"locale": "en", "revision": d2["revision"]})
	versions := ed.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates/"+id+"/versions?locale=en", nil).Items()
	if len(versions) != 2 {
		t.Fatalf("%d versions", len(versions))
	}
	active := ed.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates/"+id+"/active-version?locale=en", nil).Data()
	if active["subject"] != "Version two" || active["version"] != float64(2) {
		t.Fatalf("active version: %v", active)
	}

	restored := ed.Expect(t, http.StatusOK, http.MethodPost, "/api/v1/templates/"+id+"/versions/1/restore",
		map[string]any{"locale": "en", "revision": d2["revision"]}).Data()
	if restored["subject"] != "Version one" {
		t.Fatalf("restored draft: %v", restored)
	}
	if a := ed.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates/"+id+"/active-version?locale=en", nil).Data(); a["subject"] != "Version two" {
		t.Fatalf("a restore changed the live version: %v", a)
	}
	ed.ExpectError(t, http.StatusNotFound, "", http.MethodPost, "/api/v1/templates/"+id+"/versions/9/restore",
		map[string]any{"locale": "en", "revision": restored["revision"]})

	prev := ed.Expect(t, http.StatusOK, http.MethodPost, "/api/v1/templates/"+id+"/preview", map[string]any{
		"locale": "en", "subject": "Hi {{name}}", "html_body": "<p>Hi {{name}}</p>", "text_body": "Hi {{name}}",
		"data": map[string]any{"name": `<img src=x onerror=alert(1)>`}}).Data()
	if h := harness.Str(prev, "html"); strings.Contains(h, "<img") || !strings.Contains(h, "&lt;img") {
		t.Fatalf("preview does not escape variables: %s", h)
	}

	// A test send must come from one of the tenant's verified domains.
	ts := ed.ExpectError(t, http.StatusUnprocessableEntity, "VALIDATION", http.MethodPost, "/api/v1/templates/"+id+"/test-send",
		map[string]any{"locale": "en", "to_email": harness.NewEmail("testsend"), "from_name": "MMBL", "from_email": "alerts@example.com"})
	if !strings.Contains(ts.String(), "unverified_domain") {
		t.Fatalf("test send from an unverified domain: %s", ts)
	}

	ed.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodDelete, "/api/v1/templates/"+id, nil)
	fx.Admin(t).Expect(t, http.StatusNoContent, http.MethodDelete, "/api/v1/templates/"+id, nil)
	ed.ExpectError(t, http.StatusNotFound, "", http.MethodGet, "/api/v1/templates/"+id, nil)
}

func TestPublishedVersionIsWhatEventsRender(t *testing.T) {
	admin := fx.Admin(t)
	topic := "iam.auth.magic_link_requested"
	id := harness.Str(admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{
		"name": "Link", "slug": "link-" + harness.Unique(), "topic": topic, "default_locale": "en"}).Data(), "id")
	d := draft(t, admin, id, 0, "Live subject", "<p>Live</p>")
	admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{"locale": "en", "revision": d["revision"]})
	draft(t, admin, id, d["revision"], "Unpublished draft", "<p>Draft</p>")
	box := fx.Env.NewMailbox("live")
	fx.Service(t, "mailos-iam").Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", map[string]any{
		"id": harness.NewID(), "type": topic, "source": "iam", "data": map[string]any{"email": box.Address, "link": "https://iam.example.com/m/1"}})
	if mail := box.Wait(t, nil); mail.Subject != "Live subject" {
		t.Fatalf("an event rendered %q, want the published version", mail.Subject)
	}
}

func TestBranding(t *testing.T) {
	admin := fx.Admin(t)
	b := admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/template-branding", map[string]any{
		"company_name": "MMBL", "primary_color": "#0a5c36", "logo_url": "https://cdn.example.com/logo.png", "footer_text": "Meezan"}).Data()
	if b["company_name"] != "MMBL" || b["primary_color"] != "#0a5c36" {
		t.Fatalf("branding: %v", b)
	}
	viewer, _ := fx.NewUser(t, harness.RoleViewer)
	if g := viewer.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/template-branding", nil).Data(); g["company_name"] != "MMBL" {
		t.Fatalf("branding read: %v", g)
	}
	for _, bad := range []map[string]any{{"primary_color": "red; background:url(x)"}, {"logo_url": "javascript:alert(1)"}, {"logo_url": "http://cdn.example.com/x.png"}} {
		admin.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPut, "/api/v1/template-branding", bad)
	}
	ed, _ := fx.NewUser(t, harness.RoleTemplateEditor)
	ed.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPut, "/api/v1/template-branding", map[string]any{"company_name": "x"})
}

func TestSendingDomainRecordsAndKeys(t *testing.T) {
	admin := fx.Admin(t)
	name := "mail-" + harness.Unique() + ".example.com"
	created := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/sending-domains", map[string]any{"domain": name})
	d := created.Data()
	if d["status"] == "verified" || harness.Str(d, "dkim_public_key") == "" || !strings.Contains(created.String(), "v=spf1") ||
		!strings.Contains(created.String(), "v=DMARC1") || !strings.Contains(created.String(), "_domainkey") {
		t.Fatalf("domain records: %s", created)
	}
	id := harness.Str(d, "id")
	for _, r := range []*harness.Response{created, admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/sending-domains/"+id, nil),
		admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/sending-domains", nil)} {
		if strings.Contains(r.String(), "PRIVATE KEY") || strings.Contains(r.String(), "private") {
			t.Fatalf("the DKIM private key is returned: %s", r)
		}
	}
	admin.ExpectError(t, http.StatusConflict, "", http.MethodPost, "/api/v1/sending-domains", map[string]any{"domain": name})
	for _, bad := range []string{"localhost", "not a domain", "-x.example.com", "example"} {
		admin.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/sending-domains", map[string]any{"domain": bad})
	}
	v := admin.Do(t, http.MethodPost, "/api/v1/sending-domains/"+id+"/verify", nil)
	if v.Status >= 500 || v.Data()["status"] == "verified" {
		t.Fatalf("verify of a domain without DNS records = %s", v)
	}
	admin.Expect(t, http.StatusNoContent, http.MethodDelete, "/api/v1/sending-domains/"+id, nil)
}

func TestAnalyticsAndAuditExport(t *testing.T) {
	aud, _ := fx.NewUser(t, harness.RoleAuditor)
	aud.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/stats", nil)
	exp := aud.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs/export", nil)
	if len(exp.Items()) == 0 {
		t.Fatalf("export is empty: %s", exp)
	}
	harness.Eventually(t, "the export audited", 10*time.Second, func() bool {
		return strings.Contains(aud.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs?limit=50", nil).String(), "audit_log.exported")
	})
}
