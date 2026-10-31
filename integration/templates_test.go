//go:build integration

package integration

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/application/tenant"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type templateEnv struct {
	svc     *apptemplate.Service
	tenants *tenant.Service
	audit   *postgres.AuditRepository
	tenant  string
	ctx     context.Context
}

// newTemplateEnv provisions a fresh tenant and a service on Postgres.
func newTemplateEnv(t *testing.T) templateEnv {
	t.Helper()
	db := connectPostgres(t)
	auditRepo := postgres.NewAuditRepository(db)
	w := audit.NewWriter(auditRepo, false)
	tenants := tenant.NewService(postgres.NewTenantRepository(db), w, time.Minute)
	id := uuid.NewString()
	if err := tenants.Ensure(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	ctx := access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindUser, Subject: uuid.NewString(), TenantID: id})
	svc := apptemplate.New(apptemplate.Deps{Repo: postgres.NewTemplateRepository(db), Settings: tenants, Audit: w})
	return templateEnv{svc: svc, tenants: tenants, audit: auditRepo, tenant: id, ctx: ctx}
}

const design = `{"type":"email","attrs":{"dir":"rtl"},"content":[{"type":"button","attrs":{"href":"{{link}}","label":"Review"}}]}`

func (e templateEnv) save(t *testing.T, templateID, locale string, revision int, subject, by string) domain.Draft {
	t.Helper()
	d, _, err := e.svc.SaveDraft(e.ctx, e.tenant, templateID, apptemplate.DraftInput{Locale: locale, Revision: revision,
		Subject: subject, Design: []byte(design), HTMLBody: `<p>Hi {{user.name}}</p><img src=x onerror=alert(1)>`,
		TextBody: "Hi {{user.name}}", Variables: []string{"user.name", "link"}}, apptemplate.Editor{ID: by})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (e templateEnv) actions(t *testing.T) []string {
	t.Helper()
	events, _, err := e.audit.List(context.Background(), postgres.AuditFilter{TenantUUID: uuid.MustParse(e.tenant), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = ev.Action
	}
	return out
}

func TestTemplatesPublishPerLocaleImmutableRestore(t *testing.T) {
	e := newTemplateEnv(t)
	editor, publisher := uuid.NewString(), uuid.NewString()
	tpl, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "Security notice", Slug: "iam-security-notice",
		Topic: domain.TopicSecurityNotice})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "Again", Slug: "iam-security-notice"}); apperrors.DetailsOf(err)[0].Code != domain.CodeTaken {
		t.Fatalf("duplicate slug: %v", err)
	}
	if _, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "Again", Slug: "other", Topic: domain.TopicSecurityNotice}); apperrors.DetailsOf(err)[0].Field != "topic" {
		t.Fatalf("duplicate topic: %v", err)
	}

	d := e.save(t, tpl.ID, "en", 0, "Notice for {{user.name}}", editor)
	if d.Revision != 1 || strings.Contains(d.HTMLBody, "onerror") {
		t.Fatalf("saved draft: %+v", d)
	}
	stored, err := e.svc.Draft(e.ctx, e.tenant, tpl.ID, "en")
	if err != nil || stored.Revision != 1 || !strings.Contains(string(stored.Design), `"rtl"`) || stored.UpdatedBy != editor {
		t.Fatalf("draft read back: %+v %v", stored, err)
	}

	settings, _ := e.tenants.Settings(e.ctx, e.tenant)
	settings.FourEyesPublish = true
	if _, err := e.tenants.UpdateSettings(e.ctx, settings, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "en", 1, editor); apperrors.Code(err) != apperrors.CodeFourEyesRequired {
		t.Fatalf("own draft under four-eyes: %v", err)
	}
	v1, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "en", 1, publisher)
	if err != nil || v1.Number != 1 || !v1.IsActive {
		t.Fatalf("publish en: %+v %v", v1, err)
	}
	e.save(t, tpl.ID, "ur", 0, "سیکیورٹی نوٹس {{user.name}}", editor)
	vur, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "ur", 1, publisher)
	if err != nil || vur.Number != 2 {
		t.Fatalf("publish ur: %+v %v", vur, err)
	}
	e.save(t, tpl.ID, "en", 1, "Changed after publishing", editor)
	v3, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "en", 2, publisher)
	if err != nil || v3.Number != 3 {
		t.Fatalf("second en publish: %+v %v", v3, err)
	}

	en, _ := e.svc.ActiveVersion(e.ctx, e.tenant, tpl.ID, "en")
	ur, _ := e.svc.ActiveVersion(e.ctx, e.tenant, tpl.ID, "ur")
	if en.ID != v3.ID || ur.ID != vur.ID {
		t.Fatalf("active per locale: en %d ur %d", en.Number, ur.Number)
	}
	old, err := e.svc.Version(e.ctx, e.tenant, v1.ID)
	if err != nil || old.IsActive || old.Subject != "Notice for {{user.name}}" || old.PublishedBy != publisher {
		t.Fatalf("first version changed: %+v %v", old, err)
	}
	all, _ := e.svc.Versions(e.ctx, e.tenant, tpl.ID, "")
	if len(all) != 3 || all[0].Number != 3 {
		t.Fatalf("versions: %d", len(all))
	}
	_, resolved, err := e.svc.ResolvePublished(e.ctx, e.tenant, apptemplate.Ref{Topic: domain.TopicSecurityNotice}, "ur")
	if err != nil || resolved.ID != vur.ID || !strings.HasPrefix(resolved.Subject, "سیکیورٹی") {
		t.Fatalf("resolve ur: %+v %v", resolved, err)
	}

	restored, err := e.svc.Restore(e.ctx, e.tenant, tpl.ID, 1, "en", 2, apptemplate.Editor{ID: publisher})
	if err != nil || restored.Revision != 3 || restored.Subject != v1.Subject {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	if _, err := e.svc.Restore(e.ctx, e.tenant, tpl.ID, 1, "en", 2, apptemplate.Editor{ID: publisher}); apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("stale restore: %v", err)
	}

	other := newTemplateEnv(t)
	if _, err := other.svc.Get(other.ctx, other.tenant, tpl.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant read it: %v", err)
	}
	if _, err := other.svc.Version(other.ctx, other.tenant, v1.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant read a version: %v", err)
	}

	got := e.actions(t)
	for _, want := range []string{"template.created", "template_draft.updated", "template.published", "template.restored", "tenant_settings.updated"} {
		found := false
		for _, a := range got {
			found = found || a == want
		}
		if !found {
			t.Errorf("%s not audited: %v", want, got)
		}
	}

	if err := e.svc.Delete(e.ctx, e.tenant, tpl.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.ResolvePublished(e.ctx, e.tenant, apptemplate.Ref{Slug: "iam-security-notice"}, "en"); !apperrors.IsNotFound(err) {
		t.Fatalf("deleted template resolved: %v", err)
	}
	if _, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "Again", Slug: "iam-security-notice", Topic: domain.TopicSecurityNotice}); err != nil {
		t.Fatalf("slug and topic not freed by delete: %v", err)
	}
}

// Two editors save the first revision at once: exactly one wins.
func TestTemplateConcurrentFirstSave(t *testing.T) {
	e := newTemplateEnv(t)
	tpl, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "Race", Slug: "race"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = e.svc.SaveDraft(e.ctx, e.tenant, tpl.ID, apptemplate.DraftInput{Locale: "en", Subject: "s",
				HTMLBody: "<p>x</p>", TextBody: "x"}, apptemplate.Editor{ID: uuid.NewString()})
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case apperrors.Code(err) != apperrors.CodeConflict:
			t.Fatalf("unexpected: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d first saves won", ok)
	}
}

func TestTemplateBranding(t *testing.T) {
	e := newTemplateEnv(t)
	b, err := e.svc.Branding(e.ctx, e.tenant)
	if err != nil || b.PrimaryColor != "#2563eb" || !b.UpdatedAt.IsZero() {
		t.Fatalf("defaults: %+v %v", b, err)
	}
	b.CompanyName, b.LogoURL, b.FontFamily, b.FooterText = "Averox", "https://cdn.example.com/logo.png", "Georgia", "آپ کو یہ ای میل ملی"
	if _, err := e.svc.UpdateBranding(e.ctx, e.tenant, b, "admin"); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Branding(e.ctx, e.tenant)
	if err != nil || got.CompanyName != "Averox" || got.FontFamily != "Georgia" || got.FooterText != b.FooterText || got.UpdatedAt.IsZero() {
		t.Fatalf("read back: %+v %v", got, err)
	}
	got.PrimaryColor = "#000000"
	if _, err := e.svc.UpdateBranding(e.ctx, e.tenant, got, "admin"); err != nil {
		t.Fatal(err)
	}
	if again, _ := e.svc.Branding(e.ctx, e.tenant); again.PrimaryColor != "#000000" || again.CompanyName != "Averox" {
		t.Fatalf("upsert: %+v", again)
	}
	if other := newTemplateEnv(t); func() bool { b, _ := other.svc.Branding(other.ctx, other.tenant); return b.CompanyName != "" }() {
		t.Fatal("another tenant sees the branding")
	}
}

// The template migrations go down and up again over data: the second up
// keeps one active version per template and locale.
func TestTemplateMigrationsDownUp(t *testing.T) {
	e := newTemplateEnv(t)
	tpl, err := e.svc.Create(e.ctx, e.tenant, apptemplate.CreateInput{Name: "Migrate", Slug: "migrate"})
	if err != nil {
		t.Fatal(err)
	}
	e.save(t, tpl.ID, "en", 0, "en", "a")
	e.save(t, tpl.ID, "ur", 0, "ur", "a")
	if _, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "en", 1, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "ur", 1, "a"); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	m, err := postgres.NewMigrator(cfg.Postgres.DSN(), migrationsPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	top, _, _ := m.Version()
	// Step down past the template migrations, through any newer ones.
	for v, _, _ := m.Version(); v >= 20261031100000; v, _, _ = m.Version() {
		if err := m.Down(); err != nil {
			t.Fatal(err)
		}
	}
	if v, dirty, _ := m.Version(); v >= 20261031100000 || dirty {
		t.Fatalf("after down: %d dirty=%v", v, dirty)
	}
	if err := m.Up(); err != nil {
		t.Fatal(err)
	}
	if v, dirty, _ := m.Version(); v != top || dirty {
		t.Fatalf("after up: %d dirty=%v, want %d", v, dirty, top)
	}

	db := connectPostgres(t)
	var active int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM template_versions WHERE template_id = $1 AND is_active`, tpl.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("%d active versions after down and up", active)
	}
	// Drafts and branding were dropped with their tables; templates work again.
	if d, err := e.svc.Draft(e.ctx, e.tenant, tpl.ID, "ur"); err != nil || d.Revision != 0 {
		t.Fatalf("draft after re-up: %+v %v", d, err)
	}
	e.save(t, tpl.ID, "ur", 0, "ur again", "a")
	if _, err := e.svc.Publish(e.ctx, e.tenant, tpl.ID, "ur", 1, "a"); err != nil {
		t.Fatalf("publish after re-up: %v", err)
	}
}
