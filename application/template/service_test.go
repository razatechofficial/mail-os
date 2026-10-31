package template_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	app "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/application/template/templatetest"
	domain "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

const (
	tenantA = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"
	tenantB = "7a2d4d4f-7b49-4b9a-8b6a-3c0e4c7b9b21"
	editor  = "0b6c1c3e-6a38-4a8f-9a59-2b9d3b6a8a11"
	other   = "1c7d2d4f-7b49-4b9a-8b6a-3c0e4c7b9b22"
)

type fixture struct {
	svc      *app.Service
	repo     *templatetest.Repository
	settings *templatetest.Settings
	audit    *templatetest.Audit
	sender   *templatetest.Sender
}

func newFixture(t *testing.T, rawHTML bool) fixture {
	t.Helper()
	f := fixture{repo: templatetest.NewRepository(), settings: &templatetest.Settings{}, audit: &templatetest.Audit{},
		sender: &templatetest.Sender{}}
	clock := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	n := 0
	f.svc = app.New(app.Deps{Repo: f.repo, Settings: f.settings, Audit: f.audit, RawHTMLBlocks: rawHTML,
		Now:   func() time.Time { clock = clock.Add(time.Second); return clock },
		NewID: func() string { n++; return fmt.Sprintf("id-%d", n) }})
	return f
}

func (f fixture) create(t *testing.T, tenant, slug, topic string) domain.Template {
	t.Helper()
	tpl, err := f.svc.Create(context.Background(), tenant, app.CreateInput{Name: "Security notice", Slug: slug, Topic: topic})
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func draftInput(revision int, locale string) app.DraftInput {
	return app.DraftInput{Locale: locale, Revision: revision, Subject: "Notice for {{user.name}}",
		HTMLBody: `<p onclick="x()">Hello {{user.name}}</p><script>alert(1)</script>`, TextBody: "Hello {{user.name}}",
		Variables: []string{"user.name", "link"}}
}

func (f fixture) save(t *testing.T, tpl domain.Template, revision int, locale, by string) domain.Draft {
	t.Helper()
	d, _, err := f.svc.SaveDraft(context.Background(), tpl.OrgID, tpl.ID, draftInput(revision, locale), app.Editor{ID: by})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCreateUpdateDelete(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "iam-security-notice", domain.TopicSecurityNotice)
	if tpl.DefaultLocale != domain.LocaleEnglish || tpl.Category != domain.CategoryTransactional || !tpl.IsActive {
		t.Fatalf("defaults: %+v", tpl)
	}
	if _, err := f.svc.Create(ctx, tenantA, app.CreateInput{Name: "x", Slug: "iam-security-notice"}); apperrors.DetailsOf(err)[0].Code != domain.CodeTaken {
		t.Fatalf("duplicate slug: %v", err)
	}
	if _, err := f.svc.Create(ctx, tenantA, app.CreateInput{Name: "x", Slug: "other", Topic: domain.TopicSecurityNotice}); apperrors.DetailsOf(err)[0].Field != "topic" {
		t.Fatalf("second template for a topic: %v", err)
	}
	if _, err := f.svc.Create(ctx, tenantB, app.CreateInput{Name: "x", Slug: "iam-security-notice", Topic: domain.TopicSecurityNotice}); err != nil {
		t.Fatalf("another tenant's slug and topic: %v", err)
	}
	ur, inactive := domain.LocaleUrdu, false
	got, err := f.svc.Update(ctx, tenantA, tpl.ID, app.UpdateInput{DefaultLocale: &ur, IsActive: &inactive})
	if err != nil || got.DefaultLocale != ur || got.IsActive || got.Name != tpl.Name {
		t.Fatalf("update: %+v %v", got, err)
	}
	bad := "Not A Slug!"
	if _, err := f.svc.Update(ctx, tenantA, tpl.ID, app.UpdateInput{Slug: &bad}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("bad slug: %v", err)
	}
	if _, err := f.svc.Get(ctx, tenantB, tpl.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant read the template: %v", err)
	}
	if err := f.svc.Delete(ctx, tenantB, tpl.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant deleted the template: %v", err)
	}
	if err := f.svc.Delete(ctx, tenantA, tpl.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, tenantA, tpl.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("deleted template read: %v", err)
	}
	for _, want := range []string{"template.created", "template.updated", "template.deleted"} {
		if !slices.Contains(f.audit.Actions, want) {
			t.Errorf("%s not audited: %v", want, f.audit.Actions)
		}
	}
}

func TestDraftSaveSanitisesAndChecksRevision(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "notice", domain.TopicSecurityNotice)
	d, err := f.svc.Draft(ctx, tenantA, tpl.ID, "")
	if err != nil || d.Revision != 0 || d.Locale != domain.LocaleEnglish || d.Design != nil {
		t.Fatalf("empty draft: %+v %v", d, err)
	}
	in := draftInput(0, "en")
	in.Variables = append(in.Variables, "order.id")
	saved, warnings, err := f.svc.SaveDraft(ctx, tenantA, tpl.ID, in, app.Editor{ID: editor})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.UpdatedBy != editor || saved.HTMLBody != "<p>Hello {{user.name}}</p>" {
		t.Fatalf("saved: %+v", saved)
	}
	if len(warnings) != 1 || warnings[0].Code != domain.CodeUnknownVariable {
		t.Fatalf("warnings: %+v", warnings)
	}
	if _, _, err := f.svc.SaveDraft(ctx, tenantA, tpl.ID, draftInput(0, "en"), app.Editor{ID: other}); apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("stale save: %v", err)
	}
	if d := f.save(t, tpl, 1, "en", other); d.Revision != 2 || d.UpdatedBy != other {
		t.Fatalf("second save: %+v", d)
	}
	if d := f.save(t, tpl, 0, "ur", editor); d.Revision != 1 || d.Locale != domain.LocaleUrdu {
		t.Fatalf("urdu draft is its own: %+v", d)
	}
	if _, _, err := f.svc.SaveDraft(ctx, tenantB, tpl.ID, draftInput(2, "en"), app.Editor{ID: editor}); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant saved the draft: %v", err)
	}
	invalid := draftInput(2, "fr")
	if _, _, err := f.svc.SaveDraft(ctx, tenantA, tpl.ID, invalid, app.Editor{ID: editor}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("invalid locale: %v", err)
	}
	if action, meta := f.audit.Last(); action != "template_draft.updated" || meta["locale"] != "ur" {
		t.Fatalf("audit: %s %v", action, meta)
	}
}

func TestRawHTMLBlocks(t *testing.T) {
	design := []byte(`{"type":"email","content":[{"type":"html","attrs":{"html":"<b>x</b>"}}]}`)
	for _, c := range []struct {
		flag, admin, ok bool
	}{{true, true, true}, {true, false, false}, {false, true, false}} {
		f := newFixture(t, c.flag)
		tpl := f.create(t, tenantA, "raw", "")
		in := draftInput(0, "en")
		in.Design = design
		_, _, err := f.svc.SaveDraft(context.Background(), tenantA, tpl.ID, in, app.Editor{ID: editor, Admin: c.admin})
		if c.ok && err != nil {
			t.Errorf("flag %v admin %v: %v", c.flag, c.admin, err)
		}
		if !c.ok && (len(apperrors.DetailsOf(err)) != 1 || apperrors.DetailsOf(err)[0].Code != domain.CodeRawHTML) {
			t.Errorf("flag %v admin %v: %v", c.flag, c.admin, err)
		}
	}
}

func TestPublishFourEyesAndRevision(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "notice", domain.TopicSecurityNotice)
	if _, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 0, other); apperrors.DetailsOf(err)[0].Code != domain.CodeNoDraft {
		t.Fatalf("publish with no draft: %v", err)
	}
	f.save(t, tpl, 0, "en", editor)
	if _, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 3, other); apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("stale revision: %v", err)
	}
	f.settings.FourEyes = true
	if _, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 1, editor); apperrors.Code(err) != apperrors.CodeFourEyesRequired {
		t.Fatalf("own draft under four-eyes: %v", err)
	}
	v1, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 1, other)
	if err != nil || v1.Number != 1 || !v1.IsActive || v1.PublishedBy != other || v1.Locale != domain.LocaleEnglish {
		t.Fatalf("publish: %+v %v", v1, err)
	}
	if action, meta := f.audit.Last(); action != "template.published" || meta["version"] != 1 || meta["locale"] != "en" {
		t.Fatalf("audit: %s %v", action, meta)
	}
	f.settings.FourEyes = false
	f.save(t, tpl, 0, "ur", editor)
	vur, err := f.svc.Publish(ctx, tenantA, tpl.ID, "ur", 1, editor)
	if err != nil || vur.Number != 2 {
		t.Fatalf("urdu publish (own draft, four-eyes off): %+v %v", vur, err)
	}
	f.save(t, tpl, 1, "en", editor)
	v3, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 2, other)
	if err != nil || v3.Number != 3 {
		t.Fatalf("second english publish: %+v %v", v3, err)
	}
	en, _ := f.svc.ActiveVersion(ctx, tenantA, tpl.ID, "en")
	ur, _ := f.svc.ActiveVersion(ctx, tenantA, tpl.ID, "ur")
	if en.Number != 3 || ur.Number != 2 {
		t.Fatalf("active per locale: en %d ur %d", en.Number, ur.Number)
	}
	all, _ := f.svc.Versions(ctx, tenantA, tpl.ID, "")
	if len(all) != 3 || all[0].Number != 3 || all[2].IsActive {
		t.Fatalf("versions: %+v", all)
	}
	if _, err := f.svc.Publish(ctx, tenantB, tpl.ID, "en", 2, other); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant published: %v", err)
	}
}

func TestPublishedVersionIsImmutable(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "notice", "")
	f.save(t, tpl, 0, "en", editor)
	v, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 1, editor)
	if err != nil {
		t.Fatal(err)
	}
	in := draftInput(1, "en")
	in.Subject = "Changed after publishing"
	if _, _, err := f.svc.SaveDraft(ctx, tenantA, tpl.ID, in, app.Editor{ID: editor}); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Version(ctx, tenantA, v.ID)
	if err != nil || got.Subject != v.Subject || got.Subject == in.Subject {
		t.Fatalf("published version changed: %+v %v", got, err)
	}
	if _, err := f.svc.Version(ctx, tenantB, v.ID); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant read the version: %v", err)
	}
}

func TestRestore(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "notice", "")
	f.save(t, tpl, 0, "en", editor)
	v, _ := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 1, editor)
	in := draftInput(1, "en")
	in.Subject = "Newer"
	if _, _, err := f.svc.SaveDraft(ctx, tenantA, tpl.ID, in, app.Editor{ID: editor}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Restore(ctx, tenantA, tpl.ID, v.Number, "en", 1, app.Editor{ID: other}); apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("stale restore: %v", err)
	}
	d, err := f.svc.Restore(ctx, tenantA, tpl.ID, v.Number, "", 2, app.Editor{ID: other})
	if err != nil || d.Revision != 3 || d.Subject != v.Subject || d.UpdatedBy != other {
		t.Fatalf("restore: %+v %v", d, err)
	}
	if _, err := f.svc.Restore(ctx, tenantA, tpl.ID, 99, "en", 3, app.Editor{ID: other}); !apperrors.IsNotFound(err) {
		t.Fatalf("missing version: %v", err)
	}
	if action, _ := f.audit.Last(); action != "template.restored" {
		t.Fatalf("audit: %s", action)
	}
	// Under four-eyes the restorer is the last editor.
	f.settings.FourEyes = true
	if _, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 3, other); apperrors.Code(err) != apperrors.CodeFourEyesRequired {
		t.Fatalf("restorer published: %v", err)
	}
}

func TestDraftSeededFromActiveVersion(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "notice", "")
	f.save(t, tpl, 0, "en", editor)
	if _, err := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 1, editor); err != nil {
		t.Fatal(err)
	}
	d, err := f.svc.Draft(ctx, tenantA, tpl.ID, "ur")
	if err != nil || d.Revision != 0 || d.Subject != "" {
		t.Fatalf("urdu draft: %+v %v", d, err)
	}
	if _, err := f.svc.Draft(ctx, tenantA, tpl.ID, "fr"); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("bad locale: %v", err)
	}
}

func TestResolvePublished(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "notice", domain.TopicSecurityNotice)
	if _, _, err := f.svc.ResolvePublished(ctx, tenantA, app.Ref{Slug: "notice"}, "en"); !apperrors.IsNotFound(err) {
		t.Fatalf("nothing published: %v", err)
	}
	f.save(t, tpl, 0, "en", editor)
	en, _ := f.svc.Publish(ctx, tenantA, tpl.ID, "en", 1, editor)
	for _, ref := range []app.Ref{{TemplateID: tpl.ID}, {Slug: "notice"}, {Topic: domain.TopicSecurityNotice}} {
		_, v, err := f.svc.ResolvePublished(ctx, tenantA, ref, "ur")
		if err != nil || v.ID != en.ID {
			t.Fatalf("%+v falls back to default_locale: %+v %v", ref, v, err)
		}
	}
	f.save(t, tpl, 0, "ur", editor)
	ur, _ := f.svc.Publish(ctx, tenantA, tpl.ID, "ur", 1, editor)
	if _, v, _ := f.svc.ResolvePublished(ctx, tenantA, app.Ref{Slug: "notice"}, "ur"); v.ID != ur.ID {
		t.Fatalf("urdu not resolved: %+v", v)
	}
	if _, v, _ := f.svc.ResolvePublished(ctx, tenantA, app.Ref{Slug: "notice"}, "fr"); v.ID != en.ID {
		t.Fatalf("unsupported locale falls back: %+v", v)
	}
	for _, ref := range []app.Ref{{}, {Slug: "notice", Topic: domain.TopicSecurityNotice}} {
		if _, _, err := f.svc.ResolvePublished(ctx, tenantA, ref, "en"); apperrors.KindOf(err) != apperrors.KindInvalidInput {
			t.Fatalf("ref %+v: %v", ref, err)
		}
	}
	if _, _, err := f.svc.ResolvePublished(ctx, tenantB, app.Ref{Slug: "notice"}, "en"); !apperrors.IsNotFound(err) {
		t.Fatalf("another tenant resolved it: %v", err)
	}
	off := false
	if _, err := f.svc.Update(ctx, tenantA, tpl.ID, app.UpdateInput{IsActive: &off}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ResolvePublished(ctx, tenantA, app.Ref{Slug: "notice"}, "en"); !apperrors.IsNotFound(err) {
		t.Fatalf("inactive template resolved: %v", err)
	}
}

func TestPreviewMasksSecrets(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "code", domain.TopicMFAEmailCode)
	out, err := f.svc.Preview(ctx, tenantA, tpl.ID, app.PreviewInput{Subject: "Code {{code}}", HTMLBody: "<p>{{code}} for {{email}}</p>", TextBody: "{{code}}"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Subject+out.HTML+out.Text, "482913") || !strings.Contains(out.HTML, "amna@example.com") {
		t.Fatalf("preview: %+v", out)
	}
	if _, err := f.svc.Preview(ctx, tenantA, tpl.ID, app.PreviewInput{Subject: "a\nb", HTMLBody: "", TextBody: "x"}); len(apperrors.DetailsOf(err)) != 2 {
		t.Fatalf("preview limits: %v", err)
	}
}

func TestTestSend(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	tpl := f.create(t, tenantA, "notice", domain.TopicSecurityNotice)
	in := app.TestSendInput{Locale: "en", ToEmail: "qa@example.com", FromName: "Averox", FromEmail: "no-reply@mail.averox.com"}
	if _, _, err := f.svc.TestSend(ctx, tenantA, tpl.ID, in); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("unwired test send: %v", err)
	}
	f.svc.SetTestSend(f.sender, templatetest.Domains{Verified: []string{"mail.averox.com"}})
	if _, _, err := f.svc.TestSend(ctx, tenantA, tpl.ID, in); apperrors.DetailsOf(err)[0].Code != domain.CodeNoDraft {
		t.Fatalf("no draft: %v", err)
	}
	f.save(t, tpl, 0, "en", editor)
	bad := in
	bad.FromEmail = "no-reply@gmail.com"
	if _, _, err := f.svc.TestSend(ctx, tenantA, tpl.ID, bad); apperrors.DetailsOf(err)[0].Code != app.CodeUnverifiedDomain {
		t.Fatalf("unverified domain: %v", err)
	}
	bad = in
	bad.ToEmail, bad.FromName = "not an address", "a\r\nBcc: x@example.com"
	if _, _, err := f.svc.TestSend(ctx, tenantA, tpl.ID, bad); len(apperrors.DetailsOf(err)) != 2 {
		t.Fatalf("invalid input: %v", err)
	}
	id, status, err := f.svc.TestSend(ctx, tenantA, tpl.ID, in)
	if err != nil || id == "" || status == "" {
		t.Fatalf("send: %s %s %v", id, status, err)
	}
	m := f.sender.Sent[0]
	if m.Subject != "[Test] Notice for Amna Khan" || m.To != "qa@example.com" || !slices.Equal(m.Tags, []string{"template-test"}) ||
		m.HTML != "<p>Hello Amna Khan</p>" || m.TenantID != tenantA {
		t.Fatalf("message: %+v", m)
	}
	if action, meta := f.audit.Last(); action != "template.test_sent" || meta["to_email"] != "qa@example.com" {
		t.Fatalf("audit: %s %v", action, meta)
	}
}

func TestBranding(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	b, err := f.svc.Branding(ctx, tenantA)
	if err != nil || b.PrimaryColor != "#2563eb" || b.OrgID != tenantA {
		t.Fatalf("defaults: %+v %v", b, err)
	}
	b.CompanyName, b.PrimaryColor = "Averox", "#111111"
	saved, err := f.svc.UpdateBranding(ctx, tenantA, b, editor)
	if err != nil || saved.CompanyName != "Averox" {
		t.Fatalf("update: %+v %v", saved, err)
	}
	if got, _ := f.svc.Branding(ctx, tenantA); got.PrimaryColor != "#111111" {
		t.Fatalf("read back: %+v", got)
	}
	if got, _ := f.svc.Branding(ctx, tenantB); got.CompanyName != "" {
		t.Fatalf("another tenant's branding: %+v", got)
	}
	b.LogoURL = "http://insecure.example/logo.png"
	if _, err := f.svc.UpdateBranding(ctx, tenantA, b, editor); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("http logo: %v", err)
	}
	if action, _ := f.audit.Last(); action != "template_branding.updated" {
		t.Fatalf("audit: %s", action)
	}
}
