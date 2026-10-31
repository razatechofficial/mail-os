package template

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	domain "github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/render"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// locale reads a locale query or field; "" is the template's default.
func locale(s string, t domain.Template) (domain.Locale, error) {
	if strings.TrimSpace(s) == "" {
		return t.DefaultLocale, nil
	}
	l, ok := domain.ParseLocale(s)
	if !ok {
		return "", apperrors.Invalid("locale", domain.CodeInvalid, "locale must be en or ur")
	}
	return l, nil
}

// ── drafts ────────────────────────────────────────────────────────────────

// Draft returns the locale's draft. With none saved it is revision 0,
// seeded from the locale's active version when there is one, with no
// design.
func (s *Service) Draft(ctx context.Context, tenantID, templateID, loc string) (domain.Draft, error) {
	t, err := s.repo.Get(ctx, tenantID, templateID)
	if err != nil {
		return domain.Draft{}, err
	}
	l, err := locale(loc, t)
	if err != nil {
		return domain.Draft{}, err
	}
	d, ok, err := s.repo.Draft(ctx, t.ID, l)
	if err != nil || ok {
		return d, err
	}
	v, err := s.repo.ActiveVersion(ctx, t.ID, l)
	switch {
	case apperrors.IsNotFound(err):
		return domain.SeedDraft(t.ID, l, nil), nil
	case err != nil:
		return domain.Draft{}, err
	}
	return domain.SeedDraft(t.ID, l, &v), nil
}

// DraftInput is a draft save: the console's design and its compiled HTML
// and text, and the revision the editor loaded.
type DraftInput struct {
	Locale    string
	Revision  int
	Subject   string
	Preheader string
	Design    []byte
	HTMLBody  string
	TextBody  string
	Variables []string
}

// SaveDraft validates the draft, sanitises its HTML, and stores it as the
// next revision. warnings are variables the topic does not declare.
func (s *Service) SaveDraft(ctx context.Context, tenantID, templateID string, in DraftInput, by Editor) (domain.Draft, []apperrors.FieldError, error) {
	t, err := s.repo.Get(ctx, tenantID, templateID)
	if err != nil {
		return domain.Draft{}, nil, err
	}
	l, ok := domain.ParseLocale(in.Locale)
	if !ok {
		return domain.Draft{}, nil, apperrors.Invalid("locale", domain.CodeInvalid, "locale must be en or ur")
	}
	d := domain.Draft{TemplateID: t.ID, Locale: l, Subject: in.Subject, Preheader: in.Preheader, Design: in.Design,
		HTMLBody: in.HTMLBody, TextBody: in.TextBody, Variables: in.Variables, Revision: in.Revision}
	if domain.IsNullDesign(d.Design) {
		d.Design = nil
	}
	warnings, err := d.Validate(domain.DraftOptions{Topic: t.Topic, AllowRawHTML: s.allowRawHTML(by)})
	if err != nil {
		return domain.Draft{}, nil, err
	}
	if d.HTMLBody, err = render.SanitizeHTML(d.HTMLBody); err != nil {
		return domain.Draft{}, nil, apperrors.Invalid("html_body", domain.CodeInvalid, "html_body could not be read as HTML")
	}
	var saved domain.Draft
	err = s.repo.InTx(ctx, func(ctx context.Context) error {
		stored, _, err := s.repo.Draft(ctx, t.ID, l)
		if err != nil {
			return err
		}
		if saved, err = d.Save(stored.Revision, by.ID, s.now()); err != nil {
			return err
		}
		if err := s.repo.SaveDraft(ctx, saved, stored.Revision); err != nil {
			return err
		}
		return s.audit.Append(ctx, "template", t.ID, "template_draft.updated", map[string]any{
			"locale": string(l), "revision": saved.Revision, "variables": saved.Variables, "has_design": saved.Design != nil,
		})
	})
	if err != nil {
		return domain.Draft{}, nil, err
	}
	return saved, warnings, nil
}

// ── publishing ────────────────────────────────────────────────────────────

// Publish copies the locale's saved draft into a new active version, the
// previous one of that locale deactivated in the same transaction. Under
// the tenant's four-eyes setting the draft's last editor may not publish
// it.
func (s *Service) Publish(ctx context.Context, tenantID, templateID, loc string, revision int, publisher string) (domain.Version, error) {
	settings, err := s.settings.Settings(ctx, tenantID)
	if err != nil {
		return domain.Version{}, err
	}
	var v domain.Version
	err = s.repo.InTx(ctx, func(ctx context.Context) error {
		t, err := s.repo.GetForUpdate(ctx, tenantID, templateID)
		if err != nil {
			return err
		}
		l, ok := domain.ParseLocale(loc)
		if !ok {
			return apperrors.Invalid("locale", domain.CodeInvalid, "locale must be en or ur")
		}
		d, _, err := s.repo.Draft(ctx, t.ID, l)
		if err != nil {
			return err
		}
		d.Locale = l
		n, err := s.repo.MaxVersionNumber(ctx, t.ID)
		if err != nil {
			return err
		}
		v, err = d.Publish(domain.PublishRequest{VersionID: s.newID(), Number: n + 1, Revision: revision,
			Publisher: publisher, FourEyes: settings.FourEyesPublish, Now: s.now()})
		if err != nil {
			return err
		}
		if err := s.repo.InsertVersion(ctx, v); err != nil {
			return err
		}
		return s.audit.Append(ctx, "template", t.ID, "template.published", map[string]any{
			"version": v.Number, "version_id": v.ID, "locale": string(v.Locale), "revision": d.Revision,
			"last_editor": d.UpdatedBy, "four_eyes": settings.FourEyesPublish,
		})
	})
	if err != nil {
		return domain.Version{}, err
	}
	return v, nil
}

// Versions lists the template's versions newest first, of one locale or
// of all when loc is "".
func (s *Service) Versions(ctx context.Context, tenantID, templateID, loc string) ([]domain.Version, error) {
	t, err := s.repo.Get(ctx, tenantID, templateID)
	if err != nil {
		return nil, err
	}
	var l domain.Locale
	if strings.TrimSpace(loc) != "" {
		if l, err = locale(loc, t); err != nil {
			return nil, err
		}
	}
	return s.repo.Versions(ctx, t.ID, l)
}

// ActiveVersion returns the locale's active version; loc "" is the
// template's default_locale. None published is 404.
func (s *Service) ActiveVersion(ctx context.Context, tenantID, templateID, loc string) (domain.Version, error) {
	t, err := s.repo.Get(ctx, tenantID, templateID)
	if err != nil {
		return domain.Version{}, err
	}
	l, err := locale(loc, t)
	if err != nil {
		return domain.Version{}, err
	}
	v, err := s.repo.ActiveVersion(ctx, t.ID, l)
	if apperrors.IsNotFound(err) {
		return domain.Version{}, apperrors.NotFound("no version is published in this locale")
	}
	return v, err
}

// Restore replaces the locale's draft with a version's content as the next
// revision. loc "" is the version's own locale.
func (s *Service) Restore(ctx context.Context, tenantID, templateID string, number int, loc string, revision int, by Editor) (domain.Draft, error) {
	var d domain.Draft
	err := s.repo.InTx(ctx, func(ctx context.Context) error {
		t, err := s.repo.Get(ctx, tenantID, templateID)
		if err != nil {
			return err
		}
		v, err := s.repo.VersionByNumber(ctx, t.ID, number)
		if apperrors.IsNotFound(err) {
			return apperrors.NotFound("template version not found")
		}
		if err != nil {
			return err
		}
		l := v.Locale
		if strings.TrimSpace(loc) != "" {
			var ok bool
			if l, ok = domain.ParseLocale(loc); !ok {
				return apperrors.Invalid("locale", domain.CodeInvalid, "locale must be en or ur")
			}
		}
		current, ok, err := s.repo.Draft(ctx, t.ID, l)
		if err != nil {
			return err
		}
		if !ok {
			current = domain.Draft{TemplateID: t.ID, Locale: l}
		}
		if d, err = v.Restore(current, revision, by.ID, s.now()); err != nil {
			return err
		}
		if err := s.repo.SaveDraft(ctx, d, current.Revision); err != nil {
			return err
		}
		return s.audit.Append(ctx, "template", t.ID, "template.restored", map[string]any{
			"version": v.Number, "version_id": v.ID, "locale": string(l), "revision": d.Revision,
		})
	})
	return d, err
}

// ── preview and test send ─────────────────────────────────────────────────

// PreviewInput is unsaved content and the data to render it with; nil data
// is the topic's samples.
type PreviewInput struct {
	Locale   string
	Subject  string
	HTMLBody string
	TextBody string
	Data     map[string]any
}

// Preview renders unsaved content. The topic's secret variables are
// masked: a preview is a console view (contract §6).
func (s *Service) Preview(ctx context.Context, tenantID, templateID string, in PreviewInput) (render.Content, error) {
	t, err := s.repo.Get(ctx, tenantID, templateID)
	if err != nil {
		return render.Content{}, err
	}
	l, err := locale(in.Locale, t)
	if err != nil {
		return render.Content{}, err
	}
	if err := domain.ValidatePreview(l, in.Subject, in.HTMLBody, in.TextBody); err != nil {
		return render.Content{}, err
	}
	data := in.Data
	if data == nil {
		data = domain.SampleData(t.Topic)
	}
	return render.Render(render.Content{Subject: in.Subject, HTML: in.HTMLBody, Text: in.TextBody}, data,
		render.Options{Mask: domain.SecretKeys(t.Topic)})
}

// TestSendInput is a test send of the locale's saved draft; nil data is
// the topic's samples.
type TestSendInput struct {
	Locale    string
	ToEmail   string
	FromName  string
	FromEmail string
	Data      map[string]any
}

// TestPrefix starts a test send's subject; TestTag tags it.
const (
	TestPrefix = "[Test] "
	TestTag    = "template-test"
	// MaxFromName bounds a test send's sender name.
	MaxFromName = 255
)

// CodeUnverifiedDomain is a from_email outside the tenant's verified
// sending domains.
const CodeUnverifiedDomain = "unverified_domain"

// TestSend renders the locale's saved draft and sends it as transactional
// mail to one address, from a verified sending domain, and audits it.
func (s *Service) TestSend(ctx context.Context, tenantID, templateID string, in TestSendInput) (messageID, status string, err error) {
	if s.sender == nil || s.domains == nil {
		return "", "", apperrors.Unavailable("test sends are not available yet")
	}
	t, err := s.repo.Get(ctx, tenantID, templateID)
	if err != nil {
		return "", "", err
	}
	l, err := locale(in.Locale, t)
	if err != nil {
		return "", "", err
	}
	if errs := validateTestSend(in); len(errs) > 0 {
		return "", "", apperrors.Validation(errs...)
	}
	ok, err := s.domains.VerifiedFrom(ctx, tenantID, in.FromEmail)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", apperrors.Invalid("from_email", CodeUnverifiedDomain, "from_email must be on one of your verified sending domains")
	}
	d, saved, err := s.repo.Draft(ctx, t.ID, l)
	if err != nil {
		return "", "", err
	}
	if !saved {
		return "", "", apperrors.Invalid("locale", domain.CodeNoDraft, "there is no saved draft in this locale to send")
	}
	data := in.Data
	if data == nil {
		data = domain.SampleData(t.Topic)
	}
	out, err := render.Render(render.Content{Subject: d.Subject, HTML: d.HTMLBody, Text: d.TextBody}, data, render.Options{})
	if err != nil {
		return "", "", err
	}
	messageID, status, err = s.sender.SendTest(ctx, TestMessage{TenantID: tenantID, FromName: strings.TrimSpace(in.FromName),
		FromEmail: in.FromEmail, To: in.ToEmail, Subject: TestPrefix + out.Subject, HTML: out.HTML, Text: out.Text, Tags: []string{TestTag}})
	if err != nil {
		return "", "", err
	}
	if err := s.audit.Append(ctx, "template", t.ID, "template.test_sent", map[string]any{
		"locale": string(l), "revision": d.Revision, "to_email": in.ToEmail, "from_email": in.FromEmail, "message_id": messageID,
	}); err != nil {
		return "", "", err
	}
	return messageID, status, nil
}

func validateTestSend(in TestSendInput) []apperrors.FieldError {
	var errs []apperrors.FieldError
	for _, f := range []struct{ field, val string }{{"to_email", in.ToEmail}, {"from_email", in.FromEmail}} {
		if a, err := mail.ParseAddress(f.val); err != nil || a.Address != f.val {
			errs = append(errs, apperrors.FieldError{Field: f.field, Code: domain.CodeInvalidEmail, Message: f.field + " must be an email address"})
		}
	}
	switch name := strings.TrimSpace(in.FromName); {
	case strings.ContainsAny(name, "\r\n"):
		errs = append(errs, apperrors.FieldError{Field: "from_name", Code: domain.CodeInvalid, Message: "from_name must be one line"})
	case !utf8.ValidString(name):
		errs = append(errs, apperrors.FieldError{Field: "from_name", Code: domain.CodeInvalid, Message: "from_name is not valid UTF-8"})
	case utf8.RuneCountInString(name) > MaxFromName:
		errs = append(errs, apperrors.FieldError{Field: "from_name", Code: domain.CodeTooLong,
			Message: fmt.Sprintf("from_name must be at most %d characters", MaxFromName)})
	}
	return errs
}
