package template

import (
	"strings"
	"testing"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func validDraft() Draft {
	return Draft{
		TemplateID: "t1",
		Locale:     LocaleEnglish,
		Subject:    "Security notice for {{user.name}}",
		Preheader:  "A change was made to your account",
		Design:     []byte(sampleDesign),
		HTMLBody:   `<!doctype html><p>Hello {{user.name}}</p>`,
		TextBody:   "Hello {{user.name}}",
		Variables:  []string{"user.name", "link"},
	}
}

func TestDraftValidate(t *testing.T) {
	warnings, err := validDraft().Validate(DraftOptions{Topic: TopicSecurityNotice})
	if err != nil || warnings != nil {
		t.Fatalf("valid draft: %v %+v", err, warnings)
	}
	d := validDraft()
	d.Design = nil
	d.Locale = LocaleUrdu
	d.Subject = "سیکیورٹی نوٹس {{user.name}}"
	d.Variables = append(d.Variables, "order.id")
	warnings, err = d.Validate(DraftOptions{Topic: TopicSecurityNotice})
	if err != nil {
		t.Fatalf("design-less Urdu draft: %v", err)
	}
	if len(warnings) != 1 || warnings[0].Code != CodeUnknownVariable || warnings[0].Field != "variables[2]" {
		t.Fatalf("warnings = %+v", warnings)
	}
	if w, _ := d.Validate(DraftOptions{}); w != nil {
		t.Fatalf("topic-less draft warned: %+v", w)
	}
}

func TestDraftValidate_refuses(t *testing.T) {
	cases := map[string]struct {
		edit  func(*Draft)
		field string
		code  string
	}{
		"locale":          {func(d *Draft) { d.Locale = "fr" }, "locale", CodeInvalid},
		"no subject":      {func(d *Draft) { d.Subject = "" }, "subject", CodeRequired},
		"subject CR":      {func(d *Draft) { d.Subject = "a\r\nBcc: x@example.com" }, "subject", CodeInvalid},
		"subject LF":      {func(d *Draft) { d.Subject = "a\nb" }, "subject", CodeInvalid},
		"subject long":    {func(d *Draft) { d.Subject = strings.Repeat("s", MaxSubject+1) }, "subject", CodeTooLong},
		"preheader long":  {func(d *Draft) { d.Preheader = strings.Repeat("p", MaxPreheader+1) }, "preheader", CodeTooLong},
		"no html":         {func(d *Draft) { d.HTMLBody = "  " }, "html_body", CodeRequired},
		"html large":      {func(d *Draft) { d.HTMLBody = strings.Repeat("h", MaxHTMLBody+1) }, "html_body", CodeTooLarge},
		"no text":         {func(d *Draft) { d.TextBody = "" }, "text_body", CodeRequired},
		"text large":      {func(d *Draft) { d.TextBody = strings.Repeat("t", MaxTextBody+1) }, "text_body", CodeTooLarge},
		"text bad utf8":   {func(d *Draft) { d.TextBody = "a\xffb" }, "text_body", CodeInvalid},
		"variable key":    {func(d *Draft) { d.Variables = []string{"user.name", ".Foo"} }, "variables[1]", CodeInvalidVariable},
		"too many vars":   {func(d *Draft) { d.Variables = make([]string, MaxVariables+1); fill(d.Variables) }, "variables", CodeTooMany},
		"design":          {func(d *Draft) { d.Design = []byte(`{"type":"script"}`) }, "design.type", CodeUnknownNode},
		"raw html design": {func(d *Draft) { d.Design = []byte(block(`{"type":"html","attrs":{"html":"x"}}`)) }, "design.content[0]", CodeRawHTML},
	}
	for name, c := range cases {
		d := validDraft()
		c.edit(&d)
		w, err := d.Validate(DraftOptions{Topic: TopicSecurityNotice})
		details := apperrors.DetailsOf(err)
		if w != nil || len(details) != 1 || details[0].Field != c.field || details[0].Code != c.code {
			t.Errorf("%s: err = %v, details = %+v", name, err, details)
		}
	}
	d := validDraft()
	d.Design = []byte(block(`{"type":"html","attrs":{"html":"x"}}`))
	if _, err := d.Validate(DraftOptions{AllowRawHTML: true}); err != nil {
		t.Fatalf("admin raw html: %v", err)
	}
}

func fill(keys []string) {
	for i := range keys {
		keys[i] = "v" + strings.Repeat("a", i%50)
	}
}

func TestValidatePreview(t *testing.T) {
	if err := ValidatePreview(LocaleEnglish, "Hi", "<p>x</p>", "x"); err != nil {
		t.Fatal(err)
	}
	err := ValidatePreview("de", "", "", "")
	if len(apperrors.DetailsOf(err)) != 4 {
		t.Fatalf("details = %+v", apperrors.DetailsOf(err))
	}
}

func TestDraftSave(t *testing.T) {
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	d := validDraft()
	d.Revision = 0
	saved, err := d.Save(0, "editor-1", now)
	if err != nil || saved.Revision != 1 || saved.UpdatedBy != "editor-1" || !saved.UpdatedAt.Equal(now) {
		t.Fatalf("first save: %+v %v", saved, err)
	}
	saved.Revision = 1
	if again, err := saved.Save(1, "editor-2", now); err != nil || again.Revision != 2 {
		t.Fatalf("second save: %+v %v", again, err)
	}
	stale := validDraft()
	stale.Revision = 1
	if _, err := stale.Save(3, "editor-1", now); apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("stale save: %v", err)
	}
	fresh := validDraft()
	fresh.Revision = 2
	if _, err := fresh.Save(0, "editor-1", now); apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("revision given for an unsaved draft: %v", err)
	}
}
