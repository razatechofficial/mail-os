package template

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Limits on a draft's content (docs/mailos-template-api.md, Drafts).
const (
	// MaxSubject is RFC 5322's line limit.
	MaxSubject   = 998
	MaxPreheader = 255
	MaxHTMLBody  = 1 << 20
	MaxTextBody  = 256 << 10
	MaxVariables = 200
)

// Draft is a template's work in progress in one locale. Saving it bumps
// Revision; a save or publish naming another revision is refused, so two
// editors never overwrite each other. Revision 0 means nothing is saved.
type Draft struct {
	TemplateID string
	Locale     Locale
	Subject    string
	Preheader  string
	// Design is the designer's node tree as JSON, or nil when there is
	// none.
	Design   []byte
	HTMLBody string
	TextBody string
	// Variables are the keys the content uses, as the console found them.
	Variables []string
	Revision  int
	// UpdatedBy is the IAM user who saved it last: the one four-eyes keeps
	// from publishing it.
	UpdatedBy string
	UpdatedAt time.Time
}

// DraftOptions are what the validation needs beyond the draft.
type DraftOptions struct {
	// Topic is the template's topic; variables it does not declare are
	// warned about.
	Topic string
	// AllowRawHTML admits html design nodes (an administrator, with raw
	// HTML blocks switched on).
	AllowRawHTML bool
}

// Validate checks a draft before it is saved. err is a 422 with every
// failing field. warnings are variables the topic does not declare (code
// unknown_variable): allowed, and shown to the editor.
//
// The HTML body must still be sanitised before it is stored.
func (d Draft) Validate(opts DraftOptions) (warnings []apperrors.FieldError, err error) {
	errs := validateContent(d.Locale, d.Subject, d.Preheader, d.HTMLBody, d.TextBody)
	if !IsNullDesign(d.Design) {
		errs = append(errs, ValidateDesign(d.Design, DesignOptions{AllowRawHTML: opts.AllowRawHTML})...)
	}
	if len(d.Variables) > MaxVariables {
		errs = append(errs, apperrors.FieldError{Field: "variables", Code: CodeTooMany,
			Message: fmt.Sprintf("a draft declares at most %d variables", MaxVariables)})
	}
	for i, key := range d.Variables {
		if !ValidKey(key) {
			errs = append(errs, apperrors.FieldError{Field: fmt.Sprintf("variables[%d]", i), Code: CodeInvalidVariable,
				Message: "variable key must match ^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)*$"})
		}
	}
	if len(errs) > 0 {
		return nil, apperrors.Validation(errs...)
	}
	return UnknownVariables(opts.Topic, d.Variables), nil
}

// UnknownVariables warns about each key the topic does not declare. A
// template without a topic declares nothing to compare with, so it gets
// none.
func UnknownVariables(topic string, keys []string) []apperrors.FieldError {
	t, ok := TopicByKey(topic)
	if !ok {
		return nil
	}
	var out []apperrors.FieldError
	for i, key := range keys {
		if _, ok := t.Variable(key); !ok {
			out = append(out, apperrors.FieldError{Field: fmt.Sprintf("variables[%d]", i), Code: CodeUnknownVariable,
				Message: fmt.Sprintf("%s is not a variable of %s", key, topic)})
		}
	}
	return out
}

// ValidatePreview checks unsaved content sent for a preview: the same
// limits as a draft.
func ValidatePreview(locale Locale, subject, htmlBody, textBody string) error {
	if errs := validateContent(locale, subject, "", htmlBody, textBody); len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

func validateContent(locale Locale, subject, preheader, htmlBody, textBody string) []apperrors.FieldError {
	var errs []apperrors.FieldError
	if !locale.Valid() {
		errs = append(errs, invalidLocale("locale"))
	}
	errs = appendText(errs, "subject", subject, MaxSubject, true)
	if strings.ContainsAny(subject, "\r\n") {
		errs = append(errs, apperrors.FieldError{Field: "subject", Code: CodeInvalid, Message: "subject must be one line"})
	}
	errs = appendText(errs, "preheader", preheader, MaxPreheader, false)
	errs = appendBody(errs, "html_body", htmlBody, MaxHTMLBody)
	errs = appendBody(errs, "text_body", textBody, MaxTextBody)
	return errs
}

func appendBody(errs []apperrors.FieldError, field, s string, max int) []apperrors.FieldError {
	switch {
	case strings.TrimSpace(s) == "":
		return append(errs, required(field))
	case len(s) > max:
		return append(errs, tooLarge(field, max))
	case !utf8.ValidString(s):
		return append(errs, apperrors.FieldError{Field: field, Code: CodeInvalid, Message: field + " is not valid UTF-8"})
	}
	return errs
}

// CheckRevision refuses a write naming a revision other than the stored
// one (0 when nothing is saved): someone else saved in between. 409.
func CheckRevision(stored, given int) error {
	if stored != given {
		return apperrors.Conflict(fmt.Sprintf("the draft was saved by someone else (revision %d, not %d); reload it", stored, given))
	}
	return nil
}

// Save is the draft as stored: d carries the revision the editor loaded,
// which must be stored; the result has the next revision and its editor.
func (d Draft) Save(stored int, editor string, now time.Time) (Draft, error) {
	if err := CheckRevision(stored, d.Revision); err != nil {
		return Draft{}, err
	}
	d.Revision = stored + 1
	d.UpdatedBy = editor
	d.UpdatedAt = now
	return d, nil
}
