// Package template is MailOS's email templates (docs/mailos-template-api.md):
// a template's metadata, its per-locale draft and the immutable versions
// published from it, the designer's node tree, the organization's branding,
// and the static catalogue of event topics and the variables each carries.
//
// It validates what the console saves and decides publishing (revisions,
// four-eyes). It never renders: infrastructure/render does, escaping every
// value and executing nothing from the template text.
package template

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Field error codes in a 422's details. The console shows Message and keys
// its handling off Code.
const (
	CodeRequired        = "required"
	CodeTooLong         = "too_long"
	CodeTooLarge        = "too_large"
	CodeTooMany         = "too_many"
	CodeInvalid         = "invalid"
	CodeInvalidType     = "invalid_type"
	CodeInvalidURL      = "invalid_url"
	CodeInvalidEmail    = "invalid_email"
	CodeInvalidDatetime = "invalid_datetime"
	CodeInvalidNumber   = "invalid_number"
	CodeInvalidColor    = "invalid_color"
	CodeInvalidVariable = "invalid_variable"
	CodeUnknownTopic    = "unknown_topic"
	CodeUnknownNode     = "unknown_node"
	CodeUnknownMark     = "unknown_mark"
	CodeInvalidNesting  = "invalid_nesting"
	CodeRawHTML         = "raw_html_not_allowed"
	CodeNoDraft         = "no_draft"
	// CodeTaken is a slug or topic another live template already has.
	CodeTaken = "taken"
	// CodeUnknownVariable is a warning, never an error: a draft may use a
	// variable its topic does not declare.
	CodeUnknownVariable = "unknown_variable"
)

// Category is what kind of mail a template sends.
type Category string

// Template categories.
const (
	CategoryTransactional Category = "transactional"
	CategoryMarketing     Category = "marketing"
	CategoryNotification  Category = "notification"
)

// Categories lists the categories.
var Categories = []Category{CategoryTransactional, CategoryMarketing, CategoryNotification}

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	for _, k := range Categories {
		if c == k {
			return true
		}
	}
	return false
}

// Limits on a template's metadata.
const (
	MaxName        = 255
	MaxSlug        = 100
	MaxDescription = 2000
)

// slugRE is lower-case words joined by single hyphens: iam-security-notice.
var slugRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Template is one organization's email template. Its content lives in a
// draft and published versions per locale; a message sent by slug uses the
// active version of its locale, else of DefaultLocale.
type Template struct {
	ID string
	// OrgID is the tenant or organization that owns the template (stored as
	// org_id). Another organization never sees it.
	OrgID       string
	Name        string
	Slug        string
	Category    Category
	Description string
	// Topic is the event the template serves, or "" for none; the designer
	// offers that topic's variables.
	Topic         string
	DefaultLocale Locale
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Normalize trims the template's fields, lower-cases the slug, fills the
// default category and locale, and validates it. The error is a 422 with
// one detail per failing field.
func (t Template) Normalize() (Template, error) {
	t.Name = strings.TrimSpace(t.Name)
	t.Slug = strings.ToLower(strings.TrimSpace(t.Slug))
	t.Description = strings.TrimSpace(t.Description)
	t.Topic = strings.TrimSpace(t.Topic)
	if t.Category == "" {
		t.Category = CategoryTransactional
	}
	if t.DefaultLocale == "" {
		t.DefaultLocale = DefaultLocale
	}
	if errs := t.validate(); len(errs) > 0 {
		return t, apperrors.Validation(errs...)
	}
	return t, nil
}

func (t Template) validate() []apperrors.FieldError {
	var errs []apperrors.FieldError
	errs = appendText(errs, "name", t.Name, MaxName, true)
	errs = appendText(errs, "description", t.Description, MaxDescription, false)
	switch {
	case t.Slug == "":
		errs = append(errs, required("slug"))
	case len(t.Slug) > MaxSlug:
		errs = append(errs, tooLong("slug", MaxSlug))
	case !slugRE.MatchString(t.Slug):
		errs = append(errs, apperrors.FieldError{Field: "slug", Code: CodeInvalid,
			Message: "slug must be lower-case letters and digits joined by single hyphens"})
	}
	if !t.Category.Valid() {
		errs = append(errs, apperrors.FieldError{Field: "category", Code: CodeInvalid,
			Message: "category must be transactional, marketing or notification"})
	}
	if t.Topic != "" {
		if _, ok := TopicByKey(t.Topic); !ok {
			errs = append(errs, apperrors.FieldError{Field: "topic", Code: CodeUnknownTopic,
				Message: "topic is not in the topic catalogue"})
		}
	}
	if !t.DefaultLocale.Valid() {
		errs = append(errs, invalidLocale("default_locale"))
	}
	return errs
}

// appendText checks a free-text field: valid UTF-8, at most max characters,
// and present when req.
func appendText(errs []apperrors.FieldError, field, s string, max int, req bool) []apperrors.FieldError {
	switch {
	case s == "" && req:
		return append(errs, required(field))
	case !utf8.ValidString(s):
		return append(errs, apperrors.FieldError{Field: field, Code: CodeInvalid, Message: field + " is not valid UTF-8"})
	case utf8.RuneCountInString(s) > max:
		return append(errs, tooLong(field, max))
	}
	return errs
}

func required(field string) apperrors.FieldError {
	return apperrors.FieldError{Field: field, Code: CodeRequired, Message: field + " is required"}
}

func tooLong(field string, max int) apperrors.FieldError {
	return apperrors.FieldError{Field: field, Code: CodeTooLong, Message: fmt.Sprintf("%s must be at most %d characters", field, max)}
}

func tooLarge(field string, max int) apperrors.FieldError {
	return apperrors.FieldError{Field: field, Code: CodeTooLarge, Message: fmt.Sprintf("%s must be at most %d bytes", field, max)}
}

func invalidLocale(field string) apperrors.FieldError {
	return apperrors.FieldError{Field: field, Code: CodeInvalid, Message: field + " must be en or ur"}
}
