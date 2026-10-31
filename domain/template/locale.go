package template

import "strings"

// Locale is a language a template is written in. Each template has one
// draft and its own published versions per locale.
type Locale string

// Locales templates may be written in. English is the default; Urdu is
// written right to left.
const (
	LocaleEnglish Locale = "en"
	LocaleUrdu    Locale = "ur"
)

// DefaultLocale is a template's locale when none is given.
const DefaultLocale = LocaleEnglish

// Locales lists the supported locales.
var Locales = []Locale{LocaleEnglish, LocaleUrdu}

// Valid reports whether l is a supported locale.
func (l Locale) Valid() bool {
	for _, s := range Locales {
		if l == s {
			return true
		}
	}
	return false
}

// Dir is the HTML text direction of the locale: "rtl" for Urdu, otherwise
// "ltr".
func (l Locale) Dir() string {
	if l == LocaleUrdu {
		return "rtl"
	}
	return "ltr"
}

// ParseLocale reads a locale, ignoring case and surrounding spaces.
func ParseLocale(s string) (Locale, bool) {
	l := Locale(strings.ToLower(strings.TrimSpace(s)))
	return l, l.Valid()
}
