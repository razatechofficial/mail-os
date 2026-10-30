package template

import (
	"regexp"
	"slices"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Limits on branding.
const (
	MaxBrandText = 500
	MaxLogoURL   = 2048
)

// Fonts a brand may use: families every mail client has.
var Fonts = []string{"Arial", "Helvetica", "Georgia", "Tahoma", "Verdana", "Trebuchet MS", "Times New Roman", "Courier New"}

var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ValidColor reports a #rrggbb colour.
func ValidColor(s string) bool { return colorRE.MatchString(s) }

// Branding is an organization's look for its templates: the designer's
// defaults for the logo, colours, font and footer. One per organization.
type Branding struct {
	OrgID                  string
	CompanyName            string
	LogoURL                string
	LogoAlt                string
	PrimaryColor           string
	BackgroundColor        string
	ContentBackgroundColor string
	TextColor              string
	LinkColor              string
	FontFamily             string
	CompanyAddress         string
	FooterText             string
	UpdatedAt              time.Time
}

// DefaultBranding is an organization's branding before an administrator
// sets one.
func DefaultBranding(orgID string) Branding {
	return Branding{
		OrgID:                  orgID,
		PrimaryColor:           "#2563eb",
		BackgroundColor:        "#f1f5f9",
		ContentBackgroundColor: "#ffffff",
		TextColor:              "#0f172a",
		LinkColor:              "#2563eb",
		FontFamily:             "Arial",
	}
}

// Normalize trims the branding, fills unset colours and font from the
// defaults, lower-cases colours, and validates it: #rrggbb colours, an
// https logo of at most MaxLogoURL characters, a font from Fonts, and text
// of at most MaxBrandText characters. The error is a 422.
func (b Branding) Normalize() (Branding, error) {
	def := DefaultBranding(b.OrgID)
	for _, f := range []*string{&b.CompanyName, &b.LogoURL, &b.LogoAlt, &b.CompanyAddress, &b.FooterText, &b.FontFamily} {
		*f = strings.TrimSpace(*f)
	}
	colors := []struct {
		field string
		val   *string
		def   string
	}{
		{"primary_color", &b.PrimaryColor, def.PrimaryColor},
		{"background_color", &b.BackgroundColor, def.BackgroundColor},
		{"content_background_color", &b.ContentBackgroundColor, def.ContentBackgroundColor},
		{"text_color", &b.TextColor, def.TextColor},
		{"link_color", &b.LinkColor, def.LinkColor},
	}
	var errs []apperrors.FieldError
	for _, c := range colors {
		*c.val = strings.ToLower(strings.TrimSpace(*c.val))
		if *c.val == "" {
			*c.val = c.def
		}
		if !ValidColor(*c.val) {
			errs = append(errs, apperrors.FieldError{Field: c.field, Code: CodeInvalidColor, Message: c.field + " must be a colour such as #2563eb"})
		}
	}
	if b.FontFamily == "" {
		b.FontFamily = def.FontFamily
	}
	if !slices.Contains(Fonts, b.FontFamily) {
		errs = append(errs, apperrors.FieldError{Field: "font_family", Code: CodeInvalid,
			Message: "font_family must be one of " + strings.Join(Fonts, ", ")})
	}
	switch {
	case b.LogoURL == "":
	case len(b.LogoURL) > MaxLogoURL:
		errs = append(errs, tooLong("logo_url", MaxLogoURL))
	case !HTTPSURL(b.LogoURL):
		errs = append(errs, apperrors.FieldError{Field: "logo_url", Code: CodeInvalidURL, Message: "logo_url must be an https:// URL"})
	}
	errs = appendText(errs, "company_name", b.CompanyName, MaxBrandText, false)
	errs = appendText(errs, "logo_alt", b.LogoAlt, MaxBrandText, false)
	errs = appendText(errs, "company_address", b.CompanyAddress, MaxBrandText, false)
	errs = appendText(errs, "footer_text", b.FooterText, MaxBrandText, false)
	if len(errs) > 0 {
		return b, apperrors.Validation(errs...)
	}
	return b, nil
}
