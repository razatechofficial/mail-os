package template

import (
	"strings"
	"testing"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func TestBrandingNormalize(t *testing.T) {
	b, err := Branding{
		OrgID:        "org-1",
		CompanyName:  "  Averox ",
		LogoURL:      "https://cdn.example.com/logo.png",
		PrimaryColor: " #1D4ED8",
		FontFamily:   "Trebuchet MS",
		FooterText:   "آپ کو یہ ای میل اس لیے ملی",
	}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if b.CompanyName != "Averox" || b.PrimaryColor != "#1d4ed8" || b.BackgroundColor != "#f1f5f9" || b.TextColor != "#0f172a" {
		t.Fatalf("not normalised: %+v", b)
	}
	if d, err := DefaultBranding("org-2").Normalize(); err != nil || d.FontFamily != "Arial" {
		t.Fatalf("defaults: %+v %v", d, err)
	}
	if b, err := (Branding{}).Normalize(); err != nil || b.LinkColor != "#2563eb" {
		t.Fatalf("empty branding: %+v %v", b, err)
	}
}

func TestBrandingNormalize_refuses(t *testing.T) {
	cases := map[string]struct {
		b     Branding
		field string
		code  string
	}{
		"colour name":   {Branding{PrimaryColor: "red"}, "primary_color", CodeInvalidColor},
		"colour short":  {Branding{TextColor: "#fff"}, "text_color", CodeInvalidColor},
		"colour inject": {Branding{LinkColor: "#ffffff;x"}, "link_color", CodeInvalidColor},
		"font":          {Branding{FontFamily: "Comic Sans MS"}, "font_family", CodeInvalid},
		"logo http":     {Branding{LogoURL: "http://cdn.example.com/logo.png"}, "logo_url", CodeInvalidURL},
		"logo js":       {Branding{LogoURL: "javascript:alert(1)"}, "logo_url", CodeInvalidURL},
		"logo long":     {Branding{LogoURL: "https://x.com/" + strings.Repeat("a", MaxLogoURL)}, "logo_url", CodeTooLong},
		"name long":     {Branding{CompanyName: strings.Repeat("n", MaxBrandText+1)}, "company_name", CodeTooLong},
		"footer long":   {Branding{FooterText: strings.Repeat("ف", MaxBrandText+1)}, "footer_text", CodeTooLong},
		"address":       {Branding{CompanyAddress: strings.Repeat("a", MaxBrandText+1)}, "company_address", CodeTooLong},
		"logo alt":      {Branding{LogoAlt: strings.Repeat("a", MaxBrandText+1)}, "logo_alt", CodeTooLong},
	}
	for name, c := range cases {
		_, err := c.b.Normalize()
		d := apperrors.DetailsOf(err)
		if len(d) != 1 || d[0].Field != c.field || d[0].Code != c.code {
			t.Errorf("%s: details = %+v", name, d)
		}
	}
	// 500 Urdu characters are within the limit though they are 1000 bytes.
	if _, err := (Branding{FooterText: strings.Repeat("ف", MaxBrandText)}).Normalize(); err != nil {
		t.Fatalf("limit counts bytes: %v", err)
	}
}
