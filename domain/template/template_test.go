package template

import (
	"strings"
	"testing"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func TestTemplateNormalize(t *testing.T) {
	got, err := Template{Name: "  Security notice ", Slug: " IAM-Security-Notice ", Topic: TopicSecurityNotice}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Security notice" || got.Slug != "iam-security-notice" || got.Category != CategoryTransactional ||
		got.DefaultLocale != LocaleEnglish {
		t.Fatalf("not normalised: %+v", got)
	}
	if _, err := (Template{Name: "x", Slug: "x", Category: CategoryMarketing, DefaultLocale: LocaleUrdu}).Normalize(); err != nil {
		t.Fatalf("topic-less template refused: %v", err)
	}
}

func TestTemplateNormalize_refuses(t *testing.T) {
	cases := map[string]struct {
		tpl   Template
		field string
		code  string
	}{
		"no name":       {Template{Slug: "a"}, "name", CodeRequired},
		"long name":     {Template{Name: strings.Repeat("n", MaxName+1), Slug: "a"}, "name", CodeTooLong},
		"no slug":       {Template{Name: "a"}, "slug", CodeRequired},
		"slug spaces":   {Template{Name: "a", Slug: "a b"}, "slug", CodeInvalid},
		"slug hyphens":  {Template{Name: "a", Slug: "a--b"}, "slug", CodeInvalid},
		"slug trailing": {Template{Name: "a", Slug: "a-"}, "slug", CodeInvalid},
		"slug long":     {Template{Name: "a", Slug: strings.Repeat("s", MaxSlug+1)}, "slug", CodeTooLong},
		"category":      {Template{Name: "a", Slug: "a", Category: "spam"}, "category", CodeInvalid},
		"topic":         {Template{Name: "a", Slug: "a", Topic: "iam.nope"}, "topic", CodeUnknownTopic},
		"locale":        {Template{Name: "a", Slug: "a", DefaultLocale: "fr"}, "default_locale", CodeInvalid},
		"description":   {Template{Name: "a", Slug: "a", Description: strings.Repeat("d", MaxDescription+1)}, "description", CodeTooLong},
		"bad utf8":      {Template{Name: "a\xff", Slug: "a"}, "name", CodeInvalid},
	}
	for name, c := range cases {
		_, err := c.tpl.Normalize()
		if apperrors.KindOf(err) != apperrors.KindInvalidInput {
			t.Errorf("%s: err = %v", name, err)
			continue
		}
		d := apperrors.DetailsOf(err)
		if len(d) != 1 || d[0].Field != c.field || d[0].Code != c.code {
			t.Errorf("%s: details = %+v", name, d)
		}
	}
}
