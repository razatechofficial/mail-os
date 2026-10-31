package template

import (
	"slices"
	"strings"
	"testing"
)

func TestValidKey(t *testing.T) {
	for _, k := range []string{"link", "user.name", "contact.first_name", "a1_b2.c3", "code"} {
		if !ValidKey(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{"", "User.name", "1link", "user..name", "user.", ".user", "user-name", "_x", "user.Name",
		".Foo", strings.Repeat("a", MaxKeyLength+1)} {
		if ValidKey(k) {
			t.Errorf("%q accepted", k)
		}
	}
}

func TestPlaceholders(t *testing.T) {
	s := `Hi {{ user.name }}, {{user.email}} {{  link  }} {{ .Foo }} {{define "x"}} {{ User }} {{user.name}x {{{code}}} {{ a.b-c }}`
	var keys []string
	for _, p := range Placeholders(s) {
		keys = append(keys, p.Key)
		if got := s[p.Start:p.End]; !strings.HasPrefix(got, "{{") || !strings.HasSuffix(got, "}}") {
			t.Errorf("span %q", got)
		}
	}
	want := []string{"user.name", "user.email", "link", "code"}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
}

func TestReplacePlaceholders(t *testing.T) {
	got := ReplacePlaceholders("{{ a }}-{{b}}-{{ .c }}-{{", func(k string) string { return "<" + k + ">" })
	if got != "<a>-<b>-{{ .c }}-{{" {
		t.Fatalf("got %q", got)
	}
}

func TestSinglePlaceholder(t *testing.T) {
	if k, ok := SinglePlaceholder(" {{ link }} "); !ok || k != "link" {
		t.Fatalf("lone placeholder: %q %v", k, ok)
	}
	for _, s := range []string{"{{link}}x", "x{{link}}", "{{a}}{{b}}", "{{ .Link }}", "", "{{link}"} {
		if _, ok := SinglePlaceholder(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestExtractVariables(t *testing.T) {
	got := ExtractVariables("Notice for {{user.name}}", `<a href="{{ link }}">{{user.name}}</a>`, "{{code}} {{ .X }}")
	if !slices.Equal(got, []string{"code", "link", "user.name"}) {
		t.Fatalf("got %v", got)
	}
	if ExtractVariables("", "", "") != nil {
		t.Fatal("variables from nothing")
	}
}

func TestLookup(t *testing.T) {
	data := map[string]any{
		"user":          map[string]any{"name": "Amna"},
		"brand":         map[string]string{"locale": "ur"},
		"contact.email": "flat@example.com",
		"link":          "https://x",
	}
	cases := map[string]any{"user.name": "Amna", "brand.locale": "ur", "contact.email": "flat@example.com", "link": "https://x"}
	for k, want := range cases {
		if got, ok := Lookup(data, k); !ok || got != want {
			t.Errorf("%s = %v %v", k, got, ok)
		}
	}
	for _, k := range []string{"user.email", "link.x", "missing"} {
		if _, ok := Lookup(data, k); ok {
			t.Errorf("%s found", k)
		}
	}
	if _, ok := Lookup(nil, "x"); ok {
		t.Fatal("found in nil")
	}
}

func TestLocale(t *testing.T) {
	if LocaleUrdu.Dir() != "rtl" || LocaleEnglish.Dir() != "ltr" {
		t.Fatal("direction")
	}
	if l, ok := ParseLocale(" UR "); !ok || l != LocaleUrdu {
		t.Fatalf("parse = %q %v", l, ok)
	}
	if _, ok := ParseLocale("fr"); ok {
		t.Fatal("fr accepted")
	}
}
