package template

import (
	"strings"
	"testing"
)

const sampleDesign = `{
  "type": "email",
  "attrs": {"schema": 1, "width": 600, "background": "#f1f5f9", "dir": "ltr"},
  "content": [
    {"type": "header", "attrs": {"logo": "url", "logo_url": "https://cdn.example.com/logo.png", "align": "center"}},
    {"type": "text", "attrs": {"padding": 16},
      "content": [
        {"type": "paragraph", "content": [
          {"type": "text", "text": "Hello "},
          {"type": "variable", "attrs": {"key": "user.name", "fallback": "there"}, "marks": [{"type": "bold"}]},
          {"type": "hardBreak"},
          {"type": "text", "text": "read", "marks": [{"type": "link", "attrs": {"href": "mailto:help@example.com"}}, {"type": "italic"}]}
        ]},
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Title"}]},
        {"type": "bulletList", "content": [
          {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "one"}]},
            {"type": "orderedList", "content": [{"type": "listItem", "content": [{"type": "paragraph"}]}]}]}
        ]}
      ]},
    {"type": "button", "attrs": {"label": "Review", "href": "{{ link }}"}},
    {"type": "image", "attrs": {"src": "https://cdn.example.com/a.png", "href": "https://example.com"}},
    {"type": "divider"},
    {"type": "spacer", "attrs": {"height": 24}},
    {"type": "columns", "attrs": {"count": 2}, "content": [
      {"type": "column", "content": [{"type": "button", "attrs": {"href": "https://example.com/a"}}]},
      {"type": "column", "content": [{"type": "text", "content": []}]}
    ]},
    {"type": "footer", "attrs": {"show_unsubscribe": true}}
  ]
}`

func TestValidateDesign_accepts(t *testing.T) {
	if errs := ValidateDesign([]byte(sampleDesign), DesignOptions{}); errs != nil {
		t.Fatalf("valid design refused: %+v", errs)
	}
}

func block(b string) string {
	return `{"type":"email","content":[` + b + `]}`
}

func TestValidateDesign_refuses(t *testing.T) {
	cases := map[string]struct {
		design string
		field  string
		code   string
	}{
		"root not email":    {`{"type":"text"}`, "design.type", CodeInvalidNesting},
		"unknown node":      {block(`{"type":"script"}`), "design.content[0].type", CodeUnknownNode},
		"email nested":      {block(`{"type":"email"}`), "design.content[0].type", CodeInvalidNesting},
		"column at top":     {block(`{"type":"column"}`), "design.content[0].type", CodeInvalidNesting},
		"inline at top":     {block(`{"type":"paragraph"}`), "design.content[0].type", CodeInvalidNesting},
		"one column":        {block(`{"type":"columns","content":[{"type":"column"}]}`), "design.content[0].content", CodeInvalidNesting},
		"four columns":      {block(`{"type":"columns","content":[{"type":"column"},{"type":"column"},{"type":"column"},{"type":"column"}]}`), "design.content[0].content", CodeInvalidNesting},
		"columns in column": {block(`{"type":"columns","content":[{"type":"column","content":[{"type":"columns"}]},{"type":"column"}]}`), "design.content[0].content[0].content[0].type", CodeInvalidNesting},
		"header in column":  {block(`{"type":"columns","content":[{"type":"column"},{"type":"column","content":[{"type":"header"}]}]}`), "design.content[0].content[1].content[0].type", CodeInvalidNesting},
		"footer in column":  {block(`{"type":"columns","content":[{"type":"column","content":[{"type":"footer"}]},{"type":"column"}]}`), "design.content[0].content[0].content[0].type", CodeInvalidNesting},
		"leaf with content": {block(`{"type":"divider","content":[{"type":"spacer"}]}`), "design.content[0].content", CodeInvalidNesting},
		"unknown mark":      {block(`{"type":"text","content":[{"type":"paragraph","content":[{"type":"text","text":"x","marks":[{"type":"code"}]}]}]}`), "design.content[0].content[0].content[0].marks[0].type", CodeUnknownMark},
		"marks on block":    {block(`{"type":"divider","marks":[{"type":"bold"}]}`), "design.content[0].marks", CodeInvalid},
		"text on block":     {block(`{"type":"divider","text":"x"}`), "design.content[0].text", CodeInvalid},
		"button js":         {block(`{"type":"button","attrs":{"href":"javascript:alert(1)"}}`), "design.content[0].attrs.href", CodeInvalidURL},
		"button http":       {block(`{"type":"button","attrs":{"href":"http://example.com"}}`), "design.content[0].attrs.href", CodeInvalidURL},
		"button two vars":   {block(`{"type":"button","attrs":{"href":"{{a}}{{b}}"}}`), "design.content[0].attrs.href", CodeInvalidURL},
		"button not string": {block(`{"type":"button","attrs":{"href":5}}`), "design.content[0].attrs.href", CodeInvalidType},
		"image placeholder": {block(`{"type":"image","attrs":{"src":"{{logo}}"}}`), "design.content[0].attrs.src", CodeInvalidURL},
		"image data":        {block(`{"type":"image","attrs":{"src":"data:image/png;base64,AAAA"}}`), "design.content[0].attrs.src", CodeInvalidURL},
		"image href":        {block(`{"type":"image","attrs":{"src":"https://x.com/a.png","href":"vbscript:x"}}`), "design.content[0].attrs.href", CodeInvalidURL},
		"logo http":         {block(`{"type":"header","attrs":{"logo_url":"http://x.com/a.png"}}`), "design.content[0].attrs.logo_url", CodeInvalidURL},
		"link no href":      {block(`{"type":"text","content":[{"type":"paragraph","content":[{"type":"text","text":"x","marks":[{"type":"link"}]}]}]}`), "design.content[0].content[0].content[0].marks[0].attrs.href", CodeRequired},
		"link js":           {block(`{"type":"text","content":[{"type":"paragraph","content":[{"type":"text","text":"x","marks":[{"type":"link","attrs":{"href":" javascript:alert(1)"}}]}]}]}`), "design.content[0].content[0].content[0].marks[0].attrs.href", CodeInvalidURL},
		"variable key":      {block(`{"type":"text","content":[{"type":"paragraph","content":[{"type":"variable","attrs":{"key":".Foo"}}]}]}`), "design.content[0].content[0].content[0].attrs.key", CodeInvalidVariable},
		"raw html":          {block(`{"type":"spacer"},{"type":"html","attrs":{"html":"<b>x</b>"}}`), "design.content[1]", CodeRawHTML},
		"unknown field":     {`{"type":"email","script":"x"}`, "design", CodeInvalid},
		"not json":          {`{"type":`, "design", CodeInvalid},
		"trailing data":     {`{"type":"email"} {}`, "design", CodeInvalid},
	}
	for name, c := range cases {
		errs := ValidateDesign([]byte(c.design), DesignOptions{})
		if len(errs) != 1 || errs[0].Field != c.field || errs[0].Code != c.code {
			t.Errorf("%s: errors = %+v, want %s %s", name, errs, c.field, c.code)
		}
	}
}

func TestValidateDesign_rawHTML(t *testing.T) {
	d := block(`{"type":"html","attrs":{"html":"<table><tr><td>x</td></tr></table>"}},` +
		`{"type":"columns","content":[{"type":"column","content":[{"type":"html","attrs":{"html":"<b>y</b>"}}]},{"type":"column"}]}`)
	if errs := ValidateDesign([]byte(d), DesignOptions{AllowRawHTML: true}); errs != nil {
		t.Fatalf("admin raw html refused: %+v", errs)
	}
	errs := ValidateDesign([]byte(d), DesignOptions{})
	if len(errs) != 2 || errs[0].Code != CodeRawHTML || errs[1].Field != "design.content[1].content[0].content[0]" {
		t.Fatalf("raw html without the flag: %+v", errs)
	}
	errs = ValidateDesign([]byte(block(`{"type":"html","attrs":{"html":7}}`)), DesignOptions{AllowRawHTML: true})
	if len(errs) != 1 || errs[0].Field != "design.content[0].attrs.html" {
		t.Fatalf("non-string html: %+v", errs)
	}
}

func TestValidateDesign_limits(t *testing.T) {
	big := block(`{"type":"text","content":[{"type":"paragraph","content":[{"type":"text","text":"` + strings.Repeat("a", MaxDesignBytes) + `"}]}]}`)
	if errs := ValidateDesign([]byte(big), DesignOptions{}); len(errs) != 1 || errs[0].Code != CodeTooLarge {
		t.Fatalf("large design: %+v", errs)
	}
	deep := `{"type":"listItem","content":[{"type":"bulletList","content":[`
	d := `{"type":"paragraph"}`
	for range MaxDesignDepth {
		d = deep + d + `]}]}`
	}
	d = block(`{"type":"text","content":[{"type":"bulletList","content":[` + d + `]}]}`)
	errs := ValidateDesign([]byte(d), DesignOptions{})
	if len(errs) != 1 || errs[0].Code != CodeInvalidNesting || !strings.Contains(errs[0].Message, "deep") {
		t.Fatalf("deep design: %+v", errs)
	}
	many := strings.Repeat(`{"type":"bogus"},`, 200)
	if errs := ValidateDesign([]byte(block(many+`{"type":"spacer"}`)), DesignOptions{}); len(errs) != maxDesignErrors {
		t.Fatalf("errors not capped: %d", len(errs))
	}
}

func TestLinkURL(t *testing.T) {
	for _, s := range []string{"https://example.com", "HTTPS://example.com/a?b={{c}}", "mailto:a@example.com", "MAILTO:a@example.com", "{{link}}", "{{ link }}"} {
		if !LinkURL(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"http://example.com", "javascript:alert(1)", "java\tscript:alert(1)", "//example.com", "/a", "https://", "https://exa mple.com",
		"mailto:", "data:text/html,x", "{{link}}/x", "{{ .Link }}", "https://example.com/\x00"} {
		if LinkURL(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestIsNullDesign(t *testing.T) {
	for _, s := range []string{"", " null ", "\n"} {
		if !IsNullDesign([]byte(s)) {
			t.Errorf("%q not null", s)
		}
	}
	if IsNullDesign([]byte(`{"type":"email"}`)) {
		t.Fatal("design is null")
	}
}
