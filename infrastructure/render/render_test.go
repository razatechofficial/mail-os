package render

import (
	"encoding/json"
	htmltemplate "html/template"
	"strings"
	"testing"
	"time"

	tpl "github.com/razatechofficial/mail-os/domain/template"
)

func render(t *testing.T, c Content, data map[string]any, opts Options) Content {
	t.Helper()
	out, err := Render(c, data, opts)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

func TestRender_placeholders(t *testing.T) {
	data := map[string]any{"user": map[string]any{"name": "Amna"}, "link": "https://iam.example.com/r?a=1&b=2", "n": 3.0}
	out := render(t, Content{
		Subject: "Notice for {{ user.name }} ({{n}})",
		HTML:    `<p>Hi {{user.name}}, {{ user.name }}!</p><a href="{{link}}">Review</a>`,
		Text:    "Hi {{user.name}}\n{{link}}",
	}, data, Options{})
	if out.Subject != "Notice for Amna (3)" {
		t.Errorf("subject = %q", out.Subject)
	}
	if out.HTML != `<p>Hi Amna, Amna!</p><a href="https://iam.example.com/r?a=1&amp;b=2">Review</a>` {
		t.Errorf("html = %q", out.HTML)
	}
	if out.Text != "Hi Amna\nhttps://iam.example.com/r?a=1&b=2" {
		t.Errorf("text = %q", out.Text)
	}
}

func TestRender_escapesByContext(t *testing.T) {
	data := map[string]any{
		"name":  `<script>alert("x")</script>`,
		"quote": `" onmouseover="alert(1)`,
		"js":    "javascript:alert(1)",
		"js2":   " JaVaScRiPt:alert(1)",
		"q":     "a b&c=<d>",
		"css":   "red;background:url(javascript:alert(1))",
		"color": "#2563eb",
		"html":  htmltemplate.HTML(`<img src=x onerror=alert(1)>`),
		"url":   htmltemplate.URL("javascript:alert(1)"),
	}
	html := `<p>{{name}}</p><p title="{{quote}}">t</p><a href="{{js}}">a</a><a href="{{js2}}">b</a>` +
		`<a href="https://example.com/s?q={{q}}">c</a><p style="color: {{css}}">d</p><p style="color: {{color}}">e</p>` +
		`<p>{{html}}</p><a href="{{url}}">f</a><title>{{name}}</title>`
	out := render(t, Content{Subject: "{{name}}", HTML: html, Text: "{{name}}"}, data, Options{}).HTML
	for _, want := range []string{
		`<p>&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;</p>`,
		`title="&#34; onmouseover=&#34;alert(1)"`,
		`<a href="#ZgotmplZ">a</a>`,
		`<a href="#ZgotmplZ">b</a>`,
		`q=a%20b%26c%3d%3cd%3e`,
		`style="color: ZgotmplZ"`,
		`style="color: #2563eb"`,
		`<p>&lt;img src=x onerror=alert(1)&gt;</p>`,
		`<a href="#ZgotmplZ">f</a>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\nin %s", want, out)
		}
	}
	if strings.Contains(out, "<script") || strings.Contains(out, "<img") {
		t.Errorf("value executed: %s", out)
	}
}

func TestRender_textIsNotEscaped(t *testing.T) {
	out := render(t, Content{Subject: "a", Text: "Code: {{code}} & <b>{{name}}</b>"}, map[string]any{"code": "1<2", "name": "A&B"}, Options{})
	if out.Text != "Code: 1<2 & <b>A&B</b>" {
		t.Fatalf("text = %q", out.Text)
	}
	if out.HTML != "" {
		t.Fatalf("html from nothing = %q", out.HTML)
	}
}

func TestRender_subjectLineBreaks(t *testing.T) {
	out := render(t, Content{Subject: "Hi {{name}}"}, map[string]any{"name": "Amna\r\nBcc: victim@example.com"}, Options{})
	if out.Subject != "Hi AmnaBcc: victim@example.com" || strings.ContainsAny(out.Subject, "\r\n") {
		t.Fatalf("subject = %q", out.Subject)
	}
}

func TestRender_notPlaceholdersAreLiteral(t *testing.T) {
	src := `{{ .Foo }} {{define "x"}}boom{{end}} {{template "x"}} {{ printf "%s" "x" }} {{call .F}} {{ User }} {{a}` +
		` {{ {{name}} }} }} {{{name}}} {{- name -}} {{/* c */}} [[x]] {{`
	data := map[string]any{"name": "N", "Foo": "leak", "F": func() string { return "called" }}
	out := render(t, Content{Subject: src, HTML: "<p>" + src + "</p>", Text: src}, data, Options{})
	// {{end}} is a valid placeholder of a missing key: it renders "".
	wantText := `{{ .Foo }} {{define "x"}}boom {{template "x"}} {{ printf "%s" "x" }} {{call .F}} {{ User }} {{a}` +
		` {{ N }} }} {N} {{- name -}} {{/* c */}} [[x]] {{`
	if out.Text != wantText {
		t.Errorf("text = %q", out.Text)
	}
	if out.Subject != wantText {
		t.Errorf("subject = %q", out.Subject)
	}
	wantHTML := "<p>" + strings.ReplaceAll(wantText, `"`, "&#34;") + "</p>"
	if out.HTML != wantHTML {
		t.Errorf("html = %q\nwant  %q", out.HTML, wantHTML)
	}
	for _, leak := range []string{"leak", "called"} {
		if strings.Contains(out.HTML+out.Text+out.Subject, leak) {
			t.Errorf("%s executed", leak)
		}
	}
}

func TestRender_missingKeysAndValueKinds(t *testing.T) {
	data := map[string]any{
		"s": "x", "i": 42, "f": 1.5, "whole": 10.0, "b": true, "num": json.Number("7"), "nil": nil,
		"obj": map[string]any{"a": 1}, "list": []any{1, 2}, "at": time.Date(2026, 10, 31, 9, 30, 0, 0, time.UTC),
	}
	out := render(t, Content{
		Subject: "{{s}}|{{i}}|{{f}}|{{whole}}|{{b}}|{{num}}|{{nil}}|{{obj}}|{{list}}|{{missing}}|{{obj.a}}|{{at}}",
	}, data, Options{})
	if out.Subject != "x|42|1.5|10|true|7|||||1|2026-10-31T09:30:00Z" {
		t.Fatalf("subject = %q", out.Subject)
	}
	out = render(t, Content{Subject: "s", HTML: `<a href="{{missing}}">{{missing}}</a>`}, nil, Options{})
	if out.HTML != `<a href=""></a>` {
		t.Fatalf("html = %q", out.HTML)
	}
}

func TestRender_masking(t *testing.T) {
	data := tpl.SampleData(tpl.TopicMFAEmailCode)
	c := Content{Subject: "Your code {{code}}", HTML: "<p>Code: <b>{{ code }}</b> for {{email}}</p>", Text: "Code: {{code}}"}
	out := render(t, c, data, Options{Mask: tpl.SecretKeys(tpl.TopicMFAEmailCode)})
	for _, s := range []string{out.Subject, out.HTML, out.Text} {
		if strings.Contains(s, "482913") || !strings.Contains(s, Masked) {
			t.Errorf("not masked: %q", s)
		}
	}
	if !strings.Contains(out.HTML, "amna@example.com") {
		t.Errorf("unmasked variable lost: %q", out.HTML)
	}
	if plain := render(t, c, data, Options{}); !strings.Contains(plain.Text, "482913") {
		t.Errorf("code masked without asking: %q", plain.Text)
	}
}

func TestRender_rtl(t *testing.T) {
	data := tpl.SampleData(tpl.TopicSecurityNotice)
	data["brand"].(map[string]any)["locale"] = "ur"
	data["user"].(map[string]any)["name"] = "آمنہ"
	locale := tpl.LocaleFromData(data, tpl.LocaleEnglish)
	if locale != tpl.LocaleUrdu || locale.Dir() != "rtl" {
		t.Fatalf("locale = %q", locale)
	}
	html := `<!doctype html><html lang="ur" dir="` + locale.Dir() + `"><body><p dir="rtl" style="text-align:right">السلام علیکم {{user.name}}</p></body></html>`
	out := render(t, Content{Subject: "سیکیورٹی نوٹس {{user.name}}", HTML: html, Text: "السلام علیکم {{user.name}}"}, data, Options{})
	if out.Subject != "سیکیورٹی نوٹس آمنہ" || out.Text != "السلام علیکم آمنہ" {
		t.Fatalf("urdu text = %q / %q", out.Subject, out.Text)
	}
	for _, want := range []string{`<html lang="ur" dir="rtl">`, `<p dir="rtl" style="text-align:right">السلام علیکم آمنہ</p>`} {
		if !strings.Contains(out.HTML, want) {
			t.Errorf("missing %q in %s", want, out.HTML)
		}
	}
}

func TestRender_sanitisesTheTemplate(t *testing.T) {
	out := render(t, Content{Subject: "s", HTML: `<p onclick="alert(1)">Hi {{name}}</p><script>alert(1)</script><a href="javascript:alert(1)">x</a>`},
		map[string]any{"name": "N"}, Options{})
	if out.HTML != `<p>Hi N</p><a>x</a>` {
		t.Fatalf("html = %q", out.HTML)
	}
}

func TestRender_placeholderInAttributeAndStyle(t *testing.T) {
	data := map[string]any{"brand": map[string]any{"primary_color": "#2563eb", "logo_url": "https://cdn.example.com/l.png"}, "w": 140}
	html := `<td style="background-color: {{brand.primary_color}}"><img src="{{brand.logo_url}}" width="{{w}}"></td>` +
		`<style>.x{color:{{brand.primary_color}}}</style>`
	out := render(t, Content{Subject: "s", HTML: "<table><tr>" + html + "</tr></table>"}, data, Options{}).HTML
	for _, want := range []string{`style="background-color: #2563eb"`, `src="https://cdn.example.com/l.png"`, `width="140"`, `.x{color:#2563eb}`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
}

func TestRender_cssValueCannotBreakOut(t *testing.T) {
	data := map[string]any{"c": "red}body{background:url(javascript:alert(1))", "u": "a b')"}
	out := render(t, Content{Subject: "s", HTML: `<style>a{color:{{c}}}</style><p style="background:url('https://cdn.example.com/{{u}}')">x</p>`}, data, Options{}).HTML
	if strings.Contains(out, "body{") || strings.Contains(out, "javascript") {
		t.Fatalf("css value broke out: %s", out)
	}
	if !strings.Contains(out, "ZgotmplZ") || !strings.Contains(out, "a%20b") {
		t.Fatalf("css values not escaped: %s", out)
	}
}

func TestDelimitersAvoidContent(t *testing.T) {
	l, r, err := delimiters("[[")
	if err != nil || !strings.HasPrefix(l, "[[") || !strings.HasSuffix(r, "]]") || l == "[[" {
		t.Fatalf("delimiters = %q %q %v", l, r, err)
	}
	l2, _, _ := delimiters("")
	if l == l2 {
		t.Fatal("delimiters repeat between renders")
	}
}
