package render

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func sanitize(t *testing.T, src string) string {
	t.Helper()
	out, err := SanitizeHTML(src)
	if err != nil {
		t.Fatalf("sanitize %q: %v", src, err)
	}
	return out
}

// checkSafe parses sanitised output as a browser would and fails on
// anything active: a dropped or foreign element, an event handler or other
// refused attribute, an unsafe URL, a comment, or CSS that runs script or
// loads over anything but https.
func checkSafe(t *testing.T, vector, out string) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.CommentNode:
			t.Errorf("vector %q: comment survived in %q", vector, out)
		case html.ElementNode:
			if n.Namespace != "" || droppedElements[n.Data] || !keptElements[n.Data] {
				t.Errorf("vector %q: element <%s> survived in %q", vector, n.Data, out)
			}
			for _, a := range n.Attr {
				k := strings.ToLower(a.Key)
				switch {
				case strings.HasPrefix(k, "on"), k == "srcdoc", k == "formaction", k == "http-equiv":
					t.Errorf("vector %q: attribute %s survived in %q", vector, k, out)
				case urlAttrs[k]:
					if _, ok := cleanURL(a.Val); !ok {
						t.Errorf("vector %q: URL %s=%q survived", vector, k, a.Val)
					}
				case k == "style":
					checkCSS(t, vector, a.Val)
				}
			}
			if n.Data == "style" && n.FirstChild != nil {
				checkCSS(t, vector, n.FirstChild.Data)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
}

func checkCSS(t *testing.T, vector, css string) {
	t.Helper()
	norm := normalizeCSS(css)
	for _, f := range append(cssForbidden, "url(http:", "url('http:", `url("http:`, "url(//", "url(javascript") {
		if strings.Contains(norm, f) {
			t.Errorf("vector %q: CSS %q survived (%s)", vector, css, f)
		}
	}
}

// OWASP XSS filter evasion vectors, and a few of the mutation XSS kind.
var xssVectors = []string{
	`<script>alert(1)</script>`,
	`<SCRIPT SRC=https://xss.example/xss.js></SCRIPT>`,
	`<IMG SRC="javascript:alert('XSS');">`,
	`<IMG SRC=javascript:alert('XSS')>`,
	`<IMG SRC=JaVaScRiPt:alert('XSS')>`,
	"<IMG SRC=`javascript:alert(\"XSS\")`>",
	`<a onmouseover="alert(document.cookie)">x</a>`,
	`<IMG """><SCRIPT>alert("XSS")</SCRIPT>">`,
	`<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>`,
	`<IMG SRC=# onmouseover="alert('xxs')">`,
	`<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>`,
	`<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097">`,
	`<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>`,
	`<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>`,
	"<IMG SRC=\"jav\tascript:alert('XSS');\">",
	`<IMG SRC="jav&#x09;ascript:alert('XSS');">`,
	`<IMG SRC="jav&#x0A;ascript:alert('XSS');">`,
	`<IMG SRC=" &#14;  javascript:alert('XSS');">`,
	`<SCRIPT/XSS SRC="https://xss.example/xss.js"></SCRIPT>`,
	`<BODY onload!#$%&()*~+-_.,:;?@[/|\]^` + "`" + `=alert("XSS")>`,
	`<<SCRIPT>alert("XSS");//<</SCRIPT>`,
	`<SCRIPT SRC=//xss.example/.j>`,
	`<IMG SRC="('XSS')"`,
	`<iframe src=https://xss.example/scriptlet.html <`,
	`</TITLE><SCRIPT>alert("XSS");</SCRIPT>`,
	`<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">`,
	`<BODY BACKGROUND="javascript:alert('XSS')">`,
	`<IMG DYNSRC="javascript:alert('XSS')">`,
	`<IMG LOWSRC="javascript:alert('XSS')">`,
	`<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>`,
	`<svg/onload=alert('XSS')>`,
	`<svg><script>alert(1)</script></svg>`,
	`<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`,
	`<BODY ONLOAD=alert('XSS')>`,
	`<BGSOUND SRC="javascript:alert('XSS');">`,
	`<BR SIZE="&{alert('XSS')}">`,
	`<LINK REL="stylesheet" HREF="javascript:alert('XSS');">`,
	`<STYLE>@import'https://xss.example/xss.css';</STYLE>`,
	`<META HTTP-EQUIV="Link" Content="<https://xss.example/xss.css>; REL=stylesheet">`,
	`<STYLE>BODY{-moz-binding:url("https://xss.example/xssmoz.xml#xss")}</STYLE>`,
	`<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>`,
	`<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">`,
	`<div style="width: expression(alert('XSS'));">`,
	`<div style="width: ex\70 ression(alert('XSS'));">`,
	`<STYLE TYPE="text/javascript">alert('XSS');</STYLE>`,
	`<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>`,
	`<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>`,
	`<XSS STYLE="behavior: url(xss.htc);">`,
	`<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">`,
	`<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">`,
	`<IFRAME SRC="javascript:alert('XSS');"></IFRAME>`,
	`<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>`,
	`<TABLE BACKGROUND="javascript:alert('XSS')">`,
	`<TABLE><TD BACKGROUND="javascript:alert('XSS')">`,
	`<DIV STYLE="background-image: url(javascript:alert('XSS'))">`,
	`<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">`,
	`<DIV STYLE="width: expression(alert('XSS'));">`,
	`<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->`,
	`<BASE HREF="javascript:alert('XSS');//">`,
	`<OBJECT TYPE="text/x-scriptlet" DATA="https://xss.example/scriptlet.html"></OBJECT>`,
	`<EMBED SRC="data:image/svg+xml;base64,PHN2Zz48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+" type="image/svg+xml"></EMBED>`,
	`<a href="javascript&colon;alert(1)">x</a>`,
	`<a href="  javascript:alert(1)">x</a>`,
	`<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">x</a>`,
	`<a href="vbscript:msgbox(1)">x</a>`,
	`<iframe srcdoc="<script>alert(1)</script>"></iframe>`,
	`<form><button formaction="javascript:alert(1)">x</button></form>`,
	`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`,
	`<textarea><img src=x onerror=alert(1)></textarea>`,
	`<template><img src=x onerror=alert(1)></template>`,
	`<xmp><img src=x onerror=alert(1)></xmp>`,
	`<style></sty/**/le><img src=x onerror=alert(1)></style>`,
	`<style>a{color:red}</style ><script>alert(1)</script>`,
	`<p style="color:red;background:url(http://tracker.example/p.gif)">x</p>`,
	`<img src="http://tracker.example/p.gif">`,
	`<a href="//evil.example">x</a>`,
	`<img src=x:alert(alt) onerror=eval(src) alt=0>`,
	`<details open ontoggle=alert(1)>`,
	`<video><source onerror="alert(1)"></video>`,
	`<marquee onstart=alert(1)>x</marquee>`,
	`<a href="java&#0000009;script:alert(1)">x</a>`,
}

func TestSanitizeHTML_xssVectors(t *testing.T) {
	for _, v := range xssVectors {
		out := sanitize(t, v)
		checkSafe(t, v, out)
		// Whatever survives must read the same when sanitised again: no
		// mutation between parses.
		if again := sanitize(t, out); again != out {
			t.Errorf("vector %q not stable:\n  %q\n  %q", v, out, again)
		}
	}
}

func TestSanitizeHTML_keepsEmailLayout(t *testing.T) {
	src := `<!doctype html><html lang="ur" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">` +
		`<title>Notice</title><style>.btn{color:#fff;background:url(https://cdn.example.com/b.png)}</style></head>` +
		`<body style="margin:0" bgcolor="#f1f5f9"><center><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" align="center">` +
		`<tr><td background="https://cdn.example.com/bg.png" style="padding:24px;font-family:Arial" valign="top">` +
		`<h1>Hello</h1><p>Line<br>two <strong>b</strong> <em>i</em> <u>u</u> <s>s</s> <sup>1</sup><sub>2</sub></p>` +
		`<ul><li>one</li></ul><ol start="2"><li>two</li></ol><blockquote>q</blockquote><pre><code>c</code></pre><hr>` +
		`<a href="https://example.com/x?a=1&amp;b=2" target="_blank">link</a> <a href="mailto:help@example.com">mail</a> <a href="#top">top</a>` +
		`<img src="cid:logo@example.com" alt="logo" width="140"><font color="#333333" face="Arial">f</font>` +
		`</td></tr></table></center></body></html>`
	out := sanitize(t, src)
	for _, want := range []string{
		`<!DOCTYPE html>`, `<html lang="ur" dir="rtl">`, `<meta charset="utf-8"/>`, `<meta name="viewport" content="width=device-width"/>`,
		`<title>Notice</title>`, `.btn{color:#fff;background:url(https://cdn.example.com/b.png)}`,
		`<body style="margin:0" bgcolor="#f1f5f9">`, `<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" align="center">`,
		`<td background="https://cdn.example.com/bg.png" style="padding:24px;font-family:Arial" valign="top">`,
		`<h1>Hello</h1>`, `<br/>`, `<strong>b</strong>`, `<ol start="2">`, `<hr/>`, `<blockquote>q</blockquote>`,
		`<a href="https://example.com/x?a=1&amp;b=2" target="_blank">link</a>`, `<a href="mailto:help@example.com">`, `<a href="#top">`,
		`<img src="cid:logo@example.com" alt="logo" width="140"/>`, `<font color="#333333" face="Arial">f</font>`, `<center>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lost %q\nin %s", want, out)
		}
	}
}

func TestSanitizeHTML_fragment(t *testing.T) {
	out := sanitize(t, `<div class="x" onclick="alert(1)">Hi <custom-tag>there</custom-tag><script>x</script></div>`)
	if out != `<div class="x">Hi there</div>` {
		t.Fatalf("fragment = %q", out)
	}
	if out := sanitize(t, "plain {{ user.name }} & text"); out != "plain {{ user.name }} &amp; text" {
		t.Fatalf("text fragment = %q", out)
	}
}

func TestSanitizeHTML_placeholdersSurvive(t *testing.T) {
	src := `<p title="{{ user.name }}">Hi {{user.name}}</p><a href="{{link}}">a</a><a href="{{ link }}">b</a>` +
		`<a href="https://example.com/v?t={{token}}">c</a><img src="{{logo}}" alt="{{brand.name}}">` +
		`<td style="color: {{brand.primary_color}}; padding: 4px">x</td>` +
		`<a href="{{link}}/x">d</a><a href="{{ .Link }}">e</a><style>.a{color:{{brand.accent_color}}}</style>`
	out := sanitize(t, src)
	for _, want := range []string{
		`title="{{ user.name }}"`, `Hi {{user.name}}`, `href="{{link}}">a`, `href="{{ link }}">b`,
		`href="https://example.com/v?t={{token}}"`, `src="{{logo}}"`, `alt="{{brand.name}}"`,
		`.a{color:{{brand.accent_color}}}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lost %q\nin %s", want, out)
		}
	}
	// Only a lone placeholder is a URL: anything around it is refused.
	if strings.Contains(out, `{{link}}/x`) || strings.Contains(out, `.Link`) {
		t.Errorf("non-lone placeholder URL kept: %s", out)
	}
}

func TestSanitizeCSS(t *testing.T) {
	cases := map[string]string{
		"color:red; background:url(http://x.example/a.png); padding:4px": "color:red;; padding:4px",
		"background:url('https://cdn.example.com/a.png')":                "background:url('https://cdn.example.com/a.png')",
		"width:expression(alert(1))":                                     "",
		"width:EXPRESSION(alert(1))":                                     "",
		`width:\65 xpression(alert(1))`:                                  "",
		"x:exp/**/ression(alert(1))":                                     "",
		"behavior:url(x.htc)":                                            "",
		"-moz-binding:url(https://x.example/a.xml#x)":                    "",
		"@import 'https://x.example/a.css'; a{color:red}":                "; a{color:red}",
		"a{background:url(javascript:alert(1))}b{color:blue}":            "a{}b{color:blue}",
		"background:url(//evil.example/a.png)":                           "",
		"background:url(data:image/png;base64,AAAA)":                     ";base64,AAAA)",
		"background-image:image-set('http://x.example/a.png' 1x)":        "",
		"color:{{ brand.primary_color }};margin:0":                       "color:{{ brand.primary_color }};margin:0",
		"background:url({{img}})":                                        "",
		"a\x00b:c":                                                       "ab:c",
	}
	for in, want := range cases {
		if got := SanitizeCSS(in); got != want {
			t.Errorf("SanitizeCSS(%q) = %q, want %q", in, got, want)
		}
	}
}
