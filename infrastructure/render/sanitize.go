package render

import (
	"bytes"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	tpl "github.com/razatechofficial/mail-os/domain/template"
)

// The sanitiser is an allow-list over golang.org/x/net/html's parse, so it
// sees the markup the way a browser does (entities decoded, tags
// balanced). What survives is re-serialised from the tree, never copied
// from the input:
//   - layout elements email clients render are kept with layout attributes;
//   - active content (script, iframe, object, forms, svg, math, …) is
//     dropped with everything inside it;
//   - any other element is unwrapped: its content stays, the tag goes;
//   - comments go, including Outlook's conditional comments;
//   - event handlers, srcdoc and formaction go with every attribute not on
//     the list;
//   - URL attributes keep only https:, mailto:, cid:, #fragment or a lone
//     {{placeholder}};
//   - CSS in style attributes and <style> loses expression(), javascript:,
//     behavior, -moz-binding, @import and non-https url(…).
//
// Placeholders are plain text to the parser, so they survive anywhere text
// or an allowed attribute value may hold them.

// keptElements are kept, with their allowed attributes.
var keptElements = map[string]bool{
	"html": true, "head": true, "meta": true, "title": true, "style": true, "body": true,
	"table": true, "thead": true, "tbody": true, "tfoot": true, "tr": true, "td": true, "th": true,
	"caption": true, "colgroup": true, "col": true,
	"div": true, "span": true, "p": true, "a": true, "img": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"ul": true, "ol": true, "li": true, "br": true, "hr": true,
	"strong": true, "b": true, "em": true, "i": true, "u": true, "s": true, "strike": true,
	"center": true, "font": true, "blockquote": true, "pre": true, "code": true,
	"sup": true, "sub": true, "small": true,
}

// droppedElements go with their content: they run code, load documents,
// take input, or hide markup a later parse could read differently.
var droppedElements = map[string]bool{
	"script": true, "iframe": true, "frame": true, "frameset": true, "object": true, "embed": true,
	"applet": true, "param": true, "form": true, "input": true, "button": true, "textarea": true,
	"select": true, "option": true, "optgroup": true, "datalist": true, "keygen": true,
	"base": true, "link": true, "svg": true, "math": true,
	"noscript": true, "noembed": true, "noframes": true, "template": true, "xmp": true, "plaintext": true,
	"audio": true, "video": true, "source": true, "track": true, "canvas": true, "portal": true,
	"dialog": true, "slot": true,
}

// globalAttrs are allowed on every kept element.
var globalAttrs = map[string]bool{
	"style": true, "class": true, "id": true, "dir": true, "lang": true, "title": true,
	"align": true, "valign": true, "width": true, "height": true, "bgcolor": true, "border": true,
	"role": true,
}

// elementAttrs are allowed on one element.
var elementAttrs = map[string]map[string]bool{
	"html":  {"xmlns": true},
	"meta":  {"charset": true, "name": true, "content": true},
	"style": {"type": true, "media": true},
	"body":  {"background": true},
	"table": {"cellpadding": true, "cellspacing": true, "background": true, "summary": true},
	"tr":    {"background": true},
	"td":    {"colspan": true, "rowspan": true, "nowrap": true, "background": true, "scope": true, "headers": true},
	"th":    {"colspan": true, "rowspan": true, "nowrap": true, "background": true, "scope": true, "headers": true},
	"col":   {"span": true},
	"a":     {"href": true, "target": true, "rel": true, "name": true},
	"img":   {"src": true, "alt": true},
	"font":  {"color": true, "face": true, "size": true},
	"ol":    {"start": true, "type": true},
	"ul":    {"type": true},
	"li":    {"type": true, "value": true},
}

// urlAttrs hold a URL a client may follow or load.
var urlAttrs = map[string]bool{"href": true, "src": true, "background": true, "action": true}

// documentRE recognises a whole document rather than a fragment, such as a
// raw HTML block.
var documentRE = regexp.MustCompile(`(?i)<!doctype|<html[\s>/]|<head[\s>/]|<body[\s>/]`)

// SanitizeHTML makes HTML email-safe: the console's compiled body before it
// is stored, a raw HTML block, and every body before it is rendered. A
// whole document stays a document; anything else is sanitised as a body
// fragment.
func SanitizeHTML(src string) (string, error) {
	src = strings.ReplaceAll(src, "\x00", "")
	var buf bytes.Buffer
	if documentRE.MatchString(src) {
		doc, err := html.Parse(strings.NewReader(src))
		if err != nil {
			return "", err
		}
		cleanChildren(doc)
		if err := html.Render(&buf, doc); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	body := &html.Node{Type: html.ElementNode, Data: "body", DataAtom: atom.Body}
	nodes, err := html.ParseFragment(strings.NewReader(src), body)
	if err != nil {
		return "", err
	}
	for _, n := range nodes {
		body.AppendChild(n)
	}
	cleanChildren(body)
	for n := body.FirstChild; n != nil; n = n.NextSibling {
		if err := html.Render(&buf, n); err != nil {
			return "", err
		}
	}
	return buf.String(), nil
}

// cleanChildren sanitises n's children in place.
func cleanChildren(n *html.Node) {
	for c := n.FirstChild; c != nil; {
		next := c.NextSibling
		switch c.Type {
		case html.TextNode:
		case html.DoctypeNode:
			// Re-emitted as a plain <!DOCTYPE html>; identifiers carry
			// nothing an email needs.
			c.Data, c.Attr = "html", nil
		case html.ElementNode:
			cleanElement(n, c)
		default: // comments, raw and error nodes
			n.RemoveChild(c)
		}
		c = next
	}
}

func cleanElement(parent, n *html.Node) {
	name := n.Data
	switch {
	case n.Namespace != "" || droppedElements[name]:
		parent.RemoveChild(n)
		return
	case !keptElements[name]:
		cleanChildren(n)
		for c := n.FirstChild; c != nil; {
			next := c.NextSibling
			n.RemoveChild(c)
			parent.InsertBefore(c, n)
			c = next
		}
		parent.RemoveChild(n)
		return
	}
	n.Attr = cleanAttrs(name, n.Attr)
	switch name {
	case "meta":
		if !keepMeta(n) {
			parent.RemoveChild(n)
		}
	case "style":
		var css strings.Builder
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.TextNode {
				css.WriteString(c.Data)
			}
		}
		for n.FirstChild != nil {
			n.RemoveChild(n.FirstChild)
		}
		// < cannot be written into a <style> as it is: </style> would end
		// it. \3c is the same character to CSS.
		clean := strings.ReplaceAll(SanitizeCSS(css.String()), "<", `\3c `)
		n.AppendChild(&html.Node{Type: html.TextNode, Data: clean})
	default:
		cleanChildren(n)
	}
}

// keepMeta keeps <meta charset> and <meta name content>; http-equiv (a
// refresh, a cookie, a content policy) is never kept.
func keepMeta(n *html.Node) bool {
	var charset, name, content bool
	for _, a := range n.Attr {
		switch a.Key {
		case "charset":
			charset = true
		case "name":
			name = true
		case "content":
			content = true
		}
	}
	return charset || (name && content)
}

func cleanAttrs(element string, attrs []html.Attribute) []html.Attribute {
	out := attrs[:0]
	for _, a := range attrs {
		key := a.Key
		if a.Namespace != "" || !(globalAttrs[key] || elementAttrs[element][key] || strings.HasPrefix(key, "aria-")) {
			continue
		}
		switch {
		case urlAttrs[key]:
			v, ok := cleanURL(a.Val)
			if !ok {
				continue
			}
			a.Val = v
		case key == "style":
			a.Val = strings.TrimSpace(SanitizeCSS(a.Val))
			if a.Val == "" {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// cleanURL keeps an https:, mailto: or cid: URL, a #fragment, or a lone
// placeholder that the event fills (the renderer then escapes it as a
// URL). Browsers ignore tabs, newlines and other control characters inside
// a scheme ("java\tscript:"), so the scheme is read without them.
func cleanURL(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if _, ok := tpl.SinglePlaceholder(v); ok {
		return v, true
	}
	bare := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	if bare != v {
		return "", false
	}
	if strings.HasPrefix(v, "#") {
		return v, true
	}
	lower := strings.ToLower(v)
	for _, scheme := range []string{"https:", "mailto:", "cid:"} {
		if strings.HasPrefix(lower, scheme) && len(v) > len(scheme) {
			return v, true
		}
	}
	return "", false
}
