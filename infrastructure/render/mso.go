package render

import (
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Outlook for Windows lays email out with Word, which ignores max-width
// and inline-block. Email builders give it fixed-width "ghost tables"
// inside conditional comments that only Outlook reads:
//
//	<!--[if mso]><table role="presentation" width="600"><tr><td><![endif]-->
//
// A comment is opaque to the sanitiser's parse, so only comments of that
// exact kind are kept: the condition is "mso" or "gte mso N", and the
// markup inside is nothing but table, tr and td tags with layout
// attributes and non-breaking spaces. The kept comment is rebuilt from
// its tokens, never copied.

var msoCommentRE = regexp.MustCompile(`(?s)^\[if (mso|gte mso [0-9]{1,2})\]>(.*)<!\[endif\]$`)

// msoAttrs are the attributes a ghost table's tags may carry.
var msoAttrs = map[string]map[string]bool{
	"table": {"role": true, "width": true, "align": true, "cellpadding": true, "cellspacing": true, "border": true, "dir": true, "style": true},
	"tr":    {"style": true},
	"td":    {"width": true, "valign": true, "align": true, "dir": true, "style": true},
}

// msoValueRE is what an attribute value inside a ghost table may be: no
// quotes, ampersands or angle brackets, which keeps the rebuilt comment free
// of anything a comment escape would change.
var msoValueRE = regexp.MustCompile(`^[A-Za-z0-9 #%.,:;()_'-]{0,200}$`)

// MSOComment returns the comment's data rebuilt when it is an Outlook
// ghost-table comment, and false for any other comment.
func MSOComment(data string) (string, bool) {
	m := msoCommentRE.FindStringSubmatch(data)
	if m == nil {
		return "", false
	}
	var b strings.Builder
	z := html.NewTokenizer(strings.NewReader(m[2]))
	for {
		switch z.Next() {
		case html.ErrorToken:
			if z.Err() != io.EOF {
				return "", false
			}
			out := b.String()
			if strings.Contains(out, "--") {
				return "", false
			}
			return "[if " + m[1] + "]>" + out + "<![endif]", true
		case html.TextToken:
			text := string(z.Text())
			if strings.TrimSpace(strings.ReplaceAll(text, " ", "")) != "" {
				return "", false
			}
			if strings.Contains(text, " ") {
				b.WriteString(" ")
			}
		case html.StartTagToken:
			name, attrs, ok := msoTag(z)
			if !ok {
				return "", false
			}
			b.WriteString("<" + name + attrs + ">")
		case html.EndTagToken:
			name, _ := z.TagName()
			if msoAttrs[string(name)] == nil {
				return "", false
			}
			b.WriteString("</" + string(name) + ">")
		default:
			return "", false
		}
	}
}

// msoTag reads a ghost table start tag and writes its attributes back.
func msoTag(z *html.Tokenizer) (name, attrs string, ok bool) {
	raw, more := z.TagName()
	name = string(raw)
	allowed := msoAttrs[name]
	if allowed == nil {
		return "", "", false
	}
	var b strings.Builder
	for more {
		var k, v []byte
		k, v, more = z.TagAttr()
		key, val := string(k), string(v)
		if !allowed[key] {
			return "", "", false
		}
		if key == "style" {
			val = strings.TrimSpace(SanitizeCSS(val))
		}
		if !msoValueRE.MatchString(val) {
			return "", "", false
		}
		b.WriteString(" " + key + `="` + val + `"`)
	}
	return name, b.String(), true
}
