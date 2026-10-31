package render

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	tpl "github.com/razatechofficial/mail-os/domain/template"
)

// CSS is filtered rather than parsed: comments are removed, the text is cut
// at ; { and }, and every piece that, once CSS escapes are decoded and
// spaces removed, could run script or load a resource is blanked. Pieces
// are declarations, selectors and at-rule preludes, so a refused
// declaration leaves the rest of its rule.

// cssForbidden are the constructs refused anywhere in a piece.
var cssForbidden = []string{
	"expression(", // IE CSS expressions
	"javascript:",
	"vbscript:",
	"behavior", // IE HTC behaviours
	"-moz-binding",
	"@import",
	"image-set(", // loads images without url()
	"src(",
}

var (
	cssCommentRE = regexp.MustCompile(`(?s)/\*.*?(?:\*/|$)`)
	cssEscapeRE  = regexp.MustCompile(`\\(?:([0-9a-fA-F]{1,6})[ \t\r\n\f]?|\r\n|\n|(.))`)
	maskRE       = regexp.MustCompile("([0-9]+)")
)

// Placeholders are masked while CSS is cut, so their braces are not taken
// for a rule's. These private-use runes are removed from the input first.
const (
	maskOpen  = ""
	maskClose = ""
)

// SanitizeCSS filters a style attribute or the text of a <style> element.
func SanitizeCSS(css string) string {
	css = strings.NewReplacer("\x00", "", maskOpen, "", maskClose, "").Replace(css)

	// Comments become a space: removing them outright could join "</sty"
	// and "le>", or two harmless halves of a keyword.
	css = cssCommentRE.ReplaceAllString(css, " ")

	var held []string
	css = maskPlaceholders(css, &held)

	var out strings.Builder
	out.Grow(len(css))
	start := 0
	for i := 0; i < len(css); i++ {
		switch css[i] {
		case ';', '{', '}':
			out.WriteString(cleanPiece(css[start:i]))
			out.WriteByte(css[i])
			start = i + 1
		}
	}
	out.WriteString(cleanPiece(css[start:]))

	return maskRE.ReplaceAllStringFunc(out.String(), func(m string) string {
		i, err := strconv.Atoi(maskRE.FindStringSubmatch(m)[1])
		if err != nil || i >= len(held) {
			return ""
		}
		return held[i]
	})
}

func maskPlaceholders(css string, held *[]string) string {
	ps := tpl.Placeholders(css)
	if len(ps) == 0 {
		return css
	}
	var b strings.Builder
	last := 0
	for _, p := range ps {
		b.WriteString(css[last:p.Start])
		b.WriteString(maskOpen + strconv.Itoa(len(*held)) + maskClose)
		*held = append(*held, css[p.Start:p.End])
		last = p.End
	}
	b.WriteString(css[last:])
	return b.String()
}

// cleanPiece returns the piece, or "" when it is dangerous.
func cleanPiece(piece string) string {
	if dangerousCSS(piece) {
		return ""
	}
	return piece
}

func dangerousCSS(piece string) bool {
	norm := normalizeCSS(piece)
	for _, f := range cssForbidden {
		if strings.Contains(norm, f) {
			return true
		}
	}
	for rest := norm; ; {
		i := strings.Index(rest, "url(")
		if i < 0 {
			return false
		}
		rest = rest[i+len("url("):]
		arg := rest
		if j := strings.IndexByte(arg, ')'); j >= 0 {
			arg = arg[:j]
		}
		arg = strings.Trim(arg, `"'`)
		if !strings.HasPrefix(arg, "https://") {
			return true
		}
	}
}

// normalizeCSS decodes CSS escapes (\65 xpression is expression), lowers
// case, and drops whitespace and control characters, which CSS ignores in
// the places an attacker would put them.
func normalizeCSS(s string) string {
	s = cssEscapeRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := cssEscapeRE.FindStringSubmatch(m)
		switch {
		case sub[1] != "":
			n, err := strconv.ParseUint(sub[1], 16, 32)
			if err != nil || n == 0 || n > unicode.MaxRune {
				return "�"
			}
			return string(rune(n))
		case sub[2] != "":
			return sub[2]
		}
		return "" // an escaped newline continues the line
	})
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}
