package template

import (
	"regexp"
	"slices"
	"strings"
)

// Placeholders are mustache style: {{user.name}}, with optional spaces
// inside the braces ({{ user.name }}). A key is lower-case dotted segments,
// each starting with a letter. Anything else between braces, such as
// {{ .Name }} or {{define "x"}}, is not a placeholder: it renders as the
// literal text it is and is never executed.
const keyPattern = `[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*`

// MaxKeyLength is the longest variable key a draft may declare.
const MaxKeyLength = 128

var (
	keyRE             = regexp.MustCompile(`^` + keyPattern + `$`)
	placeholderRE     = regexp.MustCompile(`\{\{ *(` + keyPattern + `) *\}\}`)
	lonePlaceholderRE = regexp.MustCompile(`^\{\{ *(` + keyPattern + `) *\}\}$`)
)

// ValidKey reports whether s is a variable key: ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$
// and at most MaxKeyLength bytes.
func ValidKey(s string) bool {
	return len(s) <= MaxKeyLength && keyRE.MatchString(s)
}

// Placeholder is one {{key}} in a text: its byte span [Start, End) and key.
type Placeholder struct {
	Start, End int
	Key        string
}

// Placeholders finds the placeholders in s, in order.
func Placeholders(s string) []Placeholder {
	idx := placeholderRE.FindAllStringSubmatchIndex(s, -1)
	if len(idx) == 0 {
		return nil
	}
	out := make([]Placeholder, len(idx))
	for i, m := range idx {
		out[i] = Placeholder{Start: m[0], End: m[1], Key: s[m[2]:m[3]]}
	}
	return out
}

// ReplacePlaceholders returns s with each placeholder replaced by
// value(key). Text that is not a placeholder is copied as it is.
func ReplacePlaceholders(s string, value func(key string) string) string {
	ps := Placeholders(s)
	if len(ps) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, p := range ps {
		b.WriteString(s[last:p.Start])
		b.WriteString(value(p.Key))
		last = p.End
	}
	b.WriteString(s[last:])
	return b.String()
}

// SinglePlaceholder reports whether s, trimmed of surrounding spaces, is one
// placeholder and nothing else, such as a button's href of {{link}}.
func SinglePlaceholder(s string) (key string, ok bool) {
	m := lonePlaceholderRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ExtractVariables lists the keys of every placeholder in a template's
// subject, HTML and plain-text bodies, sorted and without duplicates.
func ExtractVariables(subject, html, text string) []string {
	var keys []string
	for _, s := range []string{subject, html, text} {
		for _, p := range Placeholders(s) {
			keys = append(keys, p.Key)
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

// Lookup finds the value at a dotted key in event data: {"user":{"name":…}}
// for user.name, walking nested objects. A flat {"user.name": …} entry is
// used when there is no nested one. ok is false when the key is missing.
func Lookup(data map[string]any, key string) (any, bool) {
	if data == nil {
		return nil, false
	}
	if v, ok := walk(data, key); ok {
		return v, true
	}
	v, ok := data[key]
	return v, ok
}

func walk(data map[string]any, key string) (any, bool) {
	var cur any = data
	for seg := range strings.SplitSeq(key, ".") {
		switch m := cur.(type) {
		case map[string]any:
			v, ok := m[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case map[string]string:
			v, ok := m[seg]
			if !ok {
				return nil, false
			}
			cur = v
		default:
			return nil, false
		}
	}
	return cur, true
}
