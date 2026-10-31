// Package render turns a template's content and an event's data into the
// message sent (docs/mailos-template-api.md, "Rendering rules"):
//   - {{key}} is replaced by the value at that dotted path of the data, and
//     a missing key by "";
//   - in HTML, values are escaped by context (text, attribute, URL, CSS)
//     exactly as html/template does, and a javascript: URL is neutralised;
//   - plain text is rendered from text_body and not escaped;
//   - the subject is rendered as text with CR and LF stripped;
//   - any {{ that is not a valid placeholder is literal and never executed.
//
// The HTML is sanitised first (SanitizeHTML). Each valid placeholder then
// becomes an html/template action calling a lookup function, under
// delimiters made fresh for every render, so no text in a template can
// open an action of its own.
package render

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	htmltemplate "html/template"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	tpl "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Masked is what a masked variable renders as.
const Masked = "••••••"

// Content is a message's subject and bodies: a template's before
// rendering, the message's after.
type Content struct {
	Subject string
	HTML    string
	Text    string
}

// Options change how values render.
type Options struct {
	// Mask lists keys rendered as Masked instead of their value: the
	// topic's secret variables (tpl.SecretKeys) when a message is shown in
	// the console, so one-time codes never are (contract §6).
	Mask []string
}

// Render renders content with data. Only an HTML body that cannot be
// rendered as it stands, such as a placeholder in a place html/template
// cannot escape, is an error: a 422 on html_body.
func Render(c Content, data map[string]any, opts Options) (Content, error) {
	value := func(key string) string {
		if slices.Contains(opts.Mask, key) {
			return Masked
		}
		v, ok := tpl.Lookup(data, key)
		if !ok {
			return ""
		}
		return format(v)
	}
	out := Content{
		Subject: strings.NewReplacer("\r", "", "\n", "").Replace(tpl.ReplacePlaceholders(c.Subject, value)),
		Text:    tpl.ReplacePlaceholders(c.Text, value),
	}
	if strings.TrimSpace(c.HTML) == "" {
		return out, nil
	}
	h, err := renderHTML(c.HTML, value)
	if err != nil {
		e := apperrors.Invalid("html_body", tpl.CodeInvalid, "the HTML body cannot be rendered: "+err.Error())
		e.Err = err
		return Content{}, e
	}
	out.HTML = h
	return out, nil
}

func renderHTML(src string, value func(string) string) (string, error) {
	clean, err := SanitizeHTML(src)
	if err != nil {
		return "", err
	}
	left, right, err := delimiters(clean)
	if err != nil {
		return "", err
	}
	text := tpl.ReplacePlaceholders(clean, func(key string) string {
		// key matches the placeholder grammar, so quoting it is exact.
		return left + " value " + strconv.Quote(key) + " " + right
	})
	t, err := htmltemplate.New("email").Delims(left, right).
		Funcs(htmltemplate.FuncMap{"value": value}).
		Parse(text)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, nil); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// delimiters returns action delimiters that occur nowhere in src: each
// render's are random, so a template cannot contain them.
func delimiters(src string) (left, right string, err error) {
	for {
		var b [12]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", "", err
		}
		nonce := hex.EncodeToString(b[:])
		left, right = "[["+nonce, nonce+"]]"
		if !strings.Contains(src, left) && !strings.Contains(src, right) {
			return left, right, nil
		}
	}
}

// format writes a data value as text. Values are written by their kind,
// never their Go type, so a caller's template.HTML or template.URL is
// escaped like any other string. Objects and lists render as "".
func format(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case json.Number:
		return x.String()
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return rv.String()
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(rv.Float(), 'f', -1, 64)
	}
	return ""
}
