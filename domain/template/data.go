package template

import (
	"encoding/json"
	"net/mail"
	"net/url"
	"reflect"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// ValidateData checks an event's data against its topic before a message
// is rendered: every required variable is present and not empty, and every
// declared variable that is present has a value of its kind. Keys the
// topic does not declare are ignored; events carry more than templates use.
// Field paths are "data.<key>". An unknown topic is one "topic" error.
//
// Errors never quote the value: it may be a one-time code.
func ValidateData(topic string, data map[string]any) []apperrors.FieldError {
	t, ok := TopicByKey(topic)
	if !ok {
		return []apperrors.FieldError{{Field: "topic", Code: CodeUnknownTopic, Message: "topic is not in the topic catalogue"}}
	}
	var errs []apperrors.FieldError
	for _, v := range t.Variables {
		field := "data." + v.Key
		val, present := Lookup(data, v.Key)
		if !present || empty(val) {
			if v.Required {
				errs = append(errs, required(field))
			}
			continue
		}
		if code, msg := checkKind(v.Kind, val); code != "" {
			errs = append(errs, apperrors.FieldError{Field: field, Code: code, Message: field + " " + msg})
		}
	}
	return errs
}

func empty(v any) bool {
	if v == nil {
		return true
	}
	s, ok := asString(v)
	return ok && strings.TrimSpace(s) == ""
}

// checkKind returns a field code and message when v is not a kind value.
func checkKind(kind Kind, v any) (code, msg string) {
	if kind == KindNumber {
		if !isNumber(v) {
			return CodeInvalidNumber, "must be a number"
		}
		return "", ""
	}
	s, ok := asString(v)
	if !ok {
		return CodeInvalidType, "must be a string"
	}
	switch kind {
	case KindURL:
		if !webURL(s) {
			return CodeInvalidURL, "must be an http or https URL"
		}
	case KindEmail:
		if a, err := mail.ParseAddress(s); err != nil || a.Address != s {
			return CodeInvalidEmail, "must be an email address"
		}
	case KindDatetime:
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return CodeInvalidDatetime, "must be an RFC 3339 date and time"
		}
	}
	return "", ""
}

// webURL reports an absolute http(s) URL with a host. Event links are
// IAM's own pages; http is allowed for local development, where IAM runs
// without TLS.
func webURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

// asString reads any string-kinded value, including named string types.
func asString(v any) (string, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.String {
		return "", false
	}
	return rv.String(), true
}

func isNumber(v any) bool {
	if n, ok := v.(json.Number); ok {
		_, err := n.Float64()
		return err == nil
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}
