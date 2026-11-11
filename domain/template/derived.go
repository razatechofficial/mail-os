package template

import (
	"encoding/json"
	"maps"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Derived variables are worded by MailOS from the event's other data. The
// template language has no conditionals, so wording that depends on a
// value (each kind of security notice, an approval without a workspace
// name, an optional justification) is a derived variable the template
// prints as it is. A derived value replaces whatever the event carries
// under its key, and events are never checked for one.

// deriveFunc words a derived variable from the event data.
type deriveFunc func(data map[string]any) string

// derived declares a derived variable. Its sample is worded from the
// topic's other samples (SampleData).
func derived(key, label string, fn deriveFunc) Variable {
	return Variable{Key: key, Label: label, Kind: KindText, Derived: true, derive: fn}
}

// WithDerived returns data with the topic's derived variables set. data
// itself is not changed; a topic without derived variables gets it back.
func WithDerived(topic string, data map[string]any) map[string]any {
	var out map[string]any
	for _, v := range variablesOf(topic) {
		if v.derive == nil {
			continue
		}
		if out == nil {
			out = maps.Clone(data)
			if out == nil {
				out = map[string]any{}
			}
		}
		out[v.Key] = v.derive(data)
	}
	if out == nil {
		return data
	}
	return out
}

// text is the trimmed string at key, or "" when it is absent or not text.
// Numbers are written as decoded JSON writes them: 7, not 7.000000.
func text(data map[string]any, key string) string {
	v, ok := Lookup(data, key)
	if !ok || v == nil {
		return ""
	}
	if s, ok := asString(v); ok {
		return strings.TrimSpace(s)
	}
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(rv.Float(), 'f', -1, 64)
	}
	return ""
}

// or returns the value at key, else fallback.
func or(key, fallback string) deriveFunc {
	return func(data map[string]any) string {
		if s := text(data, key); s != "" {
			return s
		}
		return fallback
	}
}

// when writes an RFC 3339 time for people: "10 Nov 2026 09:30 UTC". Text
// that is not a time is returned as it is.
func when(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format("2 Jan 2006 15:04 UTC")
	}
	return s
}

// noticeText words each security notice kind IAM sends
// (iam/server/pkg/events.NoticeKinds).
var noticeText = map[string]string{
	"factor_added":                 "A sign-in method was added",
	"factor_removed":               "A sign-in method was removed",
	"password_changed":             "Your password was changed",
	"account_locked":               "Your account was locked after failed sign-in attempts",
	"new_device_sign_in":           "Your account was signed in to from a new device",
	"authenticator_invitation":     "You are invited to set up the IAM Authenticator",
	"push_fraud_reported":          "You reported a sign-in request as not yours",
	"mfa_reset":                    "Your multi-factor authentication was reset",
	"temporary_access_pass_issued": "A temporary access pass was issued for your account",
}

// credentialText words the CAEP credential types IAM names.
var credentialText = map[string]string{
	"app":            "authenticator app",
	"phone-sms":      "text message",
	"fido2-platform": "passkey or security key",
	"email":          "email code",
	"hardware-otp":   "hardware token",
	"password":       "password",
}

func noticeKind(data map[string]any) string {
	if s, ok := noticeText[text(data, "kind")]; ok {
		return s
	}
	return "A security change was made to your account"
}

// noticeDetail lists what IAM recorded about the change.
func noticeDetail(data map[string]any) string {
	var parts []string
	if c := text(data, "credential"); c != "" {
		if w, ok := credentialText[c]; ok {
			c = w
		}
		parts = append(parts, "Method: "+c+".")
	}
	if at := text(data, "occurred_at"); at != "" {
		parts = append(parts, "When: "+when(at)+".")
	}
	if ip := text(data, "ip"); ip != "" {
		parts = append(parts, "IP address: "+ip+".")
	}
	if ua := text(data, "user_agent"); ua != "" {
		parts = append(parts, "Device: "+ua+".")
	}
	return strings.Join(parts, " ")
}

// noticeAdvice is what the person should do about the notice.
func noticeAdvice(data map[string]any) string {
	switch text(data, "kind") {
	case "authenticator_invitation":
		if link := text(data, "link"); link != "" {
			return "Set it up here: " + link
		}
		return "Open the account security page to set it up."
	case "push_fraud_reported":
		return "The sign-in was refused. If you did not try to sign in, change your password and tell your administrator now."
	case "temporary_access_pass_issued", "mfa_reset":
		return "If you did not ask your administrator for this, contact them immediately."
	}
	return "If this was not you, contact your administrator immediately."
}

// approvalScope names where an approval applies; IAM sends no scope name
// for a platform approval, whose tenant_id is "platform".
func approvalScope(data map[string]any) string {
	if s := text(data, "scope_name"); s != "" {
		return s
	}
	if text(data, "tenant_id") == "platform" {
		return "the platform"
	}
	return "your workspace"
}

// accessText is "access to T24 Transact", with the role when one was asked.
func accessText(data map[string]any) string {
	s := "access to " + text(data, "application_name")
	if text(data, "role_key") != "" {
		if role := text(data, "role_name"); role != "" {
			s += " with the role " + role
		} else {
			s += " with the role " + text(data, "role_key")
		}
	}
	return s
}

func accessDuration(data map[string]any) string {
	if d := text(data, "duration_days"); d != "" && d != "0" {
		if d == "1" {
			return "for 1 day"
		}
		return "for " + d + " days"
	}
	return "with no end date"
}

func accessOutcome(data map[string]any) string {
	if text(data, "decision") == "denied" {
		return "You can ask again if you still need it."
	}
	if end := text(data, "access_expires_at"); end != "" {
		return "You can sign in now. The access ends " + when(end) + "."
	}
	return "You can sign in now."
}

func privilegedRole(data map[string]any) string {
	if r := text(data, "role_name"); r != "" {
		return "the role " + r
	}
	return "a privileged role"
}

// statusText says what the workspace's new status means for its people.
func statusText(data map[string]any) string {
	switch text(data, "action") {
	case "suspended":
		return "Until it is reactivated, nobody in it can sign in and its applications receive no tokens."
	case "reactivated":
		return "People in it can sign in again, and its applications receive tokens again."
	case "cancelled":
		if p := text(data, "purge_after"); p != "" {
			return "Nobody in it can sign in again. Its data is kept until " + when(p) + ", then deleted."
		}
		return "Nobody in it can sign in again. Its data is deleted after the retention period."
	}
	return "Contact your platform provider to find out what changed."
}
