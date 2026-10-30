package logger

import (
	"net/url"
	"strings"
)

// MaskEmail redacts an email for logs: ra***@company.com
func MaskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 1 {
		return redactedValue
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return "**" + domain
	}
	return local[:2] + redactedValue + domain
}

// MaskPhone redacts a phone number for logs: +1***4567
func MaskPhone(phone string) string {
	phone = strings.TrimSpace(phone)
	if len(phone) <= 4 {
		return redactedValue
	}
	return phone[:2] + redactedValue + phone[len(phone)-4:]
}

// Redact replaces non-empty values with a fixed mask.
func Redact(s string) string {
	if s == "" {
		return ""
	}
	return redactedValue
}

// RedactURL returns a URL safe for logs with userinfo credentials masked.
// On parse failure, returns a fully redacted marker so secrets never leak.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return redactedValue
	}
	if u.User == nil {
		return u.String()
	}
	if _, hasPass := u.User.Password(); hasPass {
		u.User = url.UserPassword(Redact(u.User.Username()), redactedValue)
	} else if u.User.Username() != "" {
		u.User = url.User(Redact(u.User.Username()))
	}
	return u.String()
}

// HasSecret reports whether s is non-empty (use with *_configured bool fields).
func HasSecret(s string) bool {
	return strings.TrimSpace(s) != ""
}

// RedactedURL returns a zap field with credentials stripped from a URL.
func RedactedURL(key, raw string) Field {
	return String(key, RedactURL(raw))
}
