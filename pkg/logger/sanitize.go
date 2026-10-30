package logger

import (
	"strings"

	"go.uber.org/zap/zapcore"
)

var secretExactKeys = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"secret":        {},
	"token":         {},
	"api_key":       {},
	"apikey":        {},
	"access_key":    {},
	"private_key":   {},
	"authorization": {},
	"auth":          {},
	"credential":    {},
	"credentials":   {},
	"cookie":        {},
	"set-cookie":    {},
	"set_cookie":    {},
	// One-time codes and the data a message is rendered from (it carries
	// them): contract §6, OTP values are masked in logs.
	"otp":           {},
	"code":          {},
	"one_time_code": {},
	"template_data": {},
	"html_body":     {},
	"text_body":     {},
}

var secretKeySuffixes = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"private_key",
	"access_key",
	"authorization",
	"otp",
}

const redactedValue = "***"

// IsSecretFieldKey reports whether key should be redacted automatically.
func IsSecretFieldKey(key string) bool {
	k := normalizeFieldKey(key)
	if _, ok := secretExactKeys[k]; ok {
		return true
	}
	for _, suffix := range secretKeySuffixes {
		if k == suffix || strings.HasSuffix(k, "_"+suffix) || strings.HasSuffix(k, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizeFieldKey(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	return strings.ReplaceAll(k, "-", "_")
}

func sanitizeFields(fields []Field) []Field {
	if len(fields) == 0 {
		return fields
	}
	out := make([]Field, len(fields))
	for i, f := range fields {
		if f.Type == zapcore.SkipType {
			out[i] = f
			continue
		}
		if IsSecretFieldKey(f.Key) {
			out[i] = String(f.Key, redactedValue)
			continue
		}
		if f.Type == zapcore.StringType {
			if redacted, changed := redactSecretPatterns(f.String); changed {
				out[i] = String(f.Key, redacted)
				continue
			}
		}
		out[i] = f
	}
	return out
}

func redactSecretPatterns(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	lower := strings.ToLower(s)
	changed := false
	out := s
	for _, p := range []struct{ prefix, match string }{
		{"password=", "password="},
		{"token=", "token="},
		{"api_key=", "api_key="},
	} {
		if idx := strings.Index(lower, p.match); idx >= 0 {
			start := idx
			end := start + len(p.match)
			for end < len(out) && out[end] != ' ' && out[end] != '&' && out[end] != '"' && out[end] != '\'' {
				end++
			}
			out = out[:start] + p.prefix + redactedValue + out[end:]
			lower = strings.ToLower(out)
			changed = true
		}
	}
	const bearer = "bearer "
	if idx := strings.Index(lower, bearer); idx >= 0 {
		start := idx
		end := start + len(bearer)
		for end < len(out) && out[end] != ' ' && out[end] != '"' && out[end] != '\'' {
			end++
		}
		out = out[:start] + "Bearer " + redactedValue + out[end:]
		changed = true
	}
	return out, changed
}
