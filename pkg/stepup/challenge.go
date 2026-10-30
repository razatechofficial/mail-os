// Package stepup builds and reads RFC 9470 step-up authentication
// challenges: a resource server tells the client the access token's sign-in
// is too weak or too old, and which acr_values or max_age a new
// authorization request must ask for. It has no IAM dependencies, so a Go
// resource server can use it as it is. Copied from the IAM module unchanged.
package stepup

import (
	"strconv"
	"strings"
	"time"
)

// Error is the RFC 9470 §3 error code.
const Error = "insufficient_user_authentication"

// Challenge says what a new authorization must achieve: one of ACRValues
// (any satisfies) and a sign-in no older than MaxAge. Zero values are
// left out.
type Challenge struct {
	ACRValues   []string
	MaxAge      time.Duration
	Description string
}

// HasMaxAge reports whether the challenge limits the sign-in's age.
func (c Challenge) HasMaxAge() bool { return c.MaxAge > 0 }

// MaxAgeSeconds is max_age in whole seconds, rounded down.
func (c Challenge) MaxAgeSeconds() int64 { return int64(c.MaxAge / time.Second) }

// Header renders the WWW-Authenticate value for scheme (Bearer, or DPoP
// for a DPoP-bound token), RFC 9470 §3:
//
//	Bearer error="insufficient_user_authentication",
//	  error_description="...", acr_values="urn:iam:acr:mfa", max_age="300"
func (c Challenge) Header(scheme string) string {
	if scheme == "" {
		scheme = "Bearer"
	}
	parts := []string{`error="` + Error + `"`}
	if c.Description != "" {
		parts = append(parts, `error_description="`+quote(c.Description)+`"`)
	}
	if len(c.ACRValues) > 0 {
		parts = append(parts, `acr_values="`+quote(strings.Join(c.ACRValues, " "))+`"`)
	}
	if c.HasMaxAge() {
		parts = append(parts, `max_age="`+strconv.FormatInt(c.MaxAgeSeconds(), 10)+`"`)
	}
	return scheme + " " + strings.Join(parts, ", ")
}

// quote escapes a quoted-string value (RFC 9110 §5.6.4), dropping
// control characters.
func quote(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Parse reads a WWW-Authenticate value. ok is true only for an RFC 9470
// challenge (error="insufficient_user_authentication").
func Parse(header string) (scheme string, c Challenge, ok bool) {
	header = strings.TrimSpace(header)
	scheme, rest, _ := strings.Cut(header, " ")
	params := parseParams(rest)
	if params["error"] != Error {
		return scheme, Challenge{}, false
	}
	c.Description = params["error_description"]
	c.ACRValues = strings.Fields(params["acr_values"])
	if v, err := strconv.ParseInt(params["max_age"], 10, 64); err == nil && v >= 0 {
		c.MaxAge = time.Duration(v) * time.Second
	}
	return scheme, c, true
}

// parseParams reads comma-separated auth-params with token or
// quoted-string values.
func parseParams(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ,")
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			break
		}
		name := strings.ToLower(strings.TrimSpace(s[:eq]))
		s = strings.TrimLeft(s[eq+1:], " ")
		var val strings.Builder
		if strings.HasPrefix(s, `"`) {
			i := 1
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				val.WriteByte(s[i])
			}
			s = s[min(i+1, len(s)):]
		} else {
			end := strings.IndexByte(s, ',')
			if end < 0 {
				end = len(s)
			}
			val.WriteString(strings.TrimSpace(s[:end]))
			s = s[end:]
		}
		out[name] = val.String()
	}
	return out
}

// Fresh reports whether a sign-in at authTime is within maxAge at now. A
// token without auth_time is never fresh enough for a max_age.
func Fresh(authTime, now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return true
	}
	return !authTime.IsZero() && now.Sub(authTime) <= maxAge
}
