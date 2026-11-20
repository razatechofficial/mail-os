package message

import (
	"fmt"
	"html"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	tpl "github.com/razatechofficial/mail-os/domain/template"
)

// RedactedMark starts every redaction descriptor. A value holding it was
// already redacted, so redacting stored mail again changes nothing.
const RedactedMark = "[redacted"

// Redacted replaces a live secret found by value in free text: a log line,
// a provider's error, a body redacted after the fact.
const Redacted = "[redacted]"

// Secrets are an authentication-class message's live secret values, by
// variable key (dotted path for nested values). They exist only in memory
// and, sealed, in the short-lived retry store (ADR 0001 §3.6); messages
// hold descriptors in their place.
type Secrets map[string]string

// AuthClass reports whether the message's topic is authentication-class:
// it is stored redacted, never resent and sent without tracking.
func (m *Message) AuthClass() bool { return tpl.AuthClass(m.Topic) }

// Descriptor is what a secret variable's value is stored and shown as: a
// code becomes "[redacted: code, 6 characters]"; a secret_url keeps its
// scheme, host and declared static path prefix only
// ("https://iam.example.com/reset-password/[redacted]"), as a token may sit
// anywhere after it, in the path, the query or the fragment.
func Descriptor(v tpl.Variable, value string) string {
	if v.Kind == tpl.KindSecretURL {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Sprintf("[redacted: %s]", v.Key)
		}
		out := u.Scheme + "://" + u.Host
		if strings.HasPrefix(u.Path, v.RedactPrefix) {
			out += v.RedactPrefix
		}
		if !strings.HasSuffix(out, "/") {
			out += "/"
		}
		return out + Redacted
	}
	return fmt.Sprintf("[redacted: %s, %d characters]", v.Key, utf8.RuneCountInString(value))
}

// SplitSecrets returns a copy of data with each of topic's secret values
// replaced by its descriptor, and the live values taken out. A value that
// is already a descriptor stays as it is and is not a live value.
func SplitSecrets(topic string, data map[string]any) (map[string]any, Secrets) {
	vars := tpl.Secrets(topic)
	if data == nil || len(vars) == 0 {
		return data, nil
	}
	out := deepCopy(data).(map[string]any)
	live := Secrets{}
	for _, v := range vars {
		raw, ok := lookup(out, v.Key)
		if !ok || raw == nil {
			continue
		}
		s := fmt.Sprint(raw)
		if s == "" || strings.Contains(s, RedactedMark) {
			continue
		}
		live[v.Key] = s
		setPath(out, v.Key, Descriptor(v, s))
	}
	if len(live) == 0 {
		return out, nil
	}
	return out, live
}

// Merge returns a copy of data with the live values put back: the data of
// the render the relay gets, never stored.
func (s Secrets) Merge(data map[string]any) map[string]any {
	if len(s) == 0 {
		return data
	}
	out := map[string]any{}
	if data != nil {
		out = deepCopy(data).(map[string]any)
	}
	for k, v := range s {
		setPath(out, k, v)
	}
	return out
}

// Values lists the live values, longest first, each also in the escaped
// forms a body or URL carries it in, so a value containing another is
// replaced whole. A link's token is listed on its own too (its query and
// fragment values of 8 characters or more, and path segments of 16 or
// more): a relay may quote the token alone, or a body encode the link so
// that only the token survives (quoted-printable turns "=" into "=3D").
func (s Secrets) Values() []string {
	var out []string
	add := func(f string) {
		if f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	for _, v := range s {
		if v == "" {
			continue
		}
		for _, f := range []string{v, html.EscapeString(v), url.QueryEscape(v)} {
			add(f)
		}
		for _, t := range linkTokens(v) {
			add(t)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// Scrub replaces every live value found in text, whatever its length,
// with Redacted.
func (s Secrets) Scrub(text string) string {
	for _, v := range s.Values() {
		text = strings.ReplaceAll(text, v, Redacted)
	}
	return text
}

// DefaultSecretTTL is how long a live secret is kept for retries unless
// the platform sets otherwise; MaxSecretTTL is the product's hard ceiling
// (NIST SP 800-63B-4 §4.2.2: an emailed recovery secret lives at most 24 h;
// ADR 0001 §3.14 class (a)).
const (
	DefaultSecretTTL = time.Hour
	MaxSecretTTL     = 24 * time.Hour
)

// SecretExpiry is when a message's live secrets must be gone: ttl after
// now (DefaultSecretTTL when unset, never past MaxSecretTTL), or sooner
// when the event says its code or link expires sooner (expires_at,
// expires_in_minutes). A secret past it is never sent.
func SecretExpiry(data map[string]any, now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		ttl = DefaultSecretTTL
	}
	ttl = min(ttl, MaxSecretTTL)
	at := now.Add(ttl)
	if v, ok := lookup(data, "expires_at"); ok {
		if s, ok := v.(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil && t.Before(at) {
				at = t
			}
		}
	}
	if v, ok := lookup(data, "expires_in_minutes"); ok {
		var mins float64
		switch n := v.(type) {
		case float64:
			mins = n
		case int:
			mins = float64(n)
		}
		if mins > 0 {
			if t := now.Add(time.Duration(mins * float64(time.Minute))); t.Before(at) {
				at = t
			}
		}
	}
	return at
}

// setPath writes a dotted path into nested maps, creating them.
func setPath(data map[string]any, key string, val any) {
	segs := strings.Split(key, ".")
	cur := data
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = val
}

// ScrubError returns err with the live values replaced in its text. A
// SendError keeps its classification (reason, provider, status, wait), so
// the queue and the router still treat it the same; the wrapped error
// stays reachable for errors.Is.
func (s Secrets) ScrubError(err error) error {
	if err == nil || len(s) == 0 {
		return err
	}
	if se, ok := AsSendError(err); ok {
		c := *se
		c.Detail = s.Scrub(c.Detail)
		if c.Err != nil {
			c.Err = scrubbedError{msg: s.Scrub(c.Err.Error()), err: c.Err}
		}
		return &c
	}
	return scrubbedError{msg: s.Scrub(err.Error()), err: err}
}

// scrubbedError is an error whose text had live values replaced.
type scrubbedError struct {
	msg string
	err error
}

func (e scrubbedError) Error() string { return e.msg }
func (e scrubbedError) Unwrap() error { return e.err }

// linkTokens are the parts of a link that may be its bearer token.
func linkTokens(v string) []string {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return nil
	}
	var out []string
	q := u.Query()
	if f, err := url.ParseQuery(u.Fragment); err == nil {
		for k, vs := range f {
			q[k] = append(q[k], vs...)
		}
	}
	for _, vs := range q {
		for _, t := range vs {
			if len(t) >= 8 {
				out = append(out, t)
			}
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if len(seg) >= 16 {
			out = append(out, seg)
		}
	}
	return out
}
