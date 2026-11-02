// Package application is a project that sends email through MailOS for its
// own tenant: a bank's core-banking service, a customer portal, IAM itself.
// It is the enterprise pattern of Postmark servers and message streams, SES
// tenants and configuration sets, and SendGrid subusers with scoped
// credentials, with one difference: MailOS issues no secret or API key. An
// application is bound to the OAuth client its owner registered in IAM, and
// every call proves that client with an IAM token (contract §1).
//
// The application decides what its client may do: which message types
// (topics and template slugs) it sends, from which verified senders, on
// which stream, how fast and how much, and whether mail is delivered at all
// (sandbox captures it).
package application

import (
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Kind is how the application calls MailOS.
type Kind string

// Kinds.
const (
	// KindServer is a backend with a confidential IAM client: it calls with
	// a client-credentials token (aud mailos). A browser front end uses its
	// own backend (backend-for-frontend) and never calls MailOS itself.
	KindServer Kind = "server"
	// KindSPA is a browser application with a public IAM client. Its
	// signed-in user's token (aud mailos, scope mailos.send.self) may send
	// only the templates the application marks browser_allowed, only to
	// the user's own verified address.
	KindSPA Kind = "spa"
)

// Status is whether the application may call.
type Status string

// Statuses.
const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
)

// Environment is whether mail leaves MailOS.
type Environment string

// Environments.
const (
	// EnvSandbox stores and renders messages and marks them captured; no
	// provider is called.
	EnvSandbox Environment = "sandbox"
	EnvLive    Environment = "live"
)

// Stream separates mail by reputation (Postmark message streams): one-to-
// one transactional mail never shares a queue with bulk broadcasts.
type Stream string

// Streams.
const (
	StreamTransactional Stream = "transactional"
	StreamBroadcast     Stream = "broadcast"
)

// RawType is the message type that allows a send with written content
// (subject and bodies in the request) instead of a published template. It
// is matched literally, never by a prefix pattern.
const RawType = "raw"

// SelfSendScope is the IAM scope a browser user's token carries to send
// to themselves through a spa application.
const SelfSendScope = "mailos.send.self"

// Limits.
const (
	MaxName             = 100
	MaxDescription      = 1000
	MaxClientID         = 255
	MaxList             = 50
	MaxPattern          = 128
	MaxRatePerMinute    = 100000
	MaxDailyQuota       = 10000000
	MaxUserRatePerHour  = 100
	DefaultRatePerMin   = 60
	DefaultDailyQuota   = 10000
	DefaultUserRatePerH = 5
	MaxSuspendReason    = 500
)

// Application is one sending project of a tenant.
type Application struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	Kind        Kind
	// ClientID is the IAM OAuth client the application calls with. A client
	// is one application, across all tenants.
	ClientID        string
	Status          Status
	SuspendedReason string
	Environment     Environment
	Stream          Stream
	// MessageTypes are what the application may send: exact topics or
	// template slugs, prefixes written "bank.otp.*", and RawType.
	MessageTypes []string
	// Senders are the from addresses it may use: an address, or
	// "*@domain" for any address on that domain. Each must be on one of the
	// tenant's verified sending domains.
	Senders          []string
	DefaultFromEmail string
	DefaultFromName  string
	DefaultReplyTo   string
	// RatePerMinute and DailyQuota bound sends; zero means unlimited and is
	// allowed only for a system application.
	RatePerMinute int
	DailyQuota    int
	// BrowserTemplates are the template slugs a spa user may send to
	// themselves (browser_allowed).
	BrowserTemplates []string
	// UserRatePerHour bounds one browser user's self-sends.
	UserRatePerHour int
	// AllowedOrigins are the spa's web origins; a self-send from another
	// Origin is refused.
	AllowedOrigins []string
	// System marks the application MailOS seeds from its configuration
	// (IAM's own client). Only its status can be changed in the console.
	System    bool
	CreatedBy string
	UpdatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Active reports whether the application may call.
func (a Application) Active() bool { return a.Status == StatusActive }

// Sandbox reports whether mail is captured instead of delivered.
func (a Application) Sandbox() bool { return a.Environment == EnvSandbox }

var (
	patternRE = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?$`)
	slugRE    = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	clientRE  = regexp.MustCompile(`^[A-Za-z0-9._:@/-]+$`)
)

// ValidPattern reports whether p is a message type pattern: a topic or
// slug, a prefix ending in ".*", or RawType. A bare "*" is never allowed.
func ValidPattern(p string) bool {
	return p == RawType || (len(p) <= MaxPattern && patternRE.MatchString(p))
}

// Matches reports whether key (a topic or template slug) matches pattern.
// "bank.otp.*" matches "bank.otp.login" but not "bank.otp" or
// "bank.otpx.login"; RawType matches only RawType.
func Matches(pattern, key string) bool {
	if key == "" {
		return false
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok && pattern != RawType {
		return strings.HasPrefix(key, prefix) && len(key) > len(prefix)
	}
	return pattern == key
}

// AllowsType reports whether one of keys (the message's topic and
// template slug) is among the application's message types.
func (a Application) AllowsType(keys ...string) bool {
	for _, p := range a.MessageTypes {
		for _, k := range keys {
			if Matches(p, k) {
				return true
			}
		}
	}
	return false
}

// AllowsRaw reports whether the application may send written content.
func (a Application) AllowsRaw() bool { return slices.Contains(a.MessageTypes, RawType) }

// NormalizeAddress lowercases and trims an address.
func NormalizeAddress(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// AllowsSender reports whether from matches one of the senders.
func (a Application) AllowsSender(from string) bool {
	from = NormalizeAddress(from)
	at := strings.LastIndexByte(from, '@')
	if at <= 0 {
		return false
	}
	for _, s := range a.Senders {
		if dom, ok := strings.CutPrefix(s, "*@"); ok {
			if from[at+1:] == dom {
				return true
			}
			continue
		}
		if s == from {
			return true
		}
	}
	return false
}

// SenderDomain is the domain of a sender entry ("*@d" or "x@d").
func SenderDomain(s string) string {
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return ""
	}
	return s[at+1:]
}

// AllowsBrowserTemplate reports whether a spa user may send slug.
func (a Application) AllowsBrowserTemplate(slug string) bool {
	return a.Kind == KindSPA && slices.Contains(a.BrowserTemplates, slug)
}

// AllowsOrigin reports whether a browser origin may self-send.
func (a Application) AllowsOrigin(origin string) bool {
	return slices.Contains(a.AllowedOrigins, strings.TrimRight(strings.ToLower(strings.TrimSpace(origin)), "/"))
}

// Normalize trims and lowercases what is matched without case, and drops
// duplicate and empty list entries.
func (a *Application) Normalize() {
	a.Name = strings.TrimSpace(a.Name)
	a.Description = strings.TrimSpace(a.Description)
	a.ClientID = strings.TrimSpace(a.ClientID)
	a.DefaultFromEmail = NormalizeAddress(a.DefaultFromEmail)
	a.DefaultFromName = strings.TrimSpace(a.DefaultFromName)
	a.DefaultReplyTo = NormalizeAddress(a.DefaultReplyTo)
	a.SuspendedReason = strings.TrimSpace(a.SuspendedReason)
	a.MessageTypes = cleanList(a.MessageTypes, strings.ToLower)
	a.Senders = cleanList(a.Senders, NormalizeAddress)
	a.BrowserTemplates = cleanList(a.BrowserTemplates, strings.ToLower)
	a.AllowedOrigins = cleanList(a.AllowedOrigins, func(s string) string { return strings.TrimRight(strings.ToLower(s), "/") })
}

func cleanList(in []string, norm func(string) string) []string {
	out := []string{}
	for _, s := range in {
		s = norm(strings.TrimSpace(s))
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func validAddress(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n<>") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// Validate checks an application before it is saved. allowPlaintext
// permits http:// origins (local and test). The tenant's verified senders
// are checked by the use case, which can see the sending domains.
func (a Application) Validate(allowPlaintext bool) error {
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: field, Code: code, Message: msg})
	}
	switch {
	case a.Name == "":
		add("name", "required", "name is required")
	case len(a.Name) > MaxName:
		add("name", "too_long", "name must be at most 100 characters")
	}
	if len(a.Description) > MaxDescription {
		add("description", "too_long", "description must be at most 1000 characters")
	}
	if a.Kind != KindServer && a.Kind != KindSPA {
		add("kind", "invalid", "kind must be server or spa")
	}
	switch {
	case a.ClientID == "":
		add("client_id", "required", "client_id is the IAM OAuth client the application calls with")
	case len(a.ClientID) > MaxClientID || !clientRE.MatchString(a.ClientID):
		add("client_id", "invalid", "client_id must be an IAM client identifier")
	}
	if a.Status != StatusActive && a.Status != StatusSuspended {
		add("status", "invalid", "status must be active or suspended")
	}
	if len(a.SuspendedReason) > MaxSuspendReason {
		add("suspended_reason", "too_long", "the reason must be at most 500 characters")
	}
	if a.Environment != EnvSandbox && a.Environment != EnvLive {
		add("environment", "invalid", "environment must be sandbox or live")
	}
	if a.Stream != StreamTransactional && a.Stream != StreamBroadcast {
		add("stream", "invalid", "stream must be transactional or broadcast")
	}

	if len(a.MessageTypes) == 0 {
		add("message_types", "required", "allow at least one message type")
	}
	if len(a.MessageTypes) > MaxList {
		add("message_types", "too_many", "at most 50 message types")
	}
	for _, p := range a.MessageTypes {
		if !ValidPattern(p) {
			add("message_types", "invalid", "message type "+p+" must be a topic or template slug, a prefix ending in .*, or raw")
			break
		}
	}

	if len(a.Senders) > MaxList {
		add("senders", "too_many", "at most 50 senders")
	}
	for _, s := range a.Senders {
		probe := s
		if dom, ok := strings.CutPrefix(s, "*@"); ok {
			probe = "any@" + dom
		}
		if !validAddress(probe) {
			add("senders", "invalid", "sender "+s+" must be an address or *@domain")
			break
		}
	}
	if a.DefaultFromEmail != "" && !a.AllowsSender(a.DefaultFromEmail) {
		add("default_from_email", "not_allowed", "the default sender must be one of the senders")
	}
	if a.DefaultReplyTo != "" && !validAddress(a.DefaultReplyTo) {
		add("default_reply_to", "invalid", "default_reply_to must be an address")
	}
	if len(a.DefaultFromName) > 255 {
		add("default_from_name", "too_long", "default_from_name must be at most 255 characters")
	}

	limit := func(field string, v, maxV int) {
		switch {
		case v == 0 && a.System:
		case v < 1 || v > maxV:
			add(field, "out_of_range", field+" must be between 1 and "+strconv.Itoa(maxV))
		}
	}
	limit("rate_limit_per_minute", a.RatePerMinute, MaxRatePerMinute)
	limit("daily_quota", a.DailyQuota, MaxDailyQuota)

	if a.Kind == KindSPA {
		a.validateSPA(add, allowPlaintext)
	} else if len(a.BrowserTemplates) > 0 || len(a.AllowedOrigins) > 0 || a.UserRatePerHour != 0 {
		add("browser_templates", "not_allowed", "browser templates, origins and per-user limits are for spa applications only")
	}
	if a.System && a.Kind != KindServer {
		add("kind", "invalid", "a system application is a server")
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

func (a Application) validateSPA(add func(field, code, msg string), allowPlaintext bool) {
	if a.AllowsRaw() {
		add("message_types", "not_allowed", "a spa application cannot send raw content")
	}
	if len(a.BrowserTemplates) == 0 {
		add("browser_templates", "required", "a spa application needs at least one browser template")
	}
	if len(a.BrowserTemplates) > MaxList {
		add("browser_templates", "too_many", "at most 50 browser templates")
	}
	for _, t := range a.BrowserTemplates {
		if !slugRE.MatchString(t) {
			add("browser_templates", "invalid", "browser template "+t+" must be a template slug")
			break
		}
		if !a.AllowsType(t) {
			add("browser_templates", "not_allowed", "browser template "+t+" is not among the message types")
			break
		}
	}
	if a.DefaultFromEmail == "" {
		add("default_from_email", "required", "a spa application sends from its default sender")
	}
	if a.UserRatePerHour < 1 || a.UserRatePerHour > MaxUserRatePerHour {
		add("user_rate_limit_per_hour", "out_of_range", "user_rate_limit_per_hour must be between 1 and 100")
	}
	if len(a.AllowedOrigins) == 0 {
		add("allowed_origins", "required", "a spa application needs its web origin")
	}
	if len(a.AllowedOrigins) > MaxList {
		add("allowed_origins", "too_many", "at most 50 origins")
	}
	for _, o := range a.AllowedOrigins {
		u, err := url.Parse(o)
		ok := err == nil && u.Host != "" && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil &&
			(u.Scheme == "https" || (u.Scheme == "http" && allowPlaintext))
		if !ok {
			add("allowed_origins", "invalid", "origin "+o+" must be an https origin (scheme and host only)")
			break
		}
	}
}
