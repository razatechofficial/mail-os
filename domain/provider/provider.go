// Package provider is a tenant's outbound mail providers: an SMTP relay or
// one of the HTTPS sending APIs (Amazon SES, SendGrid, Mailgun, Postmark).
// A tenant may configure several; the router tries them by priority, then
// spreads load by weight among providers of equal priority.
//
// Each provider has non-secret Settings (host, region, domain) and secret
// Credentials (passwords, API keys) as separate types: the repository
// seals only the credentials with the key manager (contract §6), and the
// console only ever sees the redacted View.
package provider

import (
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Kind is the provider's sending protocol or API.
type Kind string

// Provider kinds.
const (
	KindSMTP     Kind = "smtp"
	KindSES      Kind = "ses"
	KindSendGrid Kind = "sendgrid"
	KindMailgun  Kind = "mailgun"
	KindPostmark Kind = "postmark"
)

// Kinds lists every provider kind.
var Kinds = []Kind{KindSMTP, KindSES, KindSendGrid, KindMailgun, KindPostmark}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindSMTP, KindSES, KindSendGrid, KindMailgun, KindPostmark:
		return true
	}
	return false
}

// SPFInclude is the SPF mechanism a sending domain publishes to authorise
// the provider's servers, or "" for SMTP (the relay's operator knows it).
func (k Kind) SPFInclude() string {
	switch k {
	case KindSES:
		return "amazonses.com"
	case KindSendGrid:
		return "sendgrid.net"
	case KindMailgun:
		return "mailgun.org"
	case KindPostmark:
		return "spf.mtasv.net"
	}
	return ""
}

// SMTP TLS modes. "none" is plaintext and allowed only where the
// deployment allows plaintext transports (local and test).
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "implicit"
	TLSNone     = "none"
)

// Mailgun API hosts. A tenant picks the region; any other host is refused,
// so the API key can never be sent somewhere else.
const (
	MailgunUS = "https://api.mailgun.net"
	MailgunEU = "https://api.eu.mailgun.net"
)

// SendGrid regions: global, or EU data residency (api.eu.sendgrid.com).
const (
	SendGridGlobal = ""
	SendGridEU     = "eu"
)

// Bounds on the scheduling fields.
const (
	MaxPriority   = 100
	MaxWeight     = 1000
	DefaultWeight = 100
	MaxNameLen    = 255
)

// Settings are a provider's non-secret settings. Which fields apply depends
// on the kind; Validate refuses fields another kind uses.
type Settings struct {
	// FromEmail and FromName are the default sender, used when a message
	// names none. Any kind.
	FromEmail string `json:"from_email,omitempty"`
	FromName  string `json:"from_name,omitempty"`

	// SMTP.
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	TLSMode  string `json:"tls_mode,omitempty"`
	Username string `json:"username,omitempty"`

	// Region is the AWS region (SES) or SendGrid region ("" or "eu").
	Region string `json:"region,omitempty"`
	// ConfigurationSet is the SES configuration set for event publishing.
	ConfigurationSet string `json:"configuration_set,omitempty"`

	// Domain is the Mailgun sending domain.
	Domain string `json:"domain,omitempty"`
	// BaseURL is the Mailgun API host: MailgunUS (default) or MailgunEU.
	BaseURL string `json:"base_url,omitempty"`

	// MessageStream is the Postmark message stream (default "outbound").
	MessageStream string `json:"message_stream,omitempty"`
}

// Credentials are a provider's secrets. The repository stores them sealed
// and they are never returned: callers see View.
type Credentials struct {
	// Password is the SMTP password.
	Password string `json:"password,omitempty"`
	// AccessKeyID and SecretAccessKey are the SES IAM user's keys.
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	// APIKey is the SendGrid or Mailgun API key.
	APIKey string `json:"api_key,omitempty"`
	// ServerToken is the Postmark server token.
	ServerToken string `json:"server_token,omitempty"`
}

const redacted = "[REDACTED]"

// String keeps credentials out of logs and error messages.
func (Credentials) String() string { return redacted }

// GoString keeps credentials out of %#v.
func (Credentials) GoString() string { return redacted }

// Empty reports whether no credential is set.
func (c Credentials) Empty() bool {
	return c == Credentials{}
}

// Merge returns c with every non-empty field of next applied, so an update
// that leaves a secret blank keeps the stored one.
func (c Credentials) Merge(next Credentials) Credentials {
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&c.Password, next.Password)
	set(&c.AccessKeyID, next.AccessKeyID)
	set(&c.SecretAccessKey, next.SecretAccessKey)
	set(&c.APIKey, next.APIKey)
	set(&c.ServerToken, next.ServerToken)
	return c
}

// Hints are the last characters of identifiers and API keys, for the
// console to tell keys apart. Passwords and secret access keys never get
// one.
type Hints map[string]string

// minHintLen is the shortest secret that gets a hint: four characters of a
// shorter value give too much of it away.
const minHintLen = 16

func lastFour(s string) string {
	if len(s) < minHintLen {
		return ""
	}
	return "…" + s[len(s)-4:]
}

// Hints returns the credentials' hints.
func (c Credentials) Hints() Hints {
	h := Hints{}
	for k, v := range map[string]string{
		"access_key_id": c.AccessKeyID,
		"api_key":       c.APIKey,
		"server_token":  c.ServerToken,
	} {
		if hint := lastFour(v); hint != "" {
			h[k] = hint
		}
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

// Provider is one of a tenant's outbound mail providers.
type Provider struct {
	ID string
	// OrgID is the IAM tenant the provider belongs to (column org_id).
	OrgID    string
	Name     string
	Kind     Kind
	Settings Settings
	// Priority orders providers: higher is tried first.
	Priority int
	// Weight spreads load among providers of equal priority; 0 makes the
	// provider a standby, tried after its weighted peers.
	Weight int
	// DailyLimit caps messages per UTC day; 0 is unlimited.
	DailyLimit int
	Active     bool
	// HasCredentials and CredentialHints describe the sealed credentials
	// without them; the repository keeps both in step with the secret.
	HasCredentials  bool
	CredentialHints Hints
	CreatedBy       string
	UpdatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SetCredentials records that c is stored for the provider (the repository
// seals c itself).
func (p *Provider) SetCredentials(c Credentials) {
	p.HasCredentials = !c.Empty()
	p.CredentialHints = c.Hints()
}

// UnderDailyLimit reports whether the provider may send another message
// after sentToday messages today.
func (p *Provider) UnderDailyLimit(sentToday int) bool {
	return p.DailyLimit <= 0 || sentToday < p.DailyLimit
}

// View is what the console and API return: everything but the secrets.
type View struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Kind            Kind      `json:"kind"`
	Settings        Settings  `json:"settings"`
	Priority        int       `json:"priority"`
	Weight          int       `json:"weight"`
	DailyLimit      int       `json:"daily_limit"`
	Active          bool      `json:"active"`
	HasCredentials  bool      `json:"has_credentials"`
	CredentialHints Hints     `json:"credential_hints,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// View returns the redacted view.
func (p *Provider) View() View {
	return View{
		ID: p.ID, Name: p.Name, Kind: p.Kind, Settings: p.Settings,
		Priority: p.Priority, Weight: p.Weight, DailyLimit: p.DailyLimit, Active: p.Active,
		HasCredentials: p.HasCredentials, CredentialHints: p.CredentialHints,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

// Normalize trims the provider's text fields and defaults the SMTP TLS mode
// to STARTTLS. Weight is left alone: 0 is a choice (standby), so the
// create path applies DefaultWeight itself.
func (p *Provider) Normalize() {
	p.Name = strings.TrimSpace(p.Name)
	s := &p.Settings
	s.FromEmail = strings.TrimSpace(s.FromEmail)
	s.FromName = strings.TrimSpace(s.FromName)
	s.Host = strings.ToLower(strings.TrimSpace(s.Host))
	s.TLSMode = strings.ToLower(strings.TrimSpace(s.TLSMode))
	s.Username = strings.TrimSpace(s.Username)
	s.Region = strings.ToLower(strings.TrimSpace(s.Region))
	s.ConfigurationSet = strings.TrimSpace(s.ConfigurationSet)
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	s.BaseURL = strings.TrimSuffix(strings.TrimSpace(s.BaseURL), "/")
	s.MessageStream = strings.TrimSpace(s.MessageStream)
	if p.Kind == KindSMTP && s.TLSMode == "" {
		s.TLSMode = TLSStartTLS
	}
}

// Validate checks the provider and its settings for its kind. Plaintext
// SMTP (tls_mode none) is accepted only when allowPlaintext is true.
// Failures are one 422 with an entry per field.
func (p *Provider) Validate(allowPlaintext bool) error {
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: field, Code: code, Message: msg})
	}
	switch {
	case p.Name == "":
		add("name", "required", "name is required")
	case len(p.Name) > MaxNameLen:
		add("name", "too_long", "name must be at most 255 characters")
	}
	if !p.Kind.Valid() {
		add("kind", "invalid", "kind must be smtp, ses, sendgrid, mailgun or postmark")
	}
	if p.Priority < 0 || p.Priority > MaxPriority {
		add("priority", "out_of_range", "priority must be between 0 and 100")
	}
	if p.Weight < 0 || p.Weight > MaxWeight {
		add("weight", "out_of_range", "weight must be between 0 and 1000")
	}
	if p.DailyLimit < 0 {
		add("daily_limit", "out_of_range", "daily limit must not be negative")
	}
	errs = append(errs, p.Settings.validate(p.Kind, allowPlaintext)...)
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

func (s Settings) validate(kind Kind, allowPlaintext bool) []apperrors.FieldError {
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: "settings." + field, Code: code, Message: msg})
	}
	if s.FromEmail != "" && !ValidEmail(s.FromEmail) {
		add("from_email", "invalid", "from email is not a valid address")
	}
	if strings.ContainsAny(s.FromName, "\r\n") || len(s.FromName) > MaxNameLen {
		add("from_name", "invalid", "from name must be one line of at most 255 characters")
	}
	// Fields only one kind uses must be empty for the others, so a stale
	// setting cannot change behaviour after the kind changes.
	only := func(field, value string, kinds ...Kind) {
		if value == "" {
			return
		}
		for _, k := range kinds {
			if k == kind {
				return
			}
		}
		add(field, "not_allowed", field+" does not apply to "+string(kind)+" providers")
	}
	only("host", s.Host, KindSMTP)
	if s.Port != 0 && kind != KindSMTP {
		add("port", "not_allowed", "port does not apply to "+string(kind)+" providers")
	}
	only("tls_mode", s.TLSMode, KindSMTP)
	only("username", s.Username, KindSMTP)
	only("region", s.Region, KindSES, KindSendGrid)
	only("configuration_set", s.ConfigurationSet, KindSES)
	only("domain", s.Domain, KindMailgun)
	only("base_url", s.BaseURL, KindMailgun)
	only("message_stream", s.MessageStream, KindPostmark)

	switch kind {
	case KindSMTP:
		if !ValidHost(s.Host) {
			add("host", "invalid", "host must be a DNS name or IP address")
		}
		if s.Port < 1 || s.Port > 65535 {
			add("port", "out_of_range", "port must be between 1 and 65535")
		}
		switch s.TLSMode {
		case TLSStartTLS, TLSImplicit:
		case TLSNone:
			if !allowPlaintext {
				add("tls_mode", "plaintext_refused", "plaintext SMTP is refused outside local and test")
			}
		default:
			add("tls_mode", "invalid", "tls mode must be starttls, implicit or none")
		}
		if len(s.Username) > MaxNameLen || strings.ContainsAny(s.Username, "\r\n") {
			add("username", "invalid", "username must be one line of at most 255 characters")
		}
	case KindSES:
		if !validRegion(s.Region) {
			add("region", "invalid", "region must be an AWS region such as eu-west-1")
		}
		if s.ConfigurationSet != "" && !validToken(s.ConfigurationSet, 64) {
			add("configuration_set", "invalid", "configuration set must be letters, digits, '-' and '_'")
		}
	case KindSendGrid:
		if s.Region != SendGridGlobal && s.Region != SendGridEU {
			add("region", "invalid", "region must be empty (global) or eu")
		}
	case KindMailgun:
		if !ValidHost(s.Domain) || net.ParseIP(s.Domain) != nil {
			add("domain", "invalid", "domain must be the Mailgun sending domain")
		}
		if s.BaseURL != "" && s.BaseURL != MailgunUS && s.BaseURL != MailgunEU {
			add("base_url", "invalid", "base URL must be "+MailgunUS+" or "+MailgunEU)
		}
	case KindPostmark:
		if s.MessageStream != "" && !validToken(s.MessageStream, 64) {
			add("message_stream", "invalid", "message stream must be letters, digits, '-' and '_'")
		}
	}
	return errs
}

// ValidateCredentials checks that c has what kind needs and nothing it
// does not. SMTP credentials are optional (relays that trust the network);
// a password needs a username in the settings, which the caller checks
// with the provider.
func ValidateCredentials(kind Kind, c Credentials) error {
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: "credentials." + field, Code: code, Message: msg})
	}
	need := func(field, v string) {
		switch {
		case v == "":
			add(field, "required", field+" is required for "+string(kind)+" providers")
		case len(v) > 4096 || strings.ContainsAny(v, "\r\n"):
			add(field, "invalid", field+" must be one line of at most 4096 characters")
		}
	}
	none := func(field, v string) {
		if v != "" {
			add(field, "not_allowed", field+" does not apply to "+string(kind)+" providers")
		}
	}
	switch kind {
	case KindSMTP:
		if c.Password != "" {
			need("password", c.Password)
		}
		none("access_key_id", c.AccessKeyID)
		none("secret_access_key", c.SecretAccessKey)
		none("api_key", c.APIKey)
		none("server_token", c.ServerToken)
	case KindSES:
		need("access_key_id", c.AccessKeyID)
		need("secret_access_key", c.SecretAccessKey)
		none("password", c.Password)
		none("api_key", c.APIKey)
		none("server_token", c.ServerToken)
	case KindSendGrid, KindMailgun:
		need("api_key", c.APIKey)
		none("password", c.Password)
		none("access_key_id", c.AccessKeyID)
		none("secret_access_key", c.SecretAccessKey)
		none("server_token", c.ServerToken)
	case KindPostmark:
		need("server_token", c.ServerToken)
		none("password", c.Password)
		none("access_key_id", c.AccessKeyID)
		none("secret_access_key", c.SecretAccessKey)
		none("api_key", c.APIKey)
	default:
		return apperrors.Invalid("kind", "invalid", "kind must be smtp, ses, sendgrid, mailgun or postmark")
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

// ValidEmail reports whether s is a bare address (no display name).
func ValidEmail(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n<>") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// ValidHost reports whether s is an IP address or a DNS name.
func ValidHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// validRegion accepts AWS region names such as eu-west-1 or us-gov-west-1.
func validRegion(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return false
	}
	if _, err := strconv.Atoi(parts[len(parts)-1]); err != nil {
		return false
	}
	return validToken(s, 32)
}

func validToken(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// MailgunBaseURL returns the provider's Mailgun API host.
func (s Settings) MailgunBaseURL() string {
	if s.BaseURL == "" {
		return MailgunUS
	}
	return s.BaseURL
}

// SMTPAddr returns host:port.
func (s Settings) SMTPAddr() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// postmarkDefaultStream is Postmark's transactional stream.
const postmarkDefaultStream = "outbound"

// PostmarkStream returns the provider's Postmark message stream.
func (s Settings) PostmarkStream() string {
	if s.MessageStream == "" {
		return postmarkDefaultStream
	}
	return s.MessageStream
}
