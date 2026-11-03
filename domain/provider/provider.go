// Package provider is a tenant's outbound mail providers: an SMTP relay
// (the bank's Exchange, Postfix, Microsoft 365, Google Workspace, or a
// sending service's SMTP endpoint) or one of the HTTPS sending APIs
// (Microsoft Graph, Gmail, Azure Communication Services, Amazon SES,
// SendGrid, Mailgun, Postmark, SparkPost, Brevo, Mailjet, Mandrill,
// Resend). A tenant may configure several; the router tries them by
// priority, then spreads load by weight among providers of equal priority.
//
// Each provider has non-secret Settings and secret Credentials as separate
// types: the repository seals only the credentials with the key manager
// (contract §6), and the console only ever sees the redacted View. Which
// settings and credentials a kind takes is declared once, in its Schema;
// validation and the console's forms both follow it.
package provider

import (
	"encoding/json"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

// Kind is the provider's sending protocol or API.
type Kind string

// Provider kinds.
const (
	KindSMTP      Kind = "smtp"
	KindSES       Kind = "ses"
	KindSendGrid  Kind = "sendgrid"
	KindMailgun   Kind = "mailgun"
	KindPostmark  Kind = "postmark"
	KindMSGraph   Kind = "msgraph"
	KindGmail     Kind = "gmail"
	KindACS       Kind = "acs"
	KindSparkPost Kind = "sparkpost"
	KindBrevo     Kind = "brevo"
	KindMailjet   Kind = "mailjet"
	KindMandrill  Kind = "mandrill"
	KindResend    Kind = "resend"
)

// Kinds lists every provider kind, in the order the console offers them.
var Kinds = []Kind{
	KindSMTP, KindMSGraph, KindGmail, KindACS, KindSES, KindSendGrid, KindMailgun,
	KindPostmark, KindSparkPost, KindBrevo, KindMailjet, KindMandrill, KindResend,
}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	_, ok := schemaOf(k)
	return ok
}

// SPFInclude is the SPF mechanism a sending domain publishes to authorise
// the provider's servers, or "" when there is none to publish (SMTP: the
// relay's operator knows it; Resend: its return path is a subdomain).
func (k Kind) SPFInclude() string {
	if s, ok := schemaOf(k); ok {
		return s.SPFInclude
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

// SMTP authentication mechanisms.
const (
	AuthNone    = "none"
	AuthPlain   = "plain"
	AuthLogin   = "login"
	AuthCRAMMD5 = "cram-md5"
	AuthXOAUTH2 = "xoauth2"
)

// OAuth 2.0 identity platforms for SMTP XOAUTH2.
const (
	OAuthMicrosoft = "microsoft"
	OAuthGoogle    = "google"
)

// Microsoft credential types: a client secret or a certificate.
const (
	MicrosoftSecret      = "secret"
	MicrosoftCertificate = "certificate"
)

// Microsoft clouds (Graph and Entra ID endpoints differ per cloud).
const (
	CloudGlobal   = "global"
	CloudUSGov    = "usgov"
	CloudUSGovDoD = "usgov_dod"
	CloudChina    = "china"
)

// Regions of the APIs that offer EU data residency. Each API host is
// fixed per region, so an API key can never be sent elsewhere.
const (
	RegionGlobal = "global"
	RegionUS     = "us"
	RegionEU     = "eu"
)

// Mailgun API hosts.
const (
	MailgunUS = "https://api.mailgun.net"
	MailgunEU = "https://api.eu.mailgun.net"
)

// PresetCustom is the preset value of a provider configured by hand.
const PresetCustom = "custom"

// Bounds on the scheduling fields.
const (
	MaxPriority   = 100
	MaxWeight     = 1000
	DefaultWeight = 100
	MaxNameLen    = 255
)

// Settings are a provider's non-secret settings. Which fields apply depends
// on the kind (its Schema); Validate refuses fields the kind does not use.
// The JSON names are the schema's field keys.
type Settings struct {
	// FromEmail and FromName are the default sender, used when a message
	// names none. Any kind.
	FromEmail string `json:"from_email,omitempty"`
	FromName  string `json:"from_name,omitempty"`

	// Preset is the SMTP preset the console started from (informational).
	Preset string `json:"preset,omitempty"`

	// SMTP.
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	TLSMode       string `json:"tls_mode,omitempty"`
	AuthMechanism string `json:"auth_mechanism,omitempty"`
	Username      string `json:"username,omitempty"`
	// OAuthProvider is the identity platform of XOAUTH2 tokens.
	OAuthProvider string `json:"oauth_provider,omitempty"`
	// HELOName is the name sent in EHLO.
	HELOName string `json:"helo_name,omitempty"`
	// CACert is a PEM bundle trusted for the relay's certificate, in
	// addition to the system roots.
	CACert string `json:"ca_cert,omitempty"`
	// ClientCert is the PEM certificate MailOS presents (mutual TLS); its
	// key is the credential client_key.
	ClientCert string `json:"client_cert,omitempty"`

	// Microsoft Entra ID application (Graph; SMTP XOAUTH2 with Microsoft).
	Cloud      string `json:"cloud,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"`
	// ClientCertificate is the application's PEM certificate; its key is
	// the credential certificate_key.
	ClientCertificate string `json:"client_certificate,omitempty"`

	// Sender is the mailbox that sends: the Graph user, or the Google
	// Workspace user the service account impersonates.
	Sender string `json:"sender,omitempty"`

	// Endpoint is the Azure Communication Services resource endpoint.
	Endpoint string `json:"endpoint,omitempty"`

	// Region is the AWS region (SES) or the API region (SendGrid,
	// SparkPost, Mailgun).
	Region string `json:"region,omitempty"`
	// ConfigurationSet is the SES configuration set for event publishing.
	ConfigurationSet string `json:"configuration_set,omitempty"`

	// Domain is the Mailgun sending domain.
	Domain string `json:"domain,omitempty"`

	// MessageStream is the Postmark message stream (default "outbound").
	MessageStream string `json:"message_stream,omitempty"`

	// Subaccount is the Mandrill subaccount.
	Subaccount string `json:"subaccount,omitempty"`
}

// Credentials are a provider's secrets. The repository stores them sealed
// and they are never returned: callers see View. The JSON names are the
// schema's secret field keys.
type Credentials struct {
	// Password is the SMTP password.
	Password string `json:"password,omitempty"`
	// AccessKeyID and SecretAccessKey are the SES IAM user's keys.
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	// APIKey is the API key of SendGrid, Mailgun, SparkPost, Brevo,
	// Mailjet, Mandrill or Resend.
	APIKey string `json:"api_key,omitempty"`
	// APISecret is the Mailjet secret key.
	APISecret string `json:"api_secret,omitempty"`
	// ServerToken is the Postmark server token.
	ServerToken string `json:"server_token,omitempty"`
	// ClientSecret is the Entra ID application's client secret.
	ClientSecret string `json:"client_secret,omitempty"`
	// CertificateKey is the PEM private key of the Entra ID application's
	// certificate.
	CertificateKey string `json:"certificate_key,omitempty"`
	// ClientKey is the PEM private key of the SMTP client certificate.
	ClientKey string `json:"client_key,omitempty"`
	// ServiceAccountJSON is the Google service account key file.
	ServiceAccountJSON string `json:"service_account_json,omitempty"`
	// AccessKey is the Azure Communication Services access key.
	AccessKey string `json:"access_key,omitempty"`
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

// Map returns the set credentials by key.
func (c Credentials) Map() map[string]string {
	raw, _ := json.Marshal(c)
	out := map[string]string{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// CredentialsFrom builds credentials from a key map (unknown keys are
// dropped; callers check keys with DecodeCredentials first).
func CredentialsFrom(m map[string]string) Credentials {
	var c Credentials
	raw, _ := json.Marshal(m)
	_ = json.Unmarshal(raw, &c)
	return c
}

// Merge returns c with every non-empty field of next applied, so an update
// that leaves a secret blank keeps the stored one.
func (c Credentials) Merge(next Credentials) Credentials {
	m := c.Map()
	for k, v := range next.Map() {
		if v != "" {
			m[k] = v
		}
	}
	return CredentialsFrom(m)
}

// Hints tell the console which secrets are stored: every stored key, with
// the last characters of identifiers and API keys, or "" for secrets that
// get no hint (passwords, secret keys, private keys).
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

// hinted are the keys whose last four characters may be shown.
var hinted = map[string]bool{"access_key_id": true, "api_key": true, "server_token": true, "access_key": true}

// Hints returns the credentials' hints, nil when none are stored.
func (c Credentials) Hints() Hints {
	h := Hints{}
	for k, v := range c.Map() {
		switch {
		case v == "":
			continue
		case hinted[k]:
			h[k] = lastFour(v)
		case k == "service_account_json":
			// The account's address identifies the key and is not secret.
			h[k] = ServiceAccountEmail(v)
		default:
			h[k] = ""
		}
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

// ServiceAccountEmail is the client_email of a Google service account key
// file, or "" when it cannot be read.
func ServiceAccountEmail(keyFile string) string {
	var k struct {
		ClientEmail string `json:"client_email"`
	}
	if json.Unmarshal([]byte(keyFile), &k) != nil || !ValidEmail(k.ClientEmail) {
		return ""
	}
	return k.ClientEmail
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
	// LastTest is the outcome of the last connection test or test send.
	LastTest  *LastTest
	CreatedBy string
	UpdatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
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
	LastTest        *LastTest `json:"last_test,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// View returns the redacted view.
func (p *Provider) View() View {
	return View{
		ID: p.ID, Name: p.Name, Kind: p.Kind, Settings: p.Settings,
		Priority: p.Priority, Weight: p.Weight, DailyLimit: p.DailyLimit, Active: p.Active,
		HasCredentials: p.HasCredentials, CredentialHints: p.CredentialHints, LastTest: p.LastTest,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
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
	if s.Region == RegionEU {
		return MailgunEU
	}
	return MailgunUS
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

// MicrosoftEndpoints are the Entra ID login and Graph hosts of a cloud.
func (s Settings) MicrosoftEndpoints() (login, graph string) {
	switch s.Cloud {
	case CloudUSGov:
		return "https://login.microsoftonline.us", "https://graph.microsoft.us"
	case CloudUSGovDoD:
		return "https://login.microsoftonline.us", "https://dod-graph.microsoft.us"
	case CloudChina:
		return "https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn"
	}
	return "https://login.microsoftonline.com", "https://graph.microsoft.com"
}

// DefaultFrom is the provider's default sender: from_email, or the
// mailbox it sends as.
func (s Settings) DefaultFrom() (name, email string) {
	email = s.FromEmail
	if email == "" {
		email = s.Sender
	}
	return s.FromName, email
}
