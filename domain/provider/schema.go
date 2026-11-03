package provider

import (
	"slices"
)

// FieldType is how the console renders a field.
type FieldType string

// Field types.
const (
	FieldText     FieldType = "text"
	FieldPassword FieldType = "password"
	FieldNumber   FieldType = "number"
	FieldSelect   FieldType = "select"
	FieldBoolean  FieldType = "boolean"
	FieldFile     FieldType = "file" // text read from a file (PEM, JSON); may be pasted
	FieldTextarea FieldType = "textarea"
	FieldEmail    FieldType = "email"
	FieldURL      FieldType = "url"
)

// Formats a text field's value must have; the console checks the ones it
// knows, the server all of them.
const (
	FormatEmail      = "email"
	FormatHostname   = "hostname"
	FormatAWSRegion  = "aws_region"
	FormatHTTPSURL   = "https_url"
	FormatUUID       = "uuid"
	FormatPEMCert    = "pem_certificate"
	FormatPEMKey     = "pem_private_key"
	FormatJSON       = "json"
	FormatEntraID    = "entra_tenant" // a tenant id (UUID) or verified domain
	FormatIdentifier = "identifier"   // letters, digits, '-' and '_'
)

// Option is one choice of a select field.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Validation are a field's value rules. Pattern is a regular expression in
// the subset Go (RE2) and JavaScript share.
type Validation struct {
	Min            *int   `json:"min,omitempty"`
	Max            *int   `json:"max,omitempty"`
	MaxLength      int    `json:"max_length,omitempty"`
	Pattern        string `json:"pattern,omitempty"`
	PatternMessage string `json:"pattern_message,omitempty"`
	Format         string `json:"format,omitempty"`
}

// Condition shows a field only when another field's value is one of In.
type Condition struct {
	Field string   `json:"field"`
	In    []string `json:"in"`
}

// Field is one setting or credential of a provider kind. Secret fields are
// credentials: sealed, write-only, never returned.
type Field struct {
	Key         string      `json:"key"`
	Label       string      `json:"label"`
	Type        FieldType   `json:"type"`
	Required    bool        `json:"required"`
	Default     any         `json:"default,omitempty"`
	Help        string      `json:"help,omitempty"`
	Placeholder string      `json:"placeholder,omitempty"`
	Secret      bool        `json:"secret"`
	Group       string      `json:"group"`
	Options     []Option    `json:"options,omitempty"`
	Validation  *Validation `json:"validation,omitempty"`
	// VisibleWhen are conditions that must all hold for the field to
	// apply; a field that does not apply is neither required nor kept.
	VisibleWhen []Condition `json:"visible_when,omitempty"`
	// Accept is a file field's file types (an <input accept> value).
	Accept string `json:"accept,omitempty"`
	// lower normalises the value to lower case.
	lower bool
}

// Group is a section of the form.
type Group struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Preset is a known relay: the values it fills in.
type Preset struct {
	ID          string         `json:"id"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	Values      map[string]any `json:"values"`
}

// Categories of kinds.
const (
	CategorySMTP = "smtp"
	CategoryAPI  = "api"
)

// TypeSchema describes one kind for the console and for validation.
type TypeSchema struct {
	Type        Kind     `json:"type"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	SPFInclude  string   `json:"spf_include"`
	Groups      []Group  `json:"groups"`
	Fields      []Field  `json:"fields"`
	Presets     []Preset `json:"presets,omitempty"`
}

// Field returns the kind's field key.
func (t TypeSchema) Field(key string) (Field, bool) {
	for _, f := range t.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

// Range is a scheduling field's bounds and explanation.
type Range struct {
	Min     int    `json:"min"`
	Max     int    `json:"max,omitempty"`
	Default int    `json:"default"`
	Help    string `json:"help"`
}

// Scheduling explains priority, weight and the daily limit.
type Scheduling struct {
	Priority   Range `json:"priority"`
	Weight     Range `json:"weight"`
	DailyLimit Range `json:"daily_limit"`
}

// Catalog is the schema endpoint's body.
type Catalog struct {
	Types      []TypeSchema `json:"types"`
	Scheduling Scheduling   `json:"scheduling"`
}

var groupLabels = []Group{
	{"sender", "Default sender"},
	{"connection", "Connection"},
	{"authentication", "Authentication"},
	{"security", "TLS and certificates"},
	{"advanced", "Advanced"},
}

func intp(v int) *int { return &v }

// Schema returns every kind's schema. Plaintext SMTP is offered only when
// the deployment allows it (local and test).
func Schema(allowPlaintext bool) Catalog {
	types := make([]TypeSchema, 0, len(Kinds))
	for _, k := range Kinds {
		t, _ := schemaOf(k)
		if k == KindSMTP && !allowPlaintext {
			t = withoutPlaintext(t)
		}
		types = append(types, t)
	}
	return Catalog{Types: types, Scheduling: Scheduling{
		Priority: Range{Min: 0, Max: MaxPriority, Default: 0,
			Help: "Higher goes first. MailOS tries the highest-priority provider and moves to the next priority only when it fails for its own reasons (credentials, outage, rate limit)."},
		Weight: Range{Min: 0, Max: MaxWeight, Default: DefaultWeight,
			Help: "Shares load between providers of the same priority: one with weight 200 gets about twice the mail of one with 100. 0 makes it a standby, used only when the others fail."},
		DailyLimit: Range{Min: 0, Default: 0,
			Help: "Messages per day (UTC) before this provider is skipped until midnight, for plans with a daily quota. 0 means no limit."},
	}}
}

func withoutPlaintext(t TypeSchema) TypeSchema {
	t.Fields = slices.Clone(t.Fields)
	for i, f := range t.Fields {
		if f.Key == "tls_mode" {
			f.Options = slices.DeleteFunc(slices.Clone(f.Options), func(o Option) bool { return o.Value == TLSNone })
			t.Fields[i] = f
		}
	}
	return t
}

var schemas = buildSchemas()

func schemaOf(k Kind) (TypeSchema, bool) {
	t, ok := schemas[k]
	return t, ok
}

// SchemaOf returns kind's schema.
func SchemaOf(k Kind) (TypeSchema, bool) { return schemaOf(k) }

func when(field string, in ...string) Condition { return Condition{Field: field, In: in} }

func senderFields(mailbox bool) []Field {
	help := "Used when a message names no sender. Use an address on one of your verified sending domains."
	if mailbox {
		help = "Used when a message names no sender. Defaults to the sending mailbox; another address needs Send As rights on it."
	}
	return []Field{
		{Key: "from_email", Label: "From address", Type: FieldEmail, Group: "sender", Help: help,
			Placeholder: "noreply@bank.example", Validation: &Validation{Format: FormatEmail, MaxLength: 254}, lower: true},
		{Key: "from_name", Label: "From name", Type: FieldText, Group: "sender", Placeholder: "Example Bank",
			Validation: &Validation{MaxLength: MaxNameLen}},
	}
}

func apiKey(label, help, placeholder string) Field {
	return Field{Key: "api_key", Label: label, Type: FieldPassword, Required: true, Secret: true, Group: "authentication",
		Help: help, Placeholder: placeholder, Validation: &Validation{MaxLength: 4096}}
}

// microsoftFields are an Entra ID application's identity, shown when all
// of cond hold.
func microsoftFields(cond ...Condition) []Field {
	with := func(extra ...Condition) []Condition { return append(slices.Clone(cond), extra...) }
	return []Field{
		{Key: "tenant_id", Label: "Directory (tenant) ID", Type: FieldText, Required: true, Group: "authentication",
			Help:        "From the app registration's Overview page in the Microsoft Entra admin center: a GUID or a verified domain.",
			Placeholder: "00000000-0000-0000-0000-000000000000", Validation: &Validation{Format: FormatEntraID, MaxLength: 253},
			VisibleWhen: with(), lower: true},
		{Key: "client_id", Label: "Application (client) ID", Type: FieldText, Required: true, Group: "authentication",
			Help: "The app registration's Application (client) ID.", Placeholder: "00000000-0000-0000-0000-000000000000",
			Validation: &Validation{Format: FormatUUID}, VisibleWhen: with(), lower: true},
		{Key: "auth_method", Label: "Credential type", Type: FieldSelect, Required: true, Default: MicrosoftSecret, Group: "authentication",
			Help:    "A certificate is preferred for production: it cannot be copied from a configuration screen and can be kept in an HSM-backed store.",
			Options: []Option{{MicrosoftSecret, "Client secret"}, {MicrosoftCertificate, "Certificate"}}, VisibleWhen: with()},
		{Key: "client_secret", Label: "Client secret", Type: FieldPassword, Required: true, Secret: true, Group: "authentication",
			Help:       "The secret's Value (not its ID). Secrets expire: note the expiry date and rotate before it.",
			Validation: &Validation{MaxLength: 1024}, VisibleWhen: with(when("auth_method", MicrosoftSecret))},
		{Key: "client_certificate", Label: "Certificate (PEM)", Type: FieldFile, Required: true, Group: "authentication", Accept: ".pem,.crt,.cer",
			Help:       "The public certificate uploaded to the app registration under Certificates & secrets.",
			Validation: &Validation{Format: FormatPEMCert, MaxLength: 65536}, VisibleWhen: with(when("auth_method", MicrosoftCertificate))},
		{Key: "certificate_key", Label: "Certificate private key (PEM)", Type: FieldFile, Required: true, Secret: true, Group: "authentication", Accept: ".pem,.key",
			Help:       "The certificate's RSA private key, unencrypted PEM (PKCS#1 or PKCS#8).",
			Validation: &Validation{Format: FormatPEMKey, MaxLength: 65536}, VisibleWhen: with(when("auth_method", MicrosoftCertificate))},
	}
}

func buildSchemas() map[Kind]TypeSchema {
	list := []TypeSchema{smtpSchema(), msGraphSchema(), gmailSchema(), acsSchema(), sesSchema(), sendGridSchema(), mailgunSchema(),
		postmarkSchema(), sparkPostSchema(), brevoSchema(), mailjetSchema(), mandrillSchema(), resendSchema()}
	out := make(map[Kind]TypeSchema, len(list))
	for _, t := range list {
		for _, g := range groupLabels {
			if slices.ContainsFunc(t.Fields, func(f Field) bool { return f.Group == g.Key }) {
				t.Groups = append(t.Groups, g)
			}
		}
		out[t.Type] = t
	}
	return out
}

var smtpAuthed = []string{AuthPlain, AuthLogin, AuthCRAMMD5, AuthXOAUTH2}

func smtpSchema() TypeSchema {
	xoauth := when("auth_mechanism", AuthXOAUTH2)
	fields := []Field{
		{Key: "host", Label: "Host", Type: FieldText, Required: true, Group: "connection", Placeholder: "smtp.bank.example",
			Help: "The relay's DNS name. It must match the name in the relay's TLS certificate.", Validation: &Validation{Format: FormatHostname, MaxLength: 253}, lower: true},
		{Key: "port", Label: "Port", Type: FieldNumber, Required: true, Default: 587, Group: "connection",
			Help: "587 for submission with STARTTLS, 465 for implicit TLS, 25 for server-to-server relay.", Validation: &Validation{Min: intp(1), Max: intp(65535)}},
		{Key: "tls_mode", Label: "Encryption", Type: FieldSelect, Required: true, Default: TLSStartTLS, Group: "connection",
			Help: "STARTTLS upgrades the connection and is required: a relay that does not offer it is refused, never used in plaintext.",
			Options: []Option{{TLSStartTLS, "STARTTLS (usually port 587 or 25)"}, {TLSImplicit, "Implicit TLS (usually port 465)"},
				{TLSNone, "None, plaintext (local and test only)"}}},
		{Key: "auth_mechanism", Label: "Authentication", Type: FieldSelect, Required: true, Default: AuthPlain, Group: "authentication",
			Help: "PLAIN or LOGIN with a username and password; CRAM-MD5 where the relay requires it; OAuth 2.0 (XOAUTH2) for Microsoft 365 and Google Workspace; none for a relay that allows MailOS's address.",
			Options: []Option{{AuthPlain, "Username and password (PLAIN)"}, {AuthLogin, "Username and password (LOGIN)"},
				{AuthCRAMMD5, "Username and password (CRAM-MD5)"}, {AuthXOAUTH2, "OAuth 2.0 (XOAUTH2)"}, {AuthNone, "None (IP-allowlisted relay)"}}},
		{Key: "username", Label: "Username", Type: FieldText, Required: true, Group: "authentication",
			Help: "For XOAUTH2, the mailbox that sends (its user principal name).", Validation: &Validation{MaxLength: MaxNameLen},
			VisibleWhen: []Condition{when("auth_mechanism", smtpAuthed...)}},
		{Key: "password", Label: "Password", Type: FieldPassword, Required: true, Secret: true, Group: "authentication",
			Help: "Sent only after TLS is established.", Validation: &Validation{MaxLength: 4096},
			VisibleWhen: []Condition{when("auth_mechanism", AuthPlain, AuthLogin, AuthCRAMMD5)}},
		{Key: "oauth_provider", Label: "OAuth identity platform", Type: FieldSelect, Required: true, Default: OAuthMicrosoft, Group: "authentication",
			Help:        "Microsoft: an Entra ID app with the SMTP.SendAsApp permission, registered in Exchange Online as a service principal with access to the mailbox. Google: a service account with domain-wide delegation for https://mail.google.com/.",
			Options:     []Option{{OAuthMicrosoft, "Microsoft 365 / Exchange Online"}, {OAuthGoogle, "Google Workspace"}},
			VisibleWhen: []Condition{xoauth}},
	}
	fields = append(fields, microsoftFields(xoauth, when("oauth_provider", OAuthMicrosoft))...)
	fields = append(fields,
		Field{Key: "service_account_json", Label: "Service account key (JSON)", Type: FieldFile, Required: true, Secret: true, Group: "authentication", Accept: ".json",
			Help:       "The key file of a service account with domain-wide delegation for the scope https://mail.google.com/ in the Google Admin console.",
			Validation: &Validation{Format: FormatJSON, MaxLength: 65536}, VisibleWhen: []Condition{xoauth, when("oauth_provider", OAuthGoogle)}},
		Field{Key: "ca_cert", Label: "Trusted CA certificates (PEM)", Type: FieldFile, Group: "security", Accept: ".pem,.crt,.cer",
			Help:       "For a relay whose certificate is issued by your internal CA. Trusted in addition to the public roots. Leave empty for a public certificate.",
			Validation: &Validation{Format: FormatPEMCert, MaxLength: 262144}},
		Field{Key: "client_cert", Label: "Client certificate (PEM)", Type: FieldFile, Group: "security", Accept: ".pem,.crt,.cer",
			Help:       "For a relay that requires mutual TLS: the certificate MailOS presents. Needs the matching private key.",
			Validation: &Validation{Format: FormatPEMCert, MaxLength: 65536}},
		Field{Key: "client_key", Label: "Client certificate private key (PEM)", Type: FieldFile, Secret: true, Group: "security", Accept: ".pem,.key",
			Help:       "Unencrypted PEM. Stored encrypted and never shown again.",
			Validation: &Validation{Format: FormatPEMKey, MaxLength: 65536}},
		Field{Key: "helo_name", Label: "EHLO name", Type: FieldText, Group: "advanced", Placeholder: "mailos.bank.example",
			Help:       "The host name MailOS announces. Some relays accept mail only from a registered name. Default: localhost.",
			Validation: &Validation{Format: FormatHostname, MaxLength: 253}, lower: true},
	)
	fields = append(fields, senderFields(false)...)
	return TypeSchema{
		Type: KindSMTP, Label: "SMTP relay", Category: CategorySMTP,
		Description: "Any SMTP server: Exchange on-premises, Postfix, Microsoft 365, Google Workspace, or a sending service's SMTP endpoint.",
		Fields:      fields,
		Presets: []Preset{
			{ID: "exchange_onprem", Label: "Microsoft Exchange Server (on-premises)",
				Description: "A receive connector on your Exchange server. Enter its host; use a service account, or no authentication on an anonymous relay connector limited to MailOS's address.",
				Values:      map[string]any{"port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthLogin}},
			{ID: "m365_oauth", Label: "Microsoft 365 / Exchange Online (OAuth 2.0)",
				Description: "SMTP AUTH with an Entra ID application (XOAUTH2). SMTP AUTH must be enabled for the sending mailbox.",
				Values:      map[string]any{"host": "smtp.office365.com", "port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthXOAUTH2, "oauth_provider": OAuthMicrosoft}},
			{ID: "google_relay", Label: "Google Workspace SMTP relay",
				Description: "smtp-relay.gmail.com. Configure the SMTP relay service in the Google Admin console: allow MailOS's egress addresses, or require SMTP authentication and use a user's app password.",
				Values:      map[string]any{"host": "smtp-relay.gmail.com", "port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthNone}},
			{ID: "google_oauth", Label: "Google Workspace (OAuth 2.0)",
				Description: "smtp.gmail.com with a service account and domain-wide delegation (XOAUTH2), sending as one user.",
				Values:      map[string]any{"host": "smtp.gmail.com", "port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthXOAUTH2, "oauth_provider": OAuthGoogle}},
			{ID: "postfix", Label: "Postfix or Sendmail relay",
				Description: "An internal MTA that relays for MailOS's address. Port 25 with STARTTLS; add a password if the relay requires SASL.",
				Values:      map[string]any{"port": 25, "tls_mode": TLSStartTLS, "auth_mechanism": AuthNone}},
			{ID: "ses_smtp", Label: "Amazon SES SMTP",
				Description: "Change the region in the host to your SES region. The username and password are SES SMTP credentials, not IAM access keys.",
				Values:      map[string]any{"host": "email-smtp.eu-west-1.amazonaws.com", "port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthPlain}},
			{ID: "sendgrid_smtp", Label: "SendGrid SMTP",
				Description: "The username is the literal word apikey; the password is an API key with Mail Send access.",
				Values:      map[string]any{"host": "smtp.sendgrid.net", "port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthPlain, "username": "apikey"}},
			{ID: "mailgun_smtp", Label: "Mailgun SMTP",
				Description: "Use smtp.eu.mailgun.org for an EU domain. The credentials are the domain's SMTP user and password.",
				Values:      map[string]any{"host": "smtp.mailgun.org", "port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthPlain}},
			{ID: "oci_smtp", Label: "Oracle Cloud (OCI) Email Delivery",
				Description: "Change the region in the host to your tenancy's region. The credentials are OCI SMTP credentials generated for an IAM user.",
				Values:      map[string]any{"host": "smtp.email.uk-london-1.oci.oraclecloud.com", "port": 587, "tls_mode": TLSStartTLS, "auth_mechanism": AuthPlain}},
		},
	}
}

func msGraphSchema() TypeSchema {
	fields := []Field{
		{Key: "cloud", Label: "Microsoft cloud", Type: FieldSelect, Required: true, Default: CloudGlobal, Group: "connection",
			Options: []Option{{CloudGlobal, "Global (microsoft.com)"}, {CloudUSGov, "US Government GCC High"},
				{CloudUSGovDoD, "US Government DoD"}, {CloudChina, "China (operated by 21Vianet)"}}},
		{Key: "sender", Label: "Sending mailbox", Type: FieldEmail, Required: true, Group: "connection", Placeholder: "noreply@bank.example",
			Help:       "The user or shared mailbox mail is sent from. Limit the app to this mailbox with an Exchange Online application access policy or RBAC for Applications.",
			Validation: &Validation{Format: FormatEmail, MaxLength: 254}, lower: true},
	}
	fields = append(fields, microsoftFields()...)
	fields = append(fields, senderFields(true)...)
	return TypeSchema{
		Type: KindMSGraph, Label: "Microsoft 365 (Graph API)", Category: CategoryAPI, SPFInclude: "spf.protection.outlook.com",
		Description: "Exchange Online through Microsoft Graph sendMail, with an Entra ID application that has the Mail.Send application permission. Copies are kept in the mailbox's Sent Items.",
		Fields:      fields,
	}
}

func gmailSchema() TypeSchema {
	fields := []Field{
		{Key: "sender", Label: "Sending user", Type: FieldEmail, Required: true, Group: "connection", Placeholder: "noreply@bank.example",
			Help:       "The Google Workspace user the service account acts as. Mail is sent from this user's mailbox.",
			Validation: &Validation{Format: FormatEmail, MaxLength: 254}, lower: true},
		{Key: "service_account_json", Label: "Service account key (JSON)", Type: FieldFile, Required: true, Secret: true, Group: "authentication", Accept: ".json",
			Help:       "In the Google Admin console, grant the service account's client ID domain-wide delegation for the scope https://www.googleapis.com/auth/gmail.send, and enable the Gmail API in its project.",
			Validation: &Validation{Format: FormatJSON, MaxLength: 65536}},
	}
	fields = append(fields, senderFields(true)...)
	return TypeSchema{
		Type: KindGmail, Label: "Google Workspace (Gmail API)", Category: CategoryAPI, SPFInclude: "_spf.google.com",
		Description: "Gmail API with a service account and domain-wide delegation, sending as one Workspace user.",
		Fields:      fields,
	}
}

func acsSchema() TypeSchema {
	fields := []Field{
		{Key: "endpoint", Label: "Endpoint", Type: FieldURL, Required: true, Group: "connection",
			Placeholder: "https://contoso.unitedstates.communication.azure.com",
			Help:        "The Communication Services resource's endpoint, from Keys in the Azure portal.",
			Validation:  &Validation{Format: FormatHTTPSURL, MaxLength: 255}, lower: true},
		{Key: "access_key", Label: "Access key", Type: FieldPassword, Required: true, Secret: true, Group: "authentication",
			Help: "The resource's primary or secondary key.", Validation: &Validation{MaxLength: 1024}},
	}
	fields = append(fields, senderFields(false)...)
	fields[2].Help = "Used when a message names no sender. Must be a MailFrom address of a domain connected to the resource; the display name is set on the domain in Azure."
	return TypeSchema{
		Type: KindACS, Label: "Azure Communication Services Email", Category: CategoryAPI, SPFInclude: "spf.protection.outlook.com",
		Description: "Azure's email service, authenticated with the resource's access key (HMAC).",
		Fields:      fields,
	}
}

func sesSchema() TypeSchema {
	return TypeSchema{
		Type: KindSES, Label: "Amazon SES", Category: CategoryAPI, SPFInclude: "amazonses.com",
		Description: "Amazon Simple Email Service API v2, signed with an IAM user's access keys.",
		Fields: append([]Field{
			{Key: "region", Label: "Region", Type: FieldText, Required: true, Group: "connection", Placeholder: "eu-west-1",
				Help: "The AWS region where your identities are verified.", Validation: &Validation{Format: FormatAWSRegion, MaxLength: 32}, lower: true},
			{Key: "access_key_id", Label: "Access key ID", Type: FieldText, Required: true, Secret: true, Group: "authentication",
				Help: "Of an IAM user allowed ses:SendEmail (and ses:GetAccount for connection tests).", Placeholder: "AKIA…",
				Validation: &Validation{MaxLength: 128}},
			{Key: "secret_access_key", Label: "Secret access key", Type: FieldPassword, Required: true, Secret: true, Group: "authentication",
				Validation: &Validation{MaxLength: 256}},
			{Key: "configuration_set", Label: "Configuration set", Type: FieldText, Group: "advanced",
				Help: "Publishes delivery, bounce and complaint events.", Validation: &Validation{Format: FormatIdentifier, MaxLength: 64}},
		}, senderFields(false)...),
	}
}

func sendGridSchema() TypeSchema {
	return TypeSchema{
		Type: KindSendGrid, Label: "SendGrid", Category: CategoryAPI, SPFInclude: "sendgrid.net",
		Description: "Twilio SendGrid v3 Mail Send API.",
		Fields: append([]Field{
			{Key: "region", Label: "Data residency", Type: FieldSelect, Required: true, Default: RegionGlobal, Group: "connection",
				Help: "EU for an EU subuser (api.eu.sendgrid.com).", Options: []Option{{RegionGlobal, "Global"}, {RegionEU, "EU"}}},
			apiKey("API key", "An API key with Mail Send access.", "SG.…"),
		}, senderFields(false)...),
	}
}

func mailgunSchema() TypeSchema {
	return TypeSchema{
		Type: KindMailgun, Label: "Mailgun", Category: CategoryAPI, SPFInclude: "mailgun.org",
		Description: "Mailgun Messages API for one sending domain.",
		Fields: append([]Field{
			{Key: "domain", Label: "Sending domain", Type: FieldText, Required: true, Group: "connection", Placeholder: "mg.bank.example",
				Validation: &Validation{Format: FormatHostname, MaxLength: 253}, lower: true},
			{Key: "region", Label: "Region", Type: FieldSelect, Required: true, Default: RegionUS, Group: "connection",
				Help: "The region the domain was created in.", Options: []Option{{RegionUS, "US (api.mailgun.net)"}, {RegionEU, "EU (api.eu.mailgun.net)"}}},
			apiKey("API key", "The account's private API key or the domain's sending key.", "key-…"),
		}, senderFields(false)...),
	}
}

func postmarkSchema() TypeSchema {
	return TypeSchema{
		Type: KindPostmark, Label: "Postmark", Category: CategoryAPI, SPFInclude: "spf.mtasv.net",
		Description: "Postmark Email API for one server.",
		Fields: append([]Field{
			{Key: "server_token", Label: "Server API token", Type: FieldPassword, Required: true, Secret: true, Group: "authentication",
				Validation: &Validation{MaxLength: 256}},
			{Key: "message_stream", Label: "Message stream", Type: FieldText, Default: postmarkDefaultStream, Group: "advanced",
				Help: "A transactional stream; outbound is the default.", Validation: &Validation{Format: FormatIdentifier, MaxLength: 64}},
		}, senderFields(false)...),
	}
}

func sparkPostSchema() TypeSchema {
	return TypeSchema{
		Type: KindSparkPost, Label: "SparkPost", Category: CategoryAPI, SPFInclude: "sparkpostmail.com",
		Description: "SparkPost (Bird) Transmissions API.",
		Fields: append([]Field{
			{Key: "region", Label: "Region", Type: FieldSelect, Required: true, Default: RegionUS, Group: "connection",
				Options: []Option{{RegionUS, "US (api.sparkpost.com)"}, {RegionEU, "EU (api.eu.sparkpost.com)"}}},
			apiKey("API key", "An API key with Transmissions: Read/Write (and Account: Read for connection tests).", ""),
		}, senderFields(false)...),
	}
}

func brevoSchema() TypeSchema {
	return TypeSchema{
		Type: KindBrevo, Label: "Brevo", Category: CategoryAPI, SPFInclude: "spf.brevo.com",
		Description: "Brevo (formerly Sendinblue) transactional email API.",
		Fields: append([]Field{
			apiKey("API key", "A v3 API key. If Brevo restricts API keys to authorised IPs, add MailOS's egress addresses.", "xkeysib-…"),
		}, senderFields(false)...),
	}
}

func mailjetSchema() TypeSchema {
	return TypeSchema{
		Type: KindMailjet, Label: "Mailjet", Category: CategoryAPI, SPFInclude: "spf.mailjet.com",
		Description: "Mailjet Send API v3.1.",
		Fields: append([]Field{
			apiKey("API key", "The public API key.", ""),
			{Key: "api_secret", Label: "Secret key", Type: FieldPassword, Required: true, Secret: true, Group: "authentication",
				Validation: &Validation{MaxLength: 256}},
		}, senderFields(false)...),
	}
}

func mandrillSchema() TypeSchema {
	return TypeSchema{
		Type: KindMandrill, Label: "Mandrill (Mailchimp Transactional)", Category: CategoryAPI, SPFInclude: "spf.mandrillapp.com",
		Description: "Mailchimp Transactional (Mandrill) messages API.",
		Fields: append([]Field{
			apiKey("API key", "A Mandrill API key (not a Mailchimp marketing key).", ""),
			{Key: "subaccount", Label: "Subaccount", Type: FieldText, Group: "advanced",
				Help: "Sends through this subaccount's reputation and quota.", Validation: &Validation{MaxLength: 255}},
		}, senderFields(false)...),
	}
}

func resendSchema() TypeSchema {
	return TypeSchema{
		Type: KindResend, Label: "Resend", Category: CategoryAPI,
		Description: "Resend email API.",
		Fields: append([]Field{
			apiKey("API key", "A key with sending access. A full-access key also lets connection tests list domains.", "re_…"),
		}, senderFields(false)...),
	}
}
