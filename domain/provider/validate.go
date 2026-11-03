package provider

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Map returns the set settings by key (numbers as float64).
func (s Settings) Map() map[string]any {
	raw, _ := json.Marshal(s)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func settingsFrom(m map[string]any) Settings {
	var s Settings
	raw, _ := json.Marshal(m)
	_ = json.Unmarshal(raw, &s)
	return s
}

// str is a setting's value as the conditions compare it.
func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// visible reports whether all of f's conditions hold for settings m.
func visible(f Field, m map[string]any) bool {
	for _, c := range f.VisibleWhen {
		if !slices.Contains(c.In, str(m[c.Field])) {
			return false
		}
	}
	return true
}

// Normalize trims the provider's text, lower-cases the fields that are
// case-insensitive, fills select defaults, and drops settings that do not
// apply with the provider's other settings (an SMTP password field after
// switching to no authentication). Keys the kind does not know are left
// for Validate to refuse. Weight is left alone: 0 is a choice (standby),
// so the create path applies DefaultWeight itself.
func (p *Provider) Normalize() {
	p.Name = strings.TrimSpace(p.Name)
	t, ok := schemaOf(p.Kind)
	if !ok {
		return
	}
	m := p.Settings.Map()
	for _, f := range t.Fields {
		if f.Secret {
			continue
		}
		if !visible(f, m) {
			delete(m, f.Key)
			continue
		}
		if s, isString := m[f.Key].(string); isString {
			s = strings.TrimSpace(s)
			if f.lower {
				s = strings.ToLower(s)
			}
			if f.Key == "endpoint" {
				s = strings.TrimSuffix(s, "/")
			}
			m[f.Key] = s
			if s == "" {
				delete(m, f.Key)
			}
		}
		if _, set := m[f.Key]; !set && f.Type == FieldSelect && f.Default != nil {
			m[f.Key] = f.Default
		}
	}
	if pr, isString := m["preset"].(string); isString {
		m["preset"] = strings.TrimSpace(pr)
	}
	p.Settings = settingsFrom(m)
}

// fieldErrors collects one 422's details.
type fieldErrors []apperrors.FieldError

func (e *fieldErrors) add(field, code, msg string) {
	*e = append(*e, apperrors.FieldError{Field: field, Code: code, Message: msg})
}

// Validate checks the provider and its settings against its kind's schema.
// Plaintext SMTP (tls_mode none) is accepted only when allowPlaintext is
// true. Failures are one 422 with an entry per field.
func (p *Provider) Validate(allowPlaintext bool) error {
	var errs fieldErrors
	switch {
	case p.Name == "":
		errs.add("name", "required", "name is required")
	case len(p.Name) > MaxNameLen:
		errs.add("name", "too_long", "name must be at most 255 characters")
	}
	if p.Priority < 0 || p.Priority > MaxPriority {
		errs.add("priority", "out_of_range", "priority must be between 0 and 100")
	}
	if p.Weight < 0 || p.Weight > MaxWeight {
		errs.add("weight", "out_of_range", "weight must be between 0 and 1000")
	}
	if p.DailyLimit < 0 {
		errs.add("daily_limit", "out_of_range", "daily limit must not be negative")
	}
	t, ok := schemaOf(p.Kind)
	if !ok {
		errs.add("kind", "invalid", "kind must be one of "+kindList())
	} else {
		errs = append(errs, p.Settings.validate(t, allowPlaintext)...)
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

func kindList() string {
	s := make([]string, len(Kinds))
	for i, k := range Kinds {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

func (s Settings) validate(t TypeSchema, allowPlaintext bool) fieldErrors {
	var errs fieldErrors
	m := s.Map()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if k == "preset" {
			if pr := str(m[k]); pr != PresetCustom && !slices.ContainsFunc(t.Presets, func(p Preset) bool { return p.ID == pr }) {
				errs.add("settings.preset", "invalid", "preset is not one of this kind's presets")
			}
			continue
		}
		// A field the kind does not use must be empty, so a stale setting
		// cannot change behaviour after the kind changes.
		if f, ok := t.Field(k); !ok || f.Secret {
			errs.add("settings."+k, "not_allowed", k+" does not apply to "+string(t.Type)+" providers")
		}
	}
	for _, f := range t.Fields {
		if f.Secret || !visible(f, m) {
			continue
		}
		v, set := m[f.Key]
		if !set || str(v) == "" {
			if f.Required {
				errs.add("settings."+f.Key, "required", f.Label+" is required")
			}
			continue
		}
		if code, msg := checkValue(f, v); code != "" {
			errs.add("settings."+f.Key, code, msg)
		}
	}
	switch t.Type {
	case KindSMTP:
		if s.TLSMode == TLSNone && !allowPlaintext {
			errs.add("settings.tls_mode", "plaintext_refused", "plaintext SMTP is refused outside local and test")
		}
	case KindACS:
		if s.Endpoint != "" && !ACSEndpointAllowed(s.Endpoint) {
			errs.add("settings.endpoint", "invalid", "endpoint must be an Azure Communication Services endpoint (https://<resource>.communication.azure.com)")
		}
	}
	return errs
}

// ACSEndpointAllowed reports whether u is an Azure Communication Services
// endpoint, so the access key is only ever sent to Azure.
func ACSEndpointAllowed(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme != "https" || parsed.Port() != "" {
		return false
	}
	host := parsed.Hostname()
	for _, suffix := range []string{".communication.azure.com", ".communication.azure.us", ".communication.azure.cn"} {
		if strings.HasSuffix(host, suffix) && ValidHost(host) {
			return true
		}
	}
	return false
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// checkValue checks one set value against its field; it returns the error
// code and message, or "".
func checkValue(f Field, v any) (code, msg string) {
	if f.Type == FieldNumber {
		n, ok := v.(float64)
		if !ok || n != math.Trunc(n) {
			return "invalid", f.Label + " must be a whole number"
		}
		if r := f.Validation; r != nil && (r.Min != nil && n < float64(*r.Min) || r.Max != nil && n > float64(*r.Max)) {
			return "out_of_range", f.Label + " is out of range"
		}
		return "", ""
	}
	if f.Type == FieldBoolean {
		if _, ok := v.(bool); !ok {
			return "invalid", f.Label + " must be true or false"
		}
		return "", ""
	}
	s, ok := v.(string)
	if !ok {
		return "invalid", f.Label + " must be text"
	}
	if f.Type == FieldSelect {
		if !slices.ContainsFunc(f.Options, func(o Option) bool { return o.Value == s }) {
			return "invalid", f.Label + " is not one of the allowed values"
		}
		return "", ""
	}
	multiline := f.Type == FieldFile || f.Type == FieldTextarea
	if !multiline && strings.ContainsAny(s, "\r\n") {
		return "invalid", f.Label + " must be one line"
	}
	r := f.Validation
	if r == nil {
		return "", ""
	}
	if r.MaxLength > 0 && len(s) > r.MaxLength {
		return "too_long", f.Label + " must be at most " + strconv.Itoa(r.MaxLength) + " characters"
	}
	if r.Pattern != "" {
		if re, err := regexp.Compile(r.Pattern); err == nil && !re.MatchString(s) {
			return "invalid", f.Label + " " + r.PatternMessage
		}
	}
	if !formatOK(r.Format, s) {
		return "invalid", f.Label + " " + formatMessage[r.Format]
	}
	return "", ""
}

var formatMessage = map[string]string{
	FormatEmail:      "must be an email address",
	FormatHostname:   "must be a DNS name or IP address",
	FormatAWSRegion:  "must be an AWS region such as eu-west-1",
	FormatHTTPSURL:   "must be an https URL without a path",
	FormatUUID:       "must be a GUID",
	FormatPEMCert:    "must be one or more PEM certificates",
	FormatPEMKey:     "must be an unencrypted PEM private key",
	FormatJSON:       "must be JSON",
	FormatEntraID:    "must be a GUID or a domain name",
	FormatIdentifier: "must be letters, digits, '-' and '_'",
}

func formatOK(format, s string) bool {
	switch format {
	case "":
		return true
	case FormatEmail:
		return ValidEmail(s)
	case FormatHostname:
		return ValidHost(s)
	case FormatAWSRegion:
		return validRegion(s)
	case FormatHTTPSURL:
		u, err := url.Parse(s)
		return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
	case FormatUUID:
		return uuidRE.MatchString(s)
	case FormatEntraID:
		return uuidRE.MatchString(s) || (strings.Contains(s, ".") && ValidHost(s))
	case FormatPEMCert:
		_, err := ParseCertificates(s)
		return err == nil
	case FormatPEMKey:
		_, err := ParsePrivateKey(s)
		return err == nil
	case FormatJSON:
		return json.Valid([]byte(s))
	case FormatIdentifier:
		return validToken(s, 64)
	}
	return false
}

// ParseCertificates reads every certificate of a PEM bundle; it fails when
// there is none or one does not parse.
func ParseCertificates(s string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errNoPEM
	}
	return out, nil
}

// ParsePrivateKey reads an unencrypted PKCS#1, PKCS#8 or SEC 1 PEM key.
func ParsePrivateKey(s string) (any, error) {
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, errNoPEM
		}
		switch b.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(b.Bytes)
		case "PRIVATE KEY":
			return x509.ParsePKCS8PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(b.Bytes)
		}
	}
}

type pemError string

func (e pemError) Error() string { return string(e) }

const errNoPEM = pemError("no PEM data")

// ServiceAccount is the part of a Google service account key file MailOS
// uses.
type ServiceAccount struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`
}

// GoogleTokenURI is the only token endpoint a service account assertion
// is sent to.
const GoogleTokenURI = "https://oauth2.googleapis.com/token"

// ParseServiceAccount reads and checks a key file.
func ParseServiceAccount(s string) (ServiceAccount, string) {
	var a ServiceAccount
	if err := json.Unmarshal([]byte(s), &a); err != nil {
		return a, "is not a service account key file (JSON)"
	}
	switch {
	case a.Type != "service_account":
		return a, "is not a service account key (type must be service_account)"
	case !ValidEmail(a.ClientEmail):
		return a, "has no client_email"
	case a.PrivateKey == "":
		return a, "has no private_key"
	case a.TokenURI != "" && a.TokenURI != GoogleTokenURI:
		return a, "has an unexpected token_uri"
	}
	if _, err := ParsePrivateKey(a.PrivateKey); err != nil {
		return a, "has a private_key that cannot be read"
	}
	return a, ""
}

// PruneCredentials drops the secrets that do not apply with settings s
// (a password after switching to OAuth), so they are not kept sealed.
func PruneCredentials(kind Kind, s Settings, c Credentials) Credentials {
	t, ok := schemaOf(kind)
	if !ok {
		return c
	}
	m := s.Map()
	cm := c.Map()
	for k := range cm {
		if f, ok := t.Field(k); !ok || !f.Secret || !visible(f, m) {
			delete(cm, k)
		}
	}
	return CredentialsFrom(cm)
}

// ValidateCredentials checks that c has what kind needs with settings s
// and nothing it does not.
func ValidateCredentials(kind Kind, s Settings, c Credentials) error {
	t, ok := schemaOf(kind)
	if !ok {
		return apperrors.Invalid("kind", "invalid", "kind must be one of "+kindList())
	}
	var errs fieldErrors
	m := s.Map()
	cm := c.Map()
	keys := make([]string, 0, len(cm))
	for k := range cm {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		f, ok := t.Field(k)
		switch {
		case !ok || !f.Secret:
			errs.add("credentials."+k, "not_allowed", k+" does not apply to "+string(kind)+" providers")
		case !visible(f, m):
			errs.add("credentials."+k, "not_allowed", k+" does not apply with these settings")
		}
	}
	for _, f := range t.Fields {
		if !f.Secret || !visible(f, m) {
			continue
		}
		v := cm[f.Key]
		if v == "" {
			if f.Required {
				errs.add("credentials."+f.Key, "required", f.Label+" is required")
			}
			continue
		}
		if code, msg := checkValue(f, v); code != "" {
			errs.add("credentials."+f.Key, code, msg)
		}
	}
	if c.ServiceAccountJSON != "" {
		if _, problem := ParseServiceAccount(c.ServiceAccountJSON); problem != "" {
			errs.add("credentials.service_account_json", "invalid", "the key file "+problem)
		}
	}
	if kind == KindSMTP {
		switch {
		case s.ClientCert != "" && c.ClientKey == "":
			errs.add("credentials.client_key", "required", "a client certificate needs its private key")
		case s.ClientCert == "" && c.ClientKey != "":
			errs.add("settings.client_cert", "required", "a client private key needs its certificate")
		}
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

// DecodeSettings reads the console's settings object: every key must be a
// setting of some kind, numbers must be numbers and the rest text. Which
// keys the provider's kind takes is Validate's job.
func DecodeSettings(raw map[string]any) (Settings, error) {
	var errs fieldErrors
	for k, v := range raw {
		f, known := anyField(k, false)
		switch {
		case k == "preset":
			if _, ok := v.(string); !ok && v != nil {
				errs.add("settings.preset", "invalid", "preset must be text")
			}
		case !known:
			errs.add("settings."+k, "unknown", k+" is not a provider setting")
		case v == nil:
		case f.Type == FieldNumber:
			if _, ok := v.(float64); !ok {
				errs.add("settings."+k, "invalid", f.Label+" must be a number")
			}
		case f.Type == FieldBoolean:
			if _, ok := v.(bool); !ok {
				errs.add("settings."+k, "invalid", f.Label+" must be true or false")
			}
		default:
			if _, ok := v.(string); !ok {
				errs.add("settings."+k, "invalid", f.Label+" must be text")
			}
		}
	}
	if len(errs) > 0 {
		return Settings{}, apperrors.Validation(errs...)
	}
	return settingsFrom(raw), nil
}

// DecodeCredentials reads the console's credentials object: every key must
// be a credential of some kind, and every value text.
func DecodeCredentials(raw map[string]any) (Credentials, error) {
	var errs fieldErrors
	out := map[string]string{}
	for k, v := range raw {
		if _, known := anyField(k, true); !known {
			errs.add("credentials."+k, "unknown", k+" is not a provider credential")
			continue
		}
		switch x := v.(type) {
		case nil:
		case string:
			out[k] = x
		default:
			errs.add("credentials."+k, "invalid", k+" must be text")
		}
	}
	if len(errs) > 0 {
		return Credentials{}, apperrors.Validation(errs...)
	}
	return CredentialsFrom(out), nil
}

// anyField finds key among every kind's settings (secret false) or
// credentials (secret true).
func anyField(key string, secret bool) (Field, bool) {
	for _, k := range Kinds {
		t, _ := schemaOf(k)
		if f, ok := t.Field(key); ok && f.Secret == secret {
			return f, true
		}
	}
	return Field{}, false
}
