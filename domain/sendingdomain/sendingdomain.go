// Package sendingdomain is a tenant's sending domains: the DNS records it
// publishes so receivers accept mail From that domain (DKIM, RFC 6376;
// SPF, RFC 7208; DMARC, RFC 7489), and the DKIM key MailOS signs with.
//
// The DKIM private key is a secret kept apart from the entity in Secrets:
// the repository seals it with the key manager (contract §6) and only the
// sending path opens it, through SigningKey.
package sendingdomain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Status is where the domain is in verification.
type Status string

// Domain statuses.
const (
	// StatusPending: records not found yet (or not checked).
	StatusPending Status = "pending"
	// StatusVerified: DKIM and SPF records found as expected. Only a
	// verified domain signs mail.
	StatusVerified Status = "verified"
	// StatusFailed: a check found records that do not match, such as an
	// old DKIM key.
	StatusFailed Status = "failed"
)

// Valid reports whether s is known.
func (s Status) Valid() bool {
	return s == StatusPending || s == StatusVerified || s == StatusFailed
}

// DMARC policies (RFC 7489 §6.3 p=).
const (
	DMARCNone       = "none"
	DMARCQuarantine = "quarantine"
	DMARCReject     = "reject"
)

// DefaultSelector is the DKIM selector when the tenant names none.
const DefaultSelector = "mailos"

// DKIMKeyBits is the RSA key size: 2048 bits (RFC 8301 §3.2 requires at
// least 1024 and recommends 2048).
const DKIMKeyBits = 2048

// Domain is one of a tenant's sending domains.
type Domain struct {
	ID string
	// OrgID is the IAM tenant (column org_id).
	OrgID string
	// Name is the domain, lowercase, without a trailing dot.
	Name string
	// DKIMSelector names the key: the record is at
	// <selector>._domainkey.<name>.
	DKIMSelector string
	// DKIMPublicKey is the base64 DER SubjectPublicKeyInfo published as p=.
	DKIMPublicKey string
	// SPFRecord and DMARCRecord are the TXT values to publish.
	SPFRecord   string
	DMARCRecord string
	Status      Status
	// LastCheckedAt is the last DNS check; FailureReason says what it
	// found wrong ("" when verified).
	LastCheckedAt *time.Time
	FailureReason string
	VerifiedAt    *time.Time
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Secrets is the domain's sealed material.
type Secrets struct {
	// DKIMPrivateKeyPEM is the PKCS #8 RSA private key.
	DKIMPrivateKeyPEM string `json:"dkim_private_key_pem"`
}

const redacted = "[REDACTED]"

// String keeps the key out of logs.
func (Secrets) String() string { return redacted }

// GoString keeps the key out of %#v.
func (Secrets) GoString() string { return redacted }

// Options set the records a new domain publishes.
type Options struct {
	// Selector is the DKIM selector (DefaultSelector when empty).
	Selector string
	// SPFIncludes are the include: mechanisms for the providers the tenant
	// sends through (provider.Kind.SPFInclude) and the platform relay.
	SPFIncludes []string
	// DMARCPolicy is none (default), quarantine or reject.
	DMARCPolicy string
	// DMARCReportTo is the aggregate report address (rua), if any.
	DMARCReportTo string
}

// New validates name and opts, generates a DKIM key and returns a pending
// domain with its secrets.
func New(orgID, name string, opts Options, now time.Time) (*Domain, Secrets, error) {
	name = NormalizeName(name)
	if opts.Selector == "" {
		opts.Selector = DefaultSelector
	}
	opts.Selector = strings.ToLower(strings.TrimSpace(opts.Selector))
	if opts.DMARCPolicy == "" {
		opts.DMARCPolicy = DMARCNone
	}
	var errs []apperrors.FieldError
	if err := ValidateName(name); err != nil {
		errs = append(errs, apperrors.DetailsOf(err)...)
	}
	if !validLabel(opts.Selector) {
		errs = append(errs, apperrors.FieldError{Field: "dkim_selector", Code: "invalid", Message: "selector must be one DNS label"})
	}
	for _, inc := range opts.SPFIncludes {
		if inc = strings.ToLower(strings.TrimSpace(inc)); inc != "" && !validName(inc) {
			errs = append(errs, apperrors.FieldError{Field: "spf_includes", Code: "invalid", Message: "SPF include " + inc + " is not a domain"})
		}
	}
	switch opts.DMARCPolicy {
	case DMARCNone, DMARCQuarantine, DMARCReject:
	default:
		errs = append(errs, apperrors.FieldError{Field: "dmarc_policy", Code: "invalid", Message: "DMARC policy must be none, quarantine or reject"})
	}
	if opts.DMARCReportTo != "" && (strings.ContainsAny(opts.DMARCReportTo, ";,! \t\r\n") || !strings.Contains(opts.DMARCReportTo, "@")) {
		errs = append(errs, apperrors.FieldError{Field: "dmarc_report_to", Code: "invalid", Message: "DMARC report address is not an email address"})
	}
	if len(errs) > 0 {
		return nil, Secrets{}, apperrors.Validation(errs...)
	}
	privPEM, pub, err := GenerateDKIMKey()
	if err != nil {
		return nil, Secrets{}, err
	}
	d := &Domain{
		OrgID:         orgID,
		Name:          name,
		DKIMSelector:  opts.Selector,
		DKIMPublicKey: pub,
		SPFRecord:     SPFRecord(opts.SPFIncludes),
		DMARCRecord:   DMARCRecord(opts.DMARCPolicy, opts.DMARCReportTo),
		Status:        StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	return d, Secrets{DKIMPrivateKeyPEM: privPEM}, nil
}

// RotateDKIM replaces the key under a new selector. The domain goes back
// to pending until the new record is published.
func (d *Domain) RotateDKIM(selector string, now time.Time) (Secrets, error) {
	selector = strings.ToLower(strings.TrimSpace(selector))
	if !validLabel(selector) || selector == d.DKIMSelector {
		return Secrets{}, apperrors.Invalid("dkim_selector", "invalid", "the new selector must be one DNS label different from the current one")
	}
	privPEM, pub, err := GenerateDKIMKey()
	if err != nil {
		return Secrets{}, err
	}
	d.DKIMSelector = selector
	d.DKIMPublicKey = pub
	d.Status = StatusPending
	d.VerifiedAt = nil
	d.FailureReason = ""
	d.UpdatedAt = now
	return Secrets{DKIMPrivateKeyPEM: privPEM}, nil
}

// GenerateDKIMKey returns a new RSA 2048 key as PKCS #8 PEM and its public
// half as the base64 DER SubjectPublicKeyInfo for the p= tag.
func GenerateDKIMKey() (privatePEM, publicKey string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, DKIMKeyBits)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return privatePEM, base64.StdEncoding.EncodeToString(pubDER), nil
}

// ErrInvalidKey is returned for a DKIM key that is not an RSA key of at
// least 2048 bits in PEM.
var ErrInvalidKey = errors.New("the DKIM private key is not a PEM RSA key of at least 2048 bits")

// ParsePrivateKey reads a PKCS #8 or PKCS #1 PEM RSA key.
func ParsePrivateKey(privatePEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil, ErrInvalidKey
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidKey
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidKey
		}
		key = rk
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidKey
		}
		key = k
	default:
		return nil, ErrInvalidKey
	}
	if key.N.BitLen() < DKIMKeyBits {
		return nil, ErrInvalidKey
	}
	return key, nil
}

// SPFRecord builds "v=spf1 include:… ~all". Soft fail (~all) lets the
// tenant add senders the platform does not know about; DMARC enforces.
func SPFRecord(includes []string) string {
	var b strings.Builder
	b.WriteString("v=spf1")
	seen := map[string]bool{}
	for _, inc := range includes {
		inc = strings.ToLower(strings.TrimSpace(inc))
		if inc == "" || seen[inc] {
			continue
		}
		seen[inc] = true
		b.WriteString(" include:" + inc)
	}
	b.WriteString(" ~all")
	return b.String()
}

// DMARCRecord builds the _dmarc TXT value with relaxed alignment.
func DMARCRecord(policy, reportTo string) string {
	r := "v=DMARC1; p=" + policy + "; adkim=r; aspf=r"
	if reportTo != "" {
		r += "; rua=mailto:" + reportTo
	}
	return r
}

// RecordType is a DNS record type.
type RecordType string

// TXT is the only type the domain publishes.
const TXT RecordType = "TXT"

// Record is one DNS record the tenant publishes.
type Record struct {
	Purpose string     `json:"purpose"` // dkim, spf, dmarc
	Type    RecordType `json:"type"`
	Name    string     `json:"name"`
	Value   string     `json:"value"`
}

// DKIMRecordName is <selector>._domainkey.<domain>.
func (d *Domain) DKIMRecordName() string { return d.DKIMSelector + "._domainkey." + d.Name }

// DKIMRecordValue is the DKIM key record (RFC 6376 §3.6.1).
func (d *Domain) DKIMRecordValue() string { return "v=DKIM1; k=rsa; p=" + d.DKIMPublicKey }

// DMARCRecordName is _dmarc.<domain>.
func (d *Domain) DMARCRecordName() string { return "_dmarc." + d.Name }

// Records lists the records to publish.
func (d *Domain) Records() []Record {
	return []Record{
		{Purpose: "dkim", Type: TXT, Name: d.DKIMRecordName(), Value: d.DKIMRecordValue()},
		{Purpose: "spf", Type: TXT, Name: d.Name, Value: d.SPFRecord},
		{Purpose: "dmarc", Type: TXT, Name: d.DMARCRecordName(), Value: d.DMARCRecord},
	}
}

// Check is the outcome of one DNS check.
type Check struct {
	DKIM  bool `json:"dkim"`
	SPF   bool `json:"spf"`
	DMARC bool `json:"dmarc"`
	// Reason says what is missing, for the console.
	Reason string `json:"reason,omitempty"`
}

// Verified reports whether the check passes: DKIM and SPF must match;
// DMARC is recommended and does not block.
func (c Check) Verified() bool { return c.DKIM && c.SPF }

// Evaluate compares the TXT values found at the DKIM name, the domain and
// the DMARC name with the expected records. Resolving is the caller's
// (infrastructure) job; a lookup that failed passes nil.
func (d *Domain) Evaluate(dkimTXT, domainTXT, dmarcTXT []string) Check {
	var c Check
	for _, v := range dkimTXT {
		if tagValue(v, "p") == d.DKIMPublicKey && d.DKIMPublicKey != "" {
			c.DKIM = true
		}
	}
	required := strings.Fields(d.SPFRecord)
	for _, v := range domainTXT {
		got := strings.Fields(strings.ToLower(v))
		if len(got) == 0 || got[0] != "v=spf1" {
			continue
		}
		c.SPF = true
		for _, m := range required {
			if strings.HasPrefix(m, "include:") && !slices.Contains(got, m) {
				c.SPF = false
			}
		}
	}
	for _, v := range dmarcTXT {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(v)), "V=DMARC1") {
			c.DMARC = true
		}
	}
	var missing []string
	if !c.DKIM {
		missing = append(missing, "the DKIM record at "+d.DKIMRecordName()+" is missing or has another key")
	}
	if !c.SPF {
		missing = append(missing, "the SPF record at "+d.Name+" is missing or lacks the required includes")
	}
	c.Reason = strings.Join(missing, "; ")
	return c
}

// ApplyCheck records a check. A domain that fails after being verified
// becomes failed (its records changed); one never verified stays pending.
func (d *Domain) ApplyCheck(c Check, now time.Time) {
	d.LastCheckedAt = &now
	d.UpdatedAt = now
	if c.Verified() {
		if d.Status != StatusVerified {
			d.VerifiedAt = &now
		}
		d.Status = StatusVerified
		d.FailureReason = ""
		return
	}
	d.FailureReason = c.Reason
	if d.Status == StatusVerified || d.Status == StatusFailed {
		d.Status = StatusFailed
	}
}

// SigningKey is what the SMTP sender needs to DKIM-sign mail From the
// domain.
type SigningKey struct {
	Domain        string
	Selector      string
	PrivateKeyPEM string
}

// String keeps the key out of logs.
func (k SigningKey) String() string { return "dkim:" + k.Selector + "._domainkey." + k.Domain }

// GoString keeps the key out of %#v.
func (k SigningKey) GoString() string { return k.String() }

// SigningKey returns the key to sign with, only for a verified domain that
// has one.
func (d *Domain) SigningKey(s Secrets) (SigningKey, bool) {
	if d.Status != StatusVerified || s.DKIMPrivateKeyPEM == "" {
		return SigningKey{}, false
	}
	return SigningKey{Domain: d.Name, Selector: d.DKIMSelector, PrivateKeyPEM: s.DKIMPrivateKeyPEM}, true
}

// NormalizeName lowercases name and drops a trailing dot.
func NormalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ValidateName accepts a DNS name of two or more labels (ASCII; IDNs in
// their xn-- form).
func ValidateName(name string) error {
	if !validName(name) || !strings.Contains(name, ".") || net.ParseIP(name) != nil {
		return apperrors.Invalid("name", "invalid", "name must be a domain such as mail.example.com")
	}
	return nil
}

// FromDomain returns the domain part of an address, normalised.
func FromDomain(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ""
	}
	return NormalizeName(address[at+1:])
}

func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// tagValue reads one tag of a tag=value; list (RFC 6376 §3.2), ignoring
// whitespace inside the value (long keys are split across strings).
func tagValue(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.TrimSpace(k) == tag {
			return strings.Join(strings.Fields(v), "")
		}
	}
	return ""
}
