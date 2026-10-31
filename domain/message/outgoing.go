package message

import (
	"fmt"
	"net/mail"
	"slices"
	"strings"

	"github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
)

// Address is a mailbox with an optional display name.
type Address struct {
	Name  string
	Email string
}

// String formats the address for a header, encoding a non-ASCII name
// (RFC 2047) and quoting it when needed.
func (a Address) String() string {
	return (&mail.Address{Name: a.Name, Address: a.Email}).String()
}

// IsZero reports whether no address is set.
func (a Address) IsZero() bool { return a.Email == "" }

// Outgoing is what a provider sends: one rendered message to one
// recipient. TenantID routes it and is never sent.
type Outgoing struct {
	TenantID string
	// MessageID is the MailOS message id. Providers carry it as metadata
	// so their webhooks can be matched; SMTP puts it in Message-ID.
	MessageID string
	From      Address
	To        Address
	ReplyTo   Address
	Subject   string
	HTML      string
	Text      string
	// Headers are extra headers (List-Unsubscribe, X-…). Structural
	// headers are refused: see ReservedHeader.
	Headers map[string]string
	Tags    []string
	// DKIM, when set, is the verified sending domain's key; the SMTP
	// sender signs with it (HTTP APIs sign with the domain configured at
	// the provider).
	DKIM *sendingdomain.SigningKey
}

// reserved are headers the senders set themselves; a caller setting them
// could forge the sender, add recipients or break the MIME structure.
var reserved = []string{
	"bcc", "cc", "content-transfer-encoding", "content-type", "date", "dkim-signature", "from",
	"message-id", "mime-version", "received", "reply-to", "return-path", "sender", "subject", "to",
}

// ReservedHeader reports whether a caller may not set the header.
func ReservedHeader(name string) bool {
	n := strings.ToLower(name)
	return slices.Contains(reserved, n) || strings.HasPrefix(n, "content-")
}

// maxHeaderValue is the longest header value accepted (RFC 5322 §2.1.1
// line limit, before folding).
const maxHeaderValue = 998

// Validate checks that the message can be sent. Errors are permanent
// (ReasonInvalid) send errors: retrying cannot fix them.
func (o *Outgoing) Validate() error {
	invalid := func(format string, args ...any) error {
		return NewSendError("", ReasonInvalid, 0, fmt.Sprintf(format, args...))
	}
	if !provider.ValidEmail(o.From.Email) {
		return invalid("the sender address is not valid")
	}
	if !provider.ValidEmail(o.To.Email) {
		return &SendError{Reason: ReasonInvalidRecipient, Detail: "the recipient address is not valid"}
	}
	if !o.ReplyTo.IsZero() && !provider.ValidEmail(o.ReplyTo.Email) {
		return invalid("the reply-to address is not valid")
	}
	for _, s := range []string{o.From.Name, o.To.Name, o.ReplyTo.Name, o.Subject} {
		if strings.ContainsAny(s, "\r\n\x00") {
			return invalid("names and the subject must be one line")
		}
	}
	if len(o.Subject) > MaxSubjectLen {
		return invalid("the subject is too long")
	}
	if strings.TrimSpace(o.Subject) == "" {
		return invalid("the subject is empty")
	}
	if o.HTML == "" && o.Text == "" {
		return invalid("the message has no body")
	}
	for k, v := range o.Headers {
		if !headerName(k) {
			return invalid("header name %q is not valid", k)
		}
		if ReservedHeader(k) {
			return invalid("header %s cannot be set", k)
		}
		if strings.ContainsAny(v, "\r\n\x00") || len(v) > maxHeaderValue {
			return invalid("header %s must be one line of at most %d characters", k, maxHeaderValue)
		}
	}
	return nil
}

// headerName accepts RFC 5322 field names: printable ASCII except colon.
func headerName(s string) bool {
	if s == "" || len(s) > 76 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 33 || c > 126 || c == ':' {
			return false
		}
	}
	return true
}

// WithDefaultFrom returns o with the sender filled from a provider's
// default when the message names none.
func (o Outgoing) WithDefaultFrom(from Address) Outgoing {
	if o.From.Email == "" {
		o.From.Email = from.Email
		if o.From.Name == "" {
			o.From.Name = from.Name
		}
	}
	return o
}
