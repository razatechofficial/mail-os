// Package webhook is a tenant's outbound webhooks: HTTPS endpoints MailOS
// posts message events to, each request signed with the endpoint's secret
// (HMAC-SHA256 over the timestamp and body, Stripe-style), so the receiver
// can check origin and freshness. The secret is sealed at rest.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Message events a webhook may subscribe to (the console's WEBHOOK_EVENTS).
const (
	EventSent       = "message.sent"
	EventDelivered  = "message.delivered"
	EventBounced    = "message.bounced"
	EventComplained = "message.complained"
	EventOpened     = "message.opened"
	EventClicked    = "message.clicked"
	EventFailed     = "message.failed"
)

// Events lists every event.
var Events = []string{EventSent, EventDelivered, EventBounced, EventComplained, EventOpened, EventClicked, EventFailed}

// Limits.
const (
	MaxURLLen       = 2048
	MinSecretLen    = 16
	MaxSecretLen    = 128
	SignatureHeader = "X-MailOS-Signature"
	EventHeader     = "X-MailOS-Event"
	DeliveryHeader  = "X-MailOS-Delivery"
)

// Webhook is one endpoint.
type Webhook struct {
	ID        string
	OrgID     string
	URL       string
	Events    []string
	Active    bool
	CreatedBy string
	UpdatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Subscribes reports whether the webhook wants event.
func (w Webhook) Subscribes(event string) bool { return w.Active && slices.Contains(w.Events, event) }

// Validate checks the endpoint. Plain http is accepted only where the
// deployment allows plaintext (local and test).
func (w Webhook) Validate(allowPlaintext bool) error {
	var errs []apperrors.FieldError
	u, err := url.Parse(strings.TrimSpace(w.URL))
	switch {
	case err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || len(w.URL) > MaxURLLen:
		errs = append(errs, apperrors.FieldError{Field: "url", Code: "invalid_url", Message: "url must be an absolute https URL"})
	case u.Scheme != "https" && !(u.Scheme == "http" && allowPlaintext):
		errs = append(errs, apperrors.FieldError{Field: "url", Code: "invalid_url", Message: "url must use https"})
	}
	if len(w.Events) == 0 {
		errs = append(errs, apperrors.FieldError{Field: "events", Code: "required", Message: "subscribe to at least one event"})
	}
	for _, e := range w.Events {
		if !slices.Contains(Events, e) {
			errs = append(errs, apperrors.FieldError{Field: "events", Code: "invalid", Message: "unknown event " + e})
			break
		}
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

// ValidateSecret checks a secret the caller chose.
func ValidateSecret(s string) error {
	if len(s) < MinSecretLen || len(s) > MaxSecretLen || strings.ContainsAny(s, " \t\r\n") {
		return apperrors.Invalid("secret", "invalid", "secret must be 16 to 128 characters without spaces")
	}
	return nil
}

// NewSecret returns a random signing secret ("whsec_" + 32 bytes).
func NewSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Sign returns the signature header value for body sent at t:
// "t=<unix>,v1=<hex HMAC-SHA256(secret, "<unix>.<body>")>".
func Sign(secret string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature header, refusing one older than tolerance.
// Receivers use the same rule; MailOS uses it in tests.
func Verify(secret, header string, body []byte, now time.Time, tolerance time.Duration) bool {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || now.Sub(time.Unix(n, 0)).Abs() > tolerance {
		return false
	}
	want := Sign(secret, time.Unix(n, 0), body)
	_, wantSig, _ := strings.Cut(want, ",v1=")
	return hmac.Equal([]byte(sig), []byte(wantSig))
}

// DeliveryStatus is where a delivery is.
type DeliveryStatus string

// Delivery statuses.
const (
	DeliveryPending   DeliveryStatus = "pending"
	DeliveryDelivered DeliveryStatus = "delivered"
	DeliveryFailed    DeliveryStatus = "failed"
)

// Delivery is one event posted to one webhook.
type Delivery struct {
	ID          string
	WebhookID   string
	MessageID   string
	Event       string
	Payload     []byte
	Status      DeliveryStatus
	StatusCode  int
	Attempts    int
	LastError   string
	DeliveredAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
