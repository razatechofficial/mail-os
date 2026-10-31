// Package webhook is a tenant's outbound webhooks: HTTPS endpoints MailOS
// posts message events to, each request signed with the endpoint's secret
// as the Standard Webhooks specification defines (webhook-id,
// webhook-timestamp and webhook-signature headers, HMAC-SHA256 over the id,
// timestamp and body), so a receiver checks origin and freshness with any
// Standard Webhooks library. An endpoint is the tenant's (every message)
// or one application's (that application's messages only). The secret is
// sealed at rest.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	MaxURLLen    = 2048
	MinSecretLen = 16
	MaxSecretLen = 128
)

// Standard Webhooks headers and secret format.
const (
	IDHeader         = "webhook-id"
	TimestampHeader  = "webhook-timestamp"
	SignatureHeader  = "webhook-signature"
	SignatureVersion = "v1"
	SecretPrefix     = "whsec_"
)

// Webhook is one endpoint.
type Webhook struct {
	ID    string
	OrgID string
	// ApplicationID limits the endpoint to one application's messages;
	// empty receives every message of the tenant.
	ApplicationID string
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

// NewSecret returns a random signing secret in the Standard Webhooks
// format: "whsec_" and 32 random bytes in base64.
func NewSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return SecretPrefix + base64.StdEncoding.EncodeToString(b[:]), nil
}

// signingKey is the HMAC key of a secret: the bytes a "whsec_" secret
// encodes in base64 (Standard Webhooks), otherwise the secret itself.
func signingKey(secret string) []byte {
	if b64, ok := strings.CutPrefix(secret, SecretPrefix); ok {
		if key, err := base64.StdEncoding.DecodeString(b64); err == nil && len(key) > 0 {
			return key
		}
	}
	return []byte(secret)
}

// Sign returns the webhook-signature header value for the message id
// sent at t (Standard Webhooks): "v1,<base64 HMAC-SHA256(key,
// "<id>.<unix>.<body>")>".
func Sign(secret, id string, t time.Time, body []byte) string {
	mac := hmac.New(sha256.New, signingKey(secret))
	mac.Write([]byte(id + "." + strconv.FormatInt(t.Unix(), 10) + "."))
	mac.Write(body)
	return SignatureVersion + "," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Headers are the Standard Webhooks headers of one delivery.
func Headers(secret, id string, t time.Time, body []byte) map[string]string {
	return map[string]string{
		IDHeader:        id,
		TimestampHeader: strconv.FormatInt(t.Unix(), 10),
		SignatureHeader: Sign(secret, id, t, body),
	}
}

// Verify checks a delivery's headers as a receiver does: one of the
// space-separated v1 signatures matches, and the timestamp is within
// tolerance of now. MailOS uses it in tests.
func Verify(secret, id, timestamp, signatures string, body []byte, now time.Time, tolerance time.Duration) bool {
	n, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || now.Sub(time.Unix(n, 0)).Abs() > tolerance {
		return false
	}
	want := Sign(secret, id, time.Unix(n, 0), body)
	for _, sig := range strings.Fields(signatures) {
		if hmac.Equal([]byte(sig), []byte(want)) {
			return true
		}
	}
	return false
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
