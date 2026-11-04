// Package providerhooks authenticates and reads the delivery event
// webhooks of the sending APIs: Amazon SES (through SNS), SendGrid,
// Mailgun, Postmark, SparkPost, Brevo, Mailjet and Resend. Each payload is
// checked against the provider's webhook secret (its webhook_secret
// credential) before anything in it is read, and normalised into
// message.ProviderEvent values: delivered, bounced (hard), soft_bounced,
// deferred, complained. Opens, clicks and other events are ignored.
//
// How each provider is authenticated:
//
//   - SES: the SNS message signature (SignatureVersion 1 or 2, the signing
//     certificate fetched over HTTPS only from sns.<region>.amazonaws.com)
//     and the basic-auth password of the subscribed URL.
//   - SendGrid: the Signed Event Webhook's ECDSA signature over timestamp
//     and body, with the verification key.
//   - Mailgun: each event's HMAC-SHA256 of timestamp and token with the
//     webhook signing key.
//   - Resend: the Svix signature (svix-id, svix-timestamp, svix-signature)
//     with the whsec_ signing secret.
//   - Postmark, SparkPost, Brevo, Mailjet: they sign nothing (or nothing a
//     receiver can check without a callback), so the event URL carries a
//     basic-auth password; Brevo may send it as a bearer token.
//
// Every signed scheme with a timestamp is refused outside Tolerance, and
// every secret comparison is constant-time.
package providerhooks

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Errors. A refused webhook is ErrUnauthenticated (401 to the caller,
// audited); a payload that cannot be read after it was authenticated is
// ErrMalformed (400).
var (
	ErrUnauthenticated = errors.New("the webhook is not authenticated")
	ErrMalformed       = errors.New("the webhook payload cannot be read")
	ErrUnsupported     = errors.New("this provider kind has no delivery webhooks")
	ErrNotConfigured   = errors.New("the provider has no webhook secret")
)

// DefaultTolerance is how far a signed timestamp may be from now.
const DefaultTolerance = 5 * time.Minute

// snsTolerance is longer: SNS retries an HTTP endpoint with backoff, and
// the timestamp is the publish time.
const snsTolerance = time.Hour

// Request is the webhook as received.
type Request struct {
	Header http.Header
	Body   []byte
}

// Result is what an authenticated webhook asked for.
type Result struct {
	Events []message.ProviderEvent
	// SubscribeURL is an SNS subscription to confirm (GET over HTTPS).
	SubscribeURL string
}

// Certificates fetches SNS signing certificates and confirms
// subscriptions; HTTPSFetcher is the network implementation.
type Certificates interface {
	// Certificate returns the PEM certificate at url. The caller has
	// already checked the URL's host.
	Certificate(ctx context.Context, url string) ([]byte, error)
}

// Verifier authenticates and parses provider webhooks.
type Verifier struct {
	// Certs fetches SNS signing certificates (required for SES).
	Certs Certificates
	// Tolerance bounds signed timestamps (DefaultTolerance when zero).
	Tolerance time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) tolerance() time.Duration {
	if v.Tolerance > 0 {
		return v.Tolerance
	}
	return DefaultTolerance
}

// Supported reports whether kind has delivery webhooks.
func Supported(kind provider.Kind) bool {
	switch kind {
	case provider.KindSES, provider.KindSendGrid, provider.KindMailgun, provider.KindPostmark,
		provider.KindSparkPost, provider.KindBrevo, provider.KindMailjet, provider.KindResend:
		return true
	}
	return false
}

// Parse authenticates r for a provider of kind with its webhook secret and
// returns its delivery events.
func (v *Verifier) Parse(ctx context.Context, kind provider.Kind, secret string, r Request) (Result, error) {
	if !Supported(kind) {
		return Result{}, ErrUnsupported
	}
	if strings.TrimSpace(secret) == "" {
		return Result{}, ErrNotConfigured
	}
	var (
		res Result
		err error
	)
	switch kind {
	case provider.KindSES:
		res, err = v.ses(ctx, secret, r)
	case provider.KindSendGrid:
		res.Events, err = v.sendGrid(secret, r)
	case provider.KindMailgun:
		res.Events, err = v.mailgun(secret, r)
	case provider.KindResend:
		res.Events, err = v.resend(secret, r)
	case provider.KindPostmark:
		if err = basicAuth(r.Header, secret, false); err == nil {
			res.Events, err = postmark(r.Body)
		}
	case provider.KindSparkPost:
		if err = basicAuth(r.Header, secret, false); err == nil {
			res.Events, err = sparkPost(r.Body)
		}
	case provider.KindBrevo:
		if err = basicAuth(r.Header, secret, true); err == nil {
			res.Events, err = brevo(r.Body)
		}
	case provider.KindMailjet:
		if err = basicAuth(r.Header, secret, false); err == nil {
			res.Events, err = mailjet(r.Body)
		}
	}
	if err != nil {
		return Result{}, err
	}
	for i := range res.Events {
		res.Events[i].Normalize()
		if res.Events[i].OccurredAt.IsZero() {
			res.Events[i].OccurredAt = v.now().UTC()
		}
	}
	return res, nil
}

// equal compares secrets in constant time.
func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// basicAuth checks the request's basic-auth password (any user name), or,
// when bearer is allowed, an Authorization: Bearer token.
func basicAuth(h http.Header, secret string, bearer bool) error {
	auth := h.Get("Authorization")
	scheme, value, ok := strings.Cut(auth, " ")
	if !ok {
		return fmt.Errorf("%w: no credentials", ErrUnauthenticated)
	}
	value = strings.TrimSpace(value)
	switch {
	case strings.EqualFold(scheme, "Basic"):
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return fmt.Errorf("%w: malformed basic credentials", ErrUnauthenticated)
		}
		_, password, ok := strings.Cut(string(raw), ":")
		if ok && equal(password, secret) {
			return nil
		}
	case bearer && strings.EqualFold(scheme, "Bearer"):
		if equal(value, secret) {
			return nil
		}
	}
	return fmt.Errorf("%w: wrong credentials", ErrUnauthenticated)
}

// within checks a signed timestamp against the tolerance.
func within(now, at time.Time, tolerance time.Duration) error {
	d := now.Sub(at)
	if d < -tolerance || d > tolerance {
		return fmt.Errorf("%w: the signature timestamp is outside the tolerance", ErrUnauthenticated)
	}
	return nil
}

// unixTime reads seconds since the epoch, whole or fractional.
func unixTime(s string) (time.Time, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f <= 0 {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), true
}

// parseTime reads an RFC 3339 time, or zero.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
