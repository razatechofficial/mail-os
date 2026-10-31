// Package msgsig verifies the signature IAM puts on every message it
// publishes to MailOS (contract §2). The signature travels in the
// iam-msg-sig header as a compact JWS:
//
//	header  {"alg","kid","typ":"mailos-msg+jwt"}
//	claims  {"iss","aud":"mailos","sub":<client_id>,"iat","exp","jti","topic","body_sha256"}
//
// Verify runs checks 1 to 5 of the contract in order: the signature against
// IAM's JWKS, iss/aud/exp with the clock skew, the topic, the body hash and
// the jti replay guard. Check 6, whether the sender may publish the topic,
// is the caller's (domain/access).
//
// A refused message is an *event.Rejection carrying the reason; it is
// permanent and the consumer commits past it after auditing the reason. When
// the check itself cannot run (IAM's JWKS unreachable, the replay store down) Verify
// returns ErrUnavailable instead, and the consumer redelivers the message.
package msgsig

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
)

const (
	// Header is the message header that carries the signature.
	Header = "iam-msg-sig"
	// Type is the JWS typ of a message signature, which keeps it from being
	// taken for any other token IAM signs (RFC 8725 §3.11).
	Type = "mailos-msg+jwt"
	// Lifetime is exp - iat of every message signature IAM issues.
	Lifetime = 5 * time.Minute
)

// Limits on what is read before the signature is checked.
const (
	maxHeaderLen = 8 << 10
	maxJTILen    = 256
)

// ErrUnavailable means the signature could not be checked: IAM's signing
// keys or the replay guard are unreachable. The message was neither
// accepted nor rejected, so it must be redelivered, never dropped.
var ErrUnavailable = errors.New("the message signature cannot be checked now")

// IsUnavailable reports whether err is a transient verification failure.
func IsUnavailable(err error) bool { return errors.Is(err, ErrUnavailable) }

// Claims are a verified message signature's claims.
type Claims struct {
	Issuer string
	// ClientID is the IAM service client that published the message (sub);
	// the caller authorises it for the topic (check 6).
	ClientID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	JTI       string
	Topic     string
}

// ReplayGuard remembers message ids (check 5). It must be atomic across
// every consumer replica.
type ReplayGuard interface {
	// Use records jti until expiresAt and reports whether it was already
	// used. delivery names this delivery of the message (its topic,
	// partition and offset): the same delivery seen again is a redelivery
	// after a failure, not a replay. With an empty delivery any earlier use
	// is a replay. An error means the guard is unavailable; the message is
	// then not accepted (fail closed).
	Use(ctx context.Context, jti, delivery string, expiresAt time.Time) (replayed bool, err error)
}

// Option adjusts one Verify call.
type Option func(*verifyOptions)

type verifyOptions struct {
	delivery string
}

// Delivery names the delivery being verified (see ReplayGuard.Use), so an
// at-least-once redelivery of the same record is not taken for a replay.
func Delivery(id string) Option {
	return func(o *verifyOptions) { o.delivery = id }
}

// Verifier checks message signatures.
type Verifier struct {
	keys   *jwt.Verifier
	replay ReplayGuard
}

// NewVerifier checks signatures with keys (IAM's JWKS, issuer, audience,
// clock skew and clock) and message ids with replay.
func NewVerifier(keys *jwt.Verifier, replay ReplayGuard) (*Verifier, error) {
	if keys == nil || replay == nil {
		return nil, errors.New("msgsig: a key verifier and a replay guard are required")
	}
	return &Verifier{keys: keys, replay: replay}, nil
}

// Verify checks header, the iam-msg-sig value of a message published on
// topic with value, and returns its claims. The error is an
// *event.Rejection (permanent, with the reason) or wraps ErrUnavailable
// (transient). Rejections never quote the value.
func (v *Verifier) Verify(ctx context.Context, header, topic string, value []byte, opts ...Option) (Claims, error) {
	var o verifyOptions
	for _, opt := range opts {
		opt(&o)
	}

	raw := strings.TrimSpace(header)
	if raw == "" {
		return Claims{}, event.Reject(event.ReasonMissingSignature, nil)
	}
	if len(raw) > maxHeaderLen {
		return Claims{}, event.Reject(event.ReasonMalformed, errors.New("the signature header is too long"))
	}
	if _, err := jose.ParseSignedCompact(raw, jwt.Algorithms); err != nil {
		return Claims{}, event.Reject(event.ReasonMalformed, fmt.Errorf("the signature is not a compact JWS: %w", err))
	}

	// 1. The signature, with the key IAM publishes under its kid, and typ.
	claims, err := v.keys.Verify(ctx, raw, Type)
	if err != nil {
		if errors.Is(err, jwt.ErrUnavailable) {
			return Claims{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return Claims{}, event.Reject(event.ReasonBadSignature, err)
	}

	// 2. iss, aud and the validity window, with the clock skew.
	iss, _ := claims["iss"].(string)
	if strings.TrimRight(iss, "/") != v.keys.Issuer() {
		return Claims{}, event.Reject(event.ReasonWrongIssuer, fmt.Errorf("iss %q", iss))
	}
	if aud := jwt.Audiences(claims); len(aud) != 1 || aud[0] != v.keys.Audience() {
		return Claims{}, event.Reject(event.ReasonWrongAudience, fmt.Errorf("aud %v", aud))
	}
	iat, okIat := jwt.NumericDate(claims, "iat")
	exp, okExp := jwt.NumericDate(claims, "exp")
	if !okIat || !okExp {
		return Claims{}, event.Reject(event.ReasonMalformed, errors.New("iat and exp are required"))
	}
	if !exp.After(iat) || exp.Sub(iat) > Lifetime {
		return Claims{}, event.Reject(event.ReasonMalformed, errors.New("exp - iat is not within the message lifetime"))
	}
	now, skew := v.keys.Now(), v.keys.ClockSkew()
	if now.After(exp.Add(skew)) {
		return Claims{}, event.Reject(event.ReasonExpired, fmt.Errorf("expired at %s", exp.Format(time.RFC3339)))
	}
	if iat.After(now.Add(skew)) {
		return Claims{}, event.Reject(event.ReasonExpired, fmt.Errorf("issued in the future at %s", iat.Format(time.RFC3339)))
	}

	// 3. The topic it was signed for.
	signedTopic, _ := claims["topic"].(string)
	if signedTopic == "" || signedTopic != topic {
		return Claims{}, event.Reject(event.ReasonTopicMismatch, fmt.Errorf("signed for topic %q, received on %q", signedTopic, topic))
	}

	// 4. The exact value bytes.
	sum := sha256.Sum256(value)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	got, _ := claims["body_sha256"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return Claims{}, event.Reject(event.ReasonBodyMismatch, nil)
	}

	sub, _ := claims["sub"].(string)
	jti, _ := claims["jti"].(string)
	if strings.TrimSpace(sub) == "" || strings.TrimSpace(jti) == "" || len(jti) > maxJTILen {
		return Claims{}, event.Reject(event.ReasonMalformed, errors.New("sub and jti are required"))
	}

	// 5. Each message once, remembered until it could no longer verify.
	replayed, err := v.replay.Use(ctx, jti, o.delivery, exp.Add(skew))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: replay guard: %w", ErrUnavailable, err)
	}
	if replayed {
		return Claims{}, event.Reject(event.ReasonReplayed, fmt.Errorf("jti %q was already used", jti))
	}

	return Claims{
		Issuer:    v.keys.Issuer(),
		ClientID:  sub,
		IssuedAt:  iat,
		ExpiresAt: exp,
		JTI:       jti,
		Topic:     signedTopic,
	}, nil
}
