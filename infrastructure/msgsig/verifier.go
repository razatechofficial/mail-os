// Package msgsig verifies the signature IAM puts on every message it
// publishes to MailOS (contract §2). The signature travels in the
// iam-msg-sig header as a compact JWS:
//
//	header  {"alg","kid","typ":"mailos-msg+jwt"}
//	claims  {"iss","sub":<client_id>,"aud":"mailos","iat","exp","jti","topic","body_sha256"}
//
// Verify runs checks 1 to 5 of the contract in the order of IAM's reference
// verifier (iam/server/pkg/msgsig), with its reason names, and passes its
// test vectors (testdata/v1.json): the JWS and the signature against IAM's
// JWKS; iss, aud, the lifetime and the validity window with the clock skew;
// the topic; the body hash; the jti replay guard. Check 6, whether the
// sender may publish the topic, is the caller's (domain/access).
//
// A refused message is an *event.Rejection carrying the reason. It is
// permanent, so the consumer commits past it after auditing the reason,
// except replay_guard_unavailable, which is Transient. When IAM's JWKS
// cannot be read the signature was not checked at all: Verify returns
// ErrUnavailable without a reason. Both transient failures wrap
// ErrUnavailable and the consumer redelivers the message.
package msgsig

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	// Lifetime is the longest exp - iat a message signature may have.
	Lifetime = 5 * time.Minute
)

// Limits on what is read before the signature is checked.
const (
	maxHeaderLen = 8 << 10
	maxJTILen    = 256
)

// ErrUnavailable means a check could not run: IAM's signing keys or the
// replay guard are unreachable. The message must be redelivered, never
// dropped.
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
	// JTI is unique per message; IAM sets it to the event id.
	JTI   string
	Topic string
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

func reject(reason event.Reason, format string, args ...any) error {
	if format == "" {
		return event.Reject(reason, nil)
	}
	return event.Reject(reason, fmt.Errorf(format, args...))
}

// Verify checks header, the iam-msg-sig value of a message published on
// topic with value, and returns its claims. The error is an
// *event.Rejection with the reason, or wraps ErrUnavailable when a check
// could not run (see the package documentation). Rejections never quote
// the value.
func (v *Verifier) Verify(ctx context.Context, header, topic string, value []byte, opts ...Option) (Claims, error) {
	var o verifyOptions
	for _, opt := range opts {
		opt(&o)
	}

	// The JWS: three segments and a protected header naming the type.
	raw := strings.TrimSpace(header)
	if raw == "" {
		return Claims{}, reject(event.ReasonMalformed, "the message has no %s header", Header)
	}
	if len(raw) > maxHeaderLen {
		return Claims{}, reject(event.ReasonMalformed, "the signature header is too long")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, reject(event.ReasonMalformed, "the signature is not a compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, reject(event.ReasonMalformed, "the JWS header is not base64url")
	}
	var h struct {
		Alg  string          `json:"alg"`
		Typ  string          `json:"typ"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, reject(event.ReasonMalformed, "the JWS header is not JSON")
	}
	if !strings.EqualFold(h.Typ, Type) {
		return Claims{}, reject(event.ReasonType, "typ %q is not %s", h.Typ, Type)
	}
	if len(h.Crit) > 0 {
		return Claims{}, reject(event.ReasonMalformed, "the crit header is not understood")
	}
	if !slices.Contains(jwt.Algorithms, jose.SignatureAlgorithm(h.Alg)) {
		return Claims{}, reject(event.ReasonAlgorithm, "alg %q is not one IAM signs with", h.Alg)
	}

	// 1. The signature, with the key IAM publishes under its kid.
	claims, err := v.keys.Verify(ctx, raw, Type)
	switch {
	case err == nil:
	case errors.Is(err, jwt.ErrUnavailable):
		return Claims{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	case errors.Is(err, jwt.ErrUnknownKey):
		return Claims{}, event.Reject(event.ReasonUnknownKey, err)
	case errors.Is(err, jwt.ErrAlgorithm):
		return Claims{}, event.Reject(event.ReasonAlgorithm, err)
	case errors.Is(err, jwt.ErrSignature):
		return Claims{}, event.Reject(event.ReasonSignature, err)
	case errors.Is(err, jwt.ErrType):
		return Claims{}, event.Reject(event.ReasonType, err)
	default:
		return Claims{}, event.Reject(event.ReasonMalformed, err)
	}
	c, err := decodeClaims(claims)
	if err != nil {
		return Claims{}, event.Reject(event.ReasonMalformed, err)
	}

	// 2. iss, aud, the lifetime and the validity window.
	if strings.TrimRight(c.Issuer, "/") != v.keys.Issuer() {
		return Claims{}, reject(event.ReasonIssuer, "iss %q", c.Issuer)
	}
	if c.audience != v.keys.Audience() {
		return Claims{}, reject(event.ReasonAudience, "aud %q", c.audience)
	}
	if !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > Lifetime {
		return Claims{}, reject(event.ReasonLifetime, "exp - iat is not within %s", Lifetime)
	}
	now, skew := v.keys.Now(), v.keys.ClockSkew()
	if !now.Before(c.ExpiresAt.Add(skew)) {
		return Claims{}, reject(event.ReasonExpired, "expired at %s", c.ExpiresAt.Format(time.RFC3339))
	}
	if c.IssuedAt.After(now.Add(skew)) {
		return Claims{}, reject(event.ReasonNotYetValid, "issued at %s", c.IssuedAt.Format(time.RFC3339))
	}

	// 3. The topic it was signed for.
	if c.Topic != topic {
		return Claims{}, reject(event.ReasonTopic, "signed for topic %q, received on %q", c.Topic, topic)
	}

	// 4. The exact value bytes.
	sum := sha256.Sum256(value)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(c.bodyHash), []byte(want)) != 1 {
		return Claims{}, reject(event.ReasonBodyHash, "")
	}

	// 5. Each message once, remembered until it could no longer verify.
	if strings.TrimSpace(c.JTI) == "" || len(c.JTI) > maxJTILen {
		return Claims{}, reject(event.ReasonMalformed, "jti is missing or too long")
	}
	replayed, err := v.replay.Use(ctx, c.JTI, o.delivery, c.ExpiresAt.Add(skew))
	if err != nil {
		return Claims{}, &event.Rejection{Reason: event.ReasonReplayGuardUnavailable, Transient: true,
			Err: fmt.Errorf("%w: replay guard: %w", ErrUnavailable, err)}
	}
	if replayed {
		return Claims{}, reject(event.ReasonReplay, "jti %q was already used", c.JTI)
	}
	c.Issuer = v.keys.Issuer()
	return c.Claims, nil
}

// signedClaims are the claims as signed, before they are checked.
type signedClaims struct {
	Claims
	audience string
	bodyHash string
}

// decodeClaims reads the claims as IAM's reference verifier does: iss, sub,
// topic and body_sha256 present, iat and exp integers, and aud a string or
// a one-element array.
func decodeClaims(m map[string]any) (signedClaims, error) {
	str := func(k string) string { s, _ := m[k].(string); return s }
	var c signedClaims
	c.Issuer, c.ClientID, c.JTI, c.Topic, c.bodyHash = str("iss"), str("sub"), str("jti"), str("topic"), str("body_sha256")
	if c.Issuer == "" || c.ClientID == "" || c.Topic == "" || c.bodyHash == "" {
		return signedClaims{}, errors.New("iss, sub, topic and body_sha256 are required")
	}
	iat, okIat := integer(m["iat"])
	exp, okExp := integer(m["exp"])
	if !okIat || !okExp {
		return signedClaims{}, errors.New("iat and exp must be integers")
	}
	c.IssuedAt, c.ExpiresAt = time.Unix(iat, 0).UTC(), time.Unix(exp, 0).UTC()
	switch aud := m["aud"].(type) {
	case string:
		c.audience = aud
	case []any:
		s, ok := "", len(aud) == 1
		if ok {
			s, ok = aud[0].(string)
		}
		if !ok {
			return signedClaims{}, errors.New("aud must be a single audience")
		}
		c.audience = s
	default:
		return signedClaims{}, errors.New("aud must be a single audience")
	}
	return c, nil
}

// integer reads a JSON integer (the jwt verifier decodes numbers as
// json.Number).
func integer(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}
