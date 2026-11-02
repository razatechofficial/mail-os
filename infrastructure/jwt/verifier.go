package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/razatechofficial/mail-os/domain/access"
)

// Config configures verification against IAM.
type Config struct {
	// Issuer is the IAM origin; discovery is {Issuer}/.well-known/openid-configuration.
	Issuer string
	// Audience is MailOS's resource identifier ("mailos").
	Audience string
	// ConsoleAudiences are the console's client IDs, accepted on user tokens.
	ConsoleAudiences []string
	CacheTTL         time.Duration
	ClockSkew        time.Duration
	// MinRefresh limits JWKS refetches for unknown kids (default 5s).
	MinRefresh time.Duration
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Verifier checks IAM-signed JWTs.
type Verifier struct {
	issuer           string
	audience         string
	consoleAudiences []string
	skew             time.Duration
	keys             *keySet
	now              func() time.Time
}

// NewVerifier builds a verifier. Keys are fetched on first use, so MailOS
// starts while IAM is briefly unreachable and answers 503 meanwhile.
func NewVerifier(cfg Config) *Verifier {
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	skew := cfg.ClockSkew
	if skew <= 0 {
		skew = 60 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	minRefresh := cfg.MinRefresh
	if minRefresh <= 0 {
		minRefresh = minRefreshInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	return &Verifier{
		issuer:           issuer,
		audience:         cfg.Audience,
		consoleAudiences: cfg.ConsoleAudiences,
		skew:             skew,
		keys:             newKeySet(issuer, ttl, minRefresh, client),
		now:              now,
	}
}

// Issuer is the IAM origin tokens must name.
func (v *Verifier) Issuer() string { return v.issuer }

// Audience is the audience service tokens and message signatures carry.
func (v *Verifier) Audience() string { return v.audience }

// ClockSkew is the tolerance applied to exp, iat and nbf.
func (v *Verifier) ClockSkew() time.Duration { return v.skew }

// Now is the verifier's clock.
func (v *Verifier) Now() time.Time { return v.now() }

// ErrInvalid wraps every reason a token is refused; the reason is logged,
// never returned to the caller.
var ErrInvalid = errors.New("invalid token")

// Kinds of signature refusal Verify reports beside ErrInvalid, so a caller
// such as the message-signature verifier can name the reason.
var (
	ErrType       = errors.New("the token type is not accepted")
	ErrUnknownKey = errors.New("the signing key is not published")
	ErrAlgorithm  = errors.New("the algorithm is not the signing key's")
	ErrSignature  = errors.New("the signature does not verify")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// invalidAs is invalid that also wraps kind.
func invalidAs(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrInvalid, kind, fmt.Sprintf(format, args...))
}

// Verify checks raw's signature against IAM's JWKS and its typ header, and
// returns the claims. wantTypes are the accepted typ values (case-insensitive).
// It checks nothing else: callers validate the claims for their token kind.
func (v *Verifier) Verify(ctx context.Context, raw string, wantTypes ...string) (map[string]any, error) {
	jws, err := jose.ParseSigned(raw, Algorithms)
	if err != nil {
		return nil, invalid("parse: %v", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, invalid("expected one signature")
	}
	h := jws.Signatures[0].Protected
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	if !slices.ContainsFunc(wantTypes, func(w string) bool { return strings.EqualFold(w, typ) }) {
		return nil, invalidAs(ErrType, "typ %q is not %v", typ, wantTypes)
	}
	if h.KeyID == "" {
		return nil, invalidAs(ErrUnknownKey, "no kid")
	}
	key, err := v.keys.key(ctx, h.KeyID)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return nil, err
		}
		return nil, invalidAs(ErrUnknownKey, "%v", err)
	}
	if !algorithmAllowed(key, h.Algorithm) {
		return nil, invalidAs(ErrAlgorithm, "alg %s is not the algorithm of key %s", h.Algorithm, h.KeyID)
	}
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, invalidAs(ErrSignature, "signature: %v", err)
	}
	var claims map[string]any
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return nil, invalid("claims: %v", err)
	}
	return claims, nil
}

// CheckTimes validates exp (required), iat (required, not in the future)
// and nbf, each with the clock skew.
func (v *Verifier) CheckTimes(claims map[string]any) error {
	now := v.now()
	exp, ok := NumericDate(claims, "exp")
	if !ok {
		return invalid("no exp")
	}
	if now.After(exp.Add(v.skew)) {
		return invalid("expired")
	}
	iat, ok := NumericDate(claims, "iat")
	if !ok {
		return invalid("no iat")
	}
	if iat.After(now.Add(v.skew)) {
		return invalid("iat in the future")
	}
	if nbf, ok := NumericDate(claims, "nbf"); ok && now.Before(nbf.Add(-v.skew)) {
		return invalid("not yet valid")
	}
	return nil
}

// accessTokenTypes are RFC 9068's access token typ values; IAM issues at+jwt.
var accessTokenTypes = []string{"at+jwt", "application/at+jwt"}

// Principal verifies an IAM access token and returns who it names.
//
//   - A service token (client credentials) has sub "client:<client_id>" and
//     must carry aud = Audience exactly (contract §1).
//   - A user token must name the MailOS audience or one of the console's
//     client IDs, and carry the tenant (tid).
//
// A security event token presented as an access token is refused.
func (v *Verifier) Principal(ctx context.Context, raw string) (access.Principal, error) {
	claims, err := v.Verify(ctx, raw, accessTokenTypes...)
	if err != nil {
		return access.Principal{}, err
	}
	if _, isSET := claims["events"]; isSET {
		return access.Principal{}, invalid("security event token presented as an access token")
	}
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != v.issuer {
		return access.Principal{}, invalid("issuer %q", iss)
	}
	if err := v.CheckTimes(claims); err != nil {
		return access.Principal{}, err
	}
	sub := String(claims, "sub")
	if sub == "" {
		return access.Principal{}, invalid("no sub")
	}
	aud := Audiences(claims)
	p := access.Principal{
		Subject:   sub,
		TenantID:  strings.ToLower(String(claims, "tid", "tenant_id")),
		OrgID:     strings.ToLower(String(claims, "org_id", "organization_uuid")),
		ClientID:  String(claims, "client_id", "azp"),
		ACR:       String(claims, "acr"),
		AMR:       Strings(claims, "amr"),
		SessionID: String(claims, "sid"),
		TokenID:   String(claims, "jti"),
		Scopes:    Strings(claims, "scope"),
		Email:     String(claims, "email"),
	}
	p.EmailVerified, _ = claims["email_verified"].(bool)
	if t, ok := NumericDate(claims, "auth_time"); ok {
		p.AuthTime = t
	}
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		p.DPoPThumbprint, _ = cnf["jkt"].(string)
	}
	_, p.Delegated = claims["act"]

	if clientID, ok := strings.CutPrefix(sub, "client:"); ok {
		if clientID == "" || (p.ClientID != "" && p.ClientID != clientID) {
			return access.Principal{}, invalid("service token client_id does not match sub")
		}
		if !slices.Contains(aud, v.audience) {
			return access.Principal{}, invalid("service token audience %v", aud)
		}
		p.Kind = access.KindService
		p.ClientID = clientID
		return p, nil
	}

	if !slices.Contains(aud, v.audience) && !slices.ContainsFunc(aud, func(a string) bool {
		return slices.Contains(v.consoleAudiences, a)
	}) {
		return access.Principal{}, invalid("user token audience %v", aud)
	}
	if p.TenantID == "" {
		return access.Principal{}, invalid("user token without tid")
	}
	p.Kind = access.KindUser
	for _, r := range Strings(claims, "roles") {
		if role, ok := access.ParseRole(r); ok && !slices.Contains(p.Roles, role) {
			p.Roles = append(p.Roles, role)
		}
	}
	return p, nil
}

// String returns the first non-empty string claim among keys.
func String(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := claims[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// Strings reads a claim that is an array of strings or one
// space-separated string.
func Strings(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case string:
		return strings.Fields(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Audiences reads aud, a string or an array (RFC 7519 §4.1.3).
func Audiences(claims map[string]any) []string { return Strings(claims, "aud") }

// NumericDate reads a NumericDate claim (seconds since the epoch).
func NumericDate(claims map[string]any, key string) (time.Time, bool) {
	var sec float64
	switch v := claims[key].(type) {
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return time.Time{}, false
		}
		sec = f
	case float64:
		sec = v
	default:
		return time.Time{}, false
	}
	if sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(sec), 0).UTC(), true
}
