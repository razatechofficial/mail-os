// Package dpop verifies DPoP proofs (RFC 9449) for sender-constrained IAM
// access tokens. The MailOS console's BFF holds DPoP-bound tokens, as the
// XDR console does; a token carrying cnf.jkt is accepted only with a fresh
// proof signed by the key it is bound to, for this request, used once.
package dpop

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Refusals. Each is answered 401 with error="invalid_dpop_proof".
var (
	// ErrProofRequired: a bound token without a DPoP header.
	ErrProofRequired = errors.New("a DPoP proof is required for this sender-constrained token")
	// ErrUnboundDPoP: the DPoP scheme with a token that is not bound.
	ErrUnboundDPoP = errors.New("the DPoP scheme was used with a token that is not sender-constrained")
	// ErrInvalidProof wraps every malformed or mismatched proof.
	ErrInvalidProof = errors.New("invalid DPoP proof")
	// ErrReplayed: the proof's jti was seen before.
	ErrReplayed = errors.New("the DPoP proof was already used")
	// ErrUnavailable: the replay cache could not answer; fail closed.
	ErrUnavailable = errors.New("the DPoP replay cache is unavailable")
)

// ReplayCache records proof ids (Redis SET NX).
type ReplayCache interface {
	ClaimOnce(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// Verifier checks proofs.
type Verifier struct {
	replay ReplayCache
	// window is how old (or how far in the future) a proof's iat may be.
	window time.Duration
	now    func() time.Time
}

// NewVerifier accepts proofs issued within window of now (RFC 9449 §11.1
// leaves the window to the server; 60 s by default).
func NewVerifier(replay ReplayCache, window time.Duration) *Verifier {
	if window <= 0 {
		window = 60 * time.Second
	}
	return &Verifier{replay: replay, window: window, now: time.Now}
}

var proofAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.PS256, jose.RS256, jose.EdDSA}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidProof, fmt.Sprintf(format, args...))
}

// Check enforces the binding for one request. scheme is the Authorization
// scheme ("Bearer" or "DPoP"), jkt the token's cnf.jkt ("" when unbound),
// htu the request URI without query or fragment.
func (v *Verifier) Check(ctx context.Context, r *http.Request, scheme, accessToken, jkt, htu string) error {
	proof := r.Header.Values("DPoP")
	if jkt == "" {
		if strings.EqualFold(scheme, "DPoP") {
			return ErrUnboundDPoP
		}
		return nil
	}
	if len(proof) == 0 {
		return ErrProofRequired
	}
	if len(proof) > 1 {
		return invalid("more than one DPoP header")
	}
	return v.verify(ctx, proof[0], r.Method, htu, accessToken, jkt)
}

func (v *Verifier) verify(ctx context.Context, raw, method, htu, accessToken, jkt string) error {
	jws, err := jose.ParseSigned(raw, proofAlgorithms)
	if err != nil || len(jws.Signatures) != 1 {
		return invalid("not a compact JWS")
	}
	h := jws.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return invalid("typ %q", typ)
	}
	if h.JSONWebKey == nil || !h.JSONWebKey.Valid() || !h.JSONWebKey.IsPublic() {
		return invalid("no public jwk in the header")
	}
	payload, err := jws.Verify(h.JSONWebKey.Key)
	if err != nil {
		return invalid("signature")
	}
	thumb, err := h.JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil || base64.RawURLEncoding.EncodeToString(thumb) != jkt {
		return invalid("the proof key is not the key the token is bound to")
	}
	var c struct {
		JTI string  `json:"jti"`
		HTM string  `json:"htm"`
		HTU string  `json:"htu"`
		IAT float64 `json:"iat"`
		ATH string  `json:"ath"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return invalid("claims")
	}
	if c.JTI == "" || len(c.JTI) > 256 {
		return invalid("jti")
	}
	if !strings.EqualFold(c.HTM, method) {
		return invalid("htm %q is not %s", c.HTM, method)
	}
	if normalizeURI(c.HTU) != normalizeURI(htu) {
		return invalid("htu %q is not this request", c.HTU)
	}
	iat := time.Unix(int64(c.IAT), 0)
	now := v.now()
	if c.IAT <= 0 || now.Sub(iat) > v.window || iat.Sub(now) > v.window {
		return invalid("iat outside the accepted window")
	}
	sum := sha256.Sum256([]byte(accessToken))
	if c.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return invalid("ath does not match the access token")
	}
	first, err := v.replay.ClaimOnce(ctx, "mailos:dpop:jti:"+jkt+":"+c.JTI, 2*v.window)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !first {
		return ErrReplayed
	}
	return nil
}

// normalizeURI drops the query and fragment and lower-cases scheme and host
// (RFC 9449 §4.3 compares htu without them).
func normalizeURI(u string) string {
	u, _, _ = strings.Cut(u, "#")
	u, _, _ = strings.Cut(u, "?")
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	host, path, _ := strings.Cut(rest, "/")
	return strings.ToLower(scheme) + "://" + strings.ToLower(host) + "/" + path
}

// RequestURI is the htu a proof for r must carry: scheme, host and path.
// The scheme is https when MailOS terminated TLS, or when a trusted proxy
// says so (trustForwarded).
func RequestURI(r *http.Request, trustForwarded bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if trustForwarded {
		if p := firstValue(r.Header.Get("X-Forwarded-Proto")); p != "" {
			scheme = p
		}
		if h := firstValue(r.Header.Get("X-Forwarded-Host")); h != "" {
			host = h
		}
	}
	return scheme + "://" + host + r.URL.Path
}

func firstValue(v string) string {
	v, _, _ = strings.Cut(v, ",")
	return strings.TrimSpace(v)
}
