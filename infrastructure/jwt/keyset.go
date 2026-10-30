// Package jwt verifies tokens IAM signs: access tokens of console users and
// service clients (contract §1, §5), and the message signatures on pub/sub
// events (§2). Keys come from the JWKS named by IAM's discovery document and
// are looked up by kid; a token's alg must be its key's algorithm, so a
// token cannot choose how it is verified (RFC 8725 §3.1).
package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Algorithms IAM signs with (its key manager: PS256, ES256, RS256, EdDSA).
var Algorithms = []jose.SignatureAlgorithm{jose.PS256, jose.ES256, jose.RS256, jose.EdDSA}

// ErrUnavailable means IAM's discovery document or JWKS could not be read.
// The token was not checked, so callers answer 503, never 401.
var ErrUnavailable = errors.New("the IAM signing keys are unavailable")

// minRefreshInterval limits refetches triggered by unknown kids, so a flood
// of forged kids cannot turn MailOS into a JWKS load generator.
const minRefreshInterval = 5 * time.Second

// keySet caches IAM's JWKS by kid.
type keySet struct {
	issuer     string
	cacheTTL   time.Duration
	minRefresh time.Duration
	client     *http.Client

	mu          sync.RWMutex
	jwksURL     string
	keys        map[string]jose.JSONWebKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

func newKeySet(issuer string, cacheTTL, minRefresh time.Duration, client *http.Client) *keySet {
	return &keySet{issuer: issuer, cacheTTL: cacheTTL, minRefresh: minRefresh, client: client, keys: map[string]jose.JSONWebKey{}}
}

// key returns the key for kid, refreshing when the cache is stale or the
// kid is unknown (IAM rotated keys).
func (s *keySet) key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	stale := s.fetchedAt.IsZero() || time.Since(s.fetchedAt) > s.cacheTTL
	recent := time.Since(s.lastAttempt) < s.minRefresh
	s.mu.RUnlock()
	if ok && !stale {
		return k, nil
	}
	if !ok && recent && !s.fetchedAtZero() {
		return jose.JSONWebKey{}, fmt.Errorf("unknown signing key %q", kid)
	}
	if err := s.refresh(ctx); err != nil {
		if ok {
			// A cached key keeps verifying through a short IAM outage.
			return k, nil
		}
		return jose.JSONWebKey{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if k, ok := s.keys[kid]; ok {
		return k, nil
	}
	return jose.JSONWebKey{}, fmt.Errorf("unknown signing key %q", kid)
}

func (s *keySet) fetchedAtZero() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fetchedAt.IsZero()
}

func (s *keySet) refresh(ctx context.Context) error {
	s.mu.Lock()
	s.lastAttempt = time.Now()
	jwksURL := s.jwksURL
	s.mu.Unlock()

	if jwksURL == "" {
		u, err := s.discover(ctx)
		if err != nil {
			return err
		}
		jwksURL = u
	}
	var doc jose.JSONWebKeySet
	if err := s.getJSON(ctx, jwksURL, &doc); err != nil {
		return fmt.Errorf("%w: jwks: %v", ErrUnavailable, err)
	}
	next := make(map[string]jose.JSONWebKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.KeyID == "" || !k.Valid() || !k.IsPublic() || (k.Use != "" && k.Use != "sig") {
			continue
		}
		next[k.KeyID] = k
	}
	if len(next) == 0 {
		return fmt.Errorf("%w: the JWKS has no usable signing keys", ErrUnavailable)
	}
	s.mu.Lock()
	s.jwksURL = jwksURL
	s.keys = next
	s.fetchedAt = time.Now()
	s.mu.Unlock()
	return nil
}

// discover reads jwks_uri from the issuer's discovery document. The
// document must name the configured issuer and a JWKS on the same host.
func (s *keySet) discover(ctx context.Context) (string, error) {
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := s.getJSON(ctx, s.issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return "", fmt.Errorf("%w: discovery: %v", ErrUnavailable, err)
	}
	if strings.TrimRight(doc.Issuer, "/") != s.issuer {
		return "", fmt.Errorf("%w: discovery issuer %q is not %q", ErrUnavailable, doc.Issuer, s.issuer)
	}
	iu, _ := url.Parse(s.issuer)
	ju, err := url.Parse(doc.JWKSURI)
	if err != nil || ju.Host == "" || !strings.EqualFold(ju.Hostname(), iu.Hostname()) || ju.Scheme != iu.Scheme {
		return "", fmt.Errorf("%w: jwks_uri %q is not on the issuer's origin", ErrUnavailable, doc.JWKSURI)
	}
	return doc.JWKSURI, nil
}

func (s *keySet) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// algorithmAllowed reports whether a token signed with alg may be verified
// with k: the key's own alg when the JWK names one, otherwise the
// algorithms of its key type. PKCS#1 v1.5 and PSS on one RSA key are kept
// apart whenever IAM publishes alg (its key manager always does).
func algorithmAllowed(k jose.JSONWebKey, alg string) bool {
	if k.Algorithm != "" {
		return k.Algorithm == alg
	}
	switch key := k.Key.(type) {
	case *rsa.PublicKey:
		return alg == string(jose.RS256) || alg == string(jose.PS256)
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256() && alg == string(jose.ES256)
	case ed25519.PublicKey:
		return alg == string(jose.EdDSA)
	default:
		return false
	}
}
