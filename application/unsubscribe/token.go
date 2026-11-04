package unsubscribe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// tokenVersion is the claims format; a token of another version is
// refused.
const tokenVersion = 1

// macContext separates these MACs from any other use of the key.
const macContext = "mailos-unsubscribe-v1."

// MinKeyBytes is the shortest signing key accepted (HMAC-SHA256).
const MinKeyBytes = 32

// maxTokenLen bounds what Verify reads, before any decoding.
const maxTokenLen = 2048

// ErrInvalidToken is a token that is malformed, tampered with, of another
// version, or expired. The reason is not told apart to the caller.
var ErrInvalidToken = errors.New("the unsubscribe link is invalid or has expired")

// Claims are what an unsubscribe link stands for: one recipient of one
// tenant (and, for an application's mail, that application), from one
// campaign when there is one.
type Claims struct {
	Version       int    `json:"v"`
	TenantID      string `json:"t"`
	ApplicationID string `json:"a,omitempty"`
	Email         string `json:"e"`
	CampaignID    string `json:"c,omitempty"`
	MessageID     string `json:"m,omitempty"`
	ExpiresAt     int64  `json:"x"`
}

// Signer issues and verifies unsubscribe tokens: the claims as base64url
// JSON, a dot, and their HMAC-SHA256. Verification is constant-time.
type Signer struct {
	key []byte
	now func() time.Time
}

// NewSigner builds a signer over key (at least MinKeyBytes).
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < MinKeyBytes {
		return nil, errors.New("unsubscribe signing key must be at least 32 bytes")
	}
	return &Signer{key: append([]byte(nil), key...), now: time.Now}, nil
}

func (s *Signer) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(macContext))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// Issue signs c, valid for ttl.
func (s *Signer) Issue(c Claims, ttl time.Duration) (string, error) {
	c.Version = tokenVersion
	c.ExpiresAt = s.now().Add(ttl).Unix()
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.mac(payload)), nil
}

// Verify checks token's signature, version and expiry and returns its
// claims.
func (s *Signer) Verify(token string) (Claims, error) {
	if len(token) > maxTokenLen {
		return Claims{}, ErrInvalidToken
	}
	payload, sig, ok := strings.Cut(token, ".")
	if !ok || payload == "" || sig == "" {
		return Claims{}, ErrInvalidToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(payload)) {
		return Claims{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if c.Version != tokenVersion || c.TenantID == "" || c.Email == "" || s.now().Unix() > c.ExpiresAt {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}
