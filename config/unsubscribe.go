package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// Unsubscribe is one-click unsubscribe for broadcast mail (RFC 8058): the
// public origin the links point to and the key that signs them. It is off
// while BaseURL is empty; then broadcast mail carries only the headers its
// sender set.
type Unsubscribe struct {
	// BaseURL is MailOS's public https origin (links are
	// BaseURL/unsubscribe/<token>).
	BaseURL string `yaml:"base_url" env:"UNSUBSCRIBE_BASE_URL" env-default:""`
	// SigningKey is the HMAC-SHA256 key of the links, base64 or hex, at
	// least 32 bytes. Rotating it invalidates the links already sent.
	SigningKey string `yaml:"signing_key" env:"UNSUBSCRIBE_SIGNING_KEY" env-default:""`
	// TokenTTL is how long a link works.
	TokenTTL time.Duration `yaml:"token_ttl" env:"UNSUBSCRIBE_TOKEN_TTL" env-default:"4320h"`
	// Mailto, when set, is a mailbox also offered in List-Unsubscribe.
	Mailto string `yaml:"mailto" env:"UNSUBSCRIBE_MAILTO" env-default:""`
	// RatePerMinute bounds unsubscribe requests per client address.
	RatePerMinute int `yaml:"rate_per_minute" env:"UNSUBSCRIBE_RATE_PER_MINUTE" env-default:"30"`
}

// Enabled reports whether MailOS adds its own unsubscribe links.
func (u Unsubscribe) Enabled() bool { return strings.TrimSpace(u.BaseURL) != "" }

// Key decodes SigningKey (base64, base64url or hex).
func (u Unsubscribe) Key() ([]byte, error) {
	s := strings.TrimSpace(u.SigningKey)
	for _, dec := range []func(string) ([]byte, error){
		hex.DecodeString, base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString, base64.RawURLEncoding.DecodeString,
	} {
		if k, err := dec(s); err == nil && len(k) >= 32 {
			return k, nil
		}
	}
	return nil, fmt.Errorf("UNSUBSCRIBE_SIGNING_KEY must be at least 32 bytes, base64 or hex")
}

func (u Unsubscribe) validate(plaintext bool) error {
	if !u.Enabled() {
		return nil
	}
	p, err := url.Parse(strings.TrimSpace(u.BaseURL))
	if err != nil || p.Host == "" || p.RawQuery != "" || p.Fragment != "" || (p.Scheme != "https" && !(plaintext && p.Scheme == "http")) {
		return fmt.Errorf("UNSUBSCRIBE_BASE_URL must be an https origin (http only in local and test)")
	}
	if _, err := u.Key(); err != nil {
		return err
	}
	if u.TokenTTL < 24*time.Hour || u.TokenTTL > 3*365*24*time.Hour {
		return fmt.Errorf("UNSUBSCRIBE_TOKEN_TTL must be between 24h and 26280h")
	}
	if m := strings.TrimSpace(u.Mailto); m != "" {
		if a, err := mail.ParseAddress(m); err != nil || a.Address != m || a.Name != "" {
			return fmt.Errorf("UNSUBSCRIBE_MAILTO must be a bare email address")
		}
	}
	if u.RatePerMinute < 1 {
		return fmt.Errorf("UNSUBSCRIBE_RATE_PER_MINUTE must be positive")
	}
	return nil
}
