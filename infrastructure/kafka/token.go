package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/oauth"

	"github.com/razatechofficial/mail-os/config"
)

const (
	// tokenRefreshMargin renews the token this long before it expires
	// (contract §1).
	tokenRefreshMargin = 30 * time.Second
	// defaultTokenTTL is assumed when the token response has no expires_in.
	defaultTokenTTL = time.Minute
)

// TokenSource gets MailOS's own client-credentials token for OAUTHBEARER and
// caches it until 30 s before it expires.
type TokenSource struct {
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	client       *http.Client
	now          func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewTokenSource builds a token source from the SASL settings. client nil
// uses a 10 s timeout and the system roots.
func NewTokenSource(c config.SASL, client *http.Client) (*TokenSource, error) {
	if c.TokenURL == "" || c.ClientID == "" || c.ClientSecret == "" {
		return nil, errors.New("kafka sasl: OAUTHBEARER needs a token URL, client id and client secret")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &TokenSource{
		tokenURL:     c.TokenURL,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		scope:        c.Scope,
		client:       client,
		now:          time.Now,
	}, nil
}

// Mechanism is OAUTHBEARER with this source's token. franz-go asks for a
// token on every (re)authentication.
func (s *TokenSource) Mechanism() sasl.Mechanism {
	return oauth.Oauth(func(ctx context.Context) (oauth.Auth, error) {
		tok, err := s.Token(ctx)
		if err != nil {
			return oauth.Auth{}, err
		}
		return oauth.Auth{Token: tok}, nil
	})
}

// Token returns the cached token, or a new one from the token endpoint.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Before(s.expires.Add(-tokenRefreshMargin)) {
		return s.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)
	if s.scope != "" {
		form.Set("scope", s.scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("kafka token: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("kafka token: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("kafka token: read: %w", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		// Only the RFC 6749 error code is kept; the description may echo input.
		return "", fmt.Errorf("kafka token: status %d %s", resp.StatusCode, out.Error)
	}
	if out.AccessToken == "" {
		return "", errors.New("kafka token: the response has no access_token")
	}
	if out.TokenType != "" && !strings.EqualFold(out.TokenType, "Bearer") {
		return "", fmt.Errorf("kafka token: token_type %q is not Bearer", out.TokenType)
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	s.token = out.AccessToken
	s.expires = s.now().Add(ttl)
	return s.token, nil
}
