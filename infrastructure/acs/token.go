package acs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Resource is ACS's resource indicator at the IAM (RFC 8707).
const Resource = "api://acs"

// TokenSource fetches MailOS's access tokens for ACS from the IAM: OAuth
// client credentials authenticated by MailOS's client certificate
// (tls_client_auth), so ACS can check the token is bound to the
// certificate it sees (RFC 8705). Tokens are cached until shortly before
// they expire. It is the gRPC per-RPC credential.
type TokenSource struct {
	URL      string
	ClientID string
	// TLS presents the client certificate to the token endpoint.
	TLS *tls.Config
	// Insecure allows a plaintext connection to ACS (local, test, e2e).
	Insecure bool
	// HTTPClient overrides the client (tests); Now the clock.
	HTTPClient *http.Client
	Now        func() time.Time

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// refreshBefore is how long before expiry a token is replaced.
const refreshBefore = 30 * time.Second

func (s *TokenSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *TokenSource) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = s.TLS
	s.HTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: tr}
	return s.HTTPClient
}

// Token returns a valid access token, fetching one when needed.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Add(refreshBefore).Before(s.expiry) {
		return s.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {s.ClientID}, "resource": {Resource}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: token: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil || resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", fmt.Errorf("%w: the token endpoint answered %d %s", ErrUnavailable, resp.StatusCode, out.Error)
	}
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 60
	}
	s.token, s.expiry = out.AccessToken, s.now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return s.token, nil
}

// GetRequestMetadata attaches the token to each ACS call.
func (s *TokenSource) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	tok, err := s.Token(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

// RequireTransportSecurity refuses to send the token in plaintext unless
// the deployment allows it.
func (s *TokenSource) RequireTransportSecurity() bool { return !s.Insecure }
