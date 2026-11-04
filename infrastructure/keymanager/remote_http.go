package keymanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The GCP, Azure and Vault KEKs call their services' HTTPS APIs with the
// standard library: no SDK, a bounded client, and errors that name the
// service and status but never a token, key or secret.

// remoteTimeout bounds one call to a key service.
const remoteTimeout = 15 * time.Second

// maxRemoteBody bounds what is read of a key service's response.
const maxRemoteBody = 1 << 20

func defaultRemoteClient() *http.Client { return &http.Client{Timeout: remoteTimeout} }

// tokenCache keeps a bearer token until shortly before it expires.
type tokenCache struct {
	mu    sync.Mutex
	tok   string
	exp   time.Time
	fetch func(ctx context.Context) (token string, ttl time.Duration, err error)
	now   func() time.Time
}

func newTokenCache(fetch func(context.Context) (string, time.Duration, error)) *tokenCache {
	return &tokenCache{fetch: fetch, now: time.Now}
}

// get returns the cached token, fetching a new one a minute before expiry.
func (c *tokenCache) get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != "" && c.now().Before(c.exp) {
		return c.tok, nil
	}
	tok, ttl, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	if tok == "" {
		return "", errors.New("the token service returned no token")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	margin := time.Minute
	if ttl < 2*margin {
		margin = ttl / 2
	}
	c.tok, c.exp = tok, c.now().Add(ttl-margin)
	return tok, nil
}

// reset drops the token after the service refused it.
func (c *tokenCache) reset() {
	c.mu.Lock()
	c.tok = ""
	c.mu.Unlock()
}

// remoteAPI is a key service's JSON API behind a bearer token.
type remoteAPI struct {
	service string
	client  *http.Client
	tokens  *tokenCache
	// auth puts the token on a request.
	auth func(h http.Header, token string)
}

// call sends in as JSON and decodes the answer into out. A 401 or 403
// drops the token and tries once more with a new one.
func (r *remoteAPI) call(ctx context.Context, method, endpoint string, in, out any) error {
	for attempt := 0; ; attempt++ {
		tok, err := r.tokens.get(ctx)
		if err != nil {
			return fmt.Errorf("%s: authenticate: %w", r.service, err)
		}
		status, err := doJSON(ctx, r.client, r.service, method, endpoint, func(h http.Header) { r.auth(h, tok) }, in, out)
		if (status == http.StatusUnauthorized || status == http.StatusForbidden) && attempt == 0 {
			r.tokens.reset()
			continue
		}
		return err
	}
}

// doJSON performs one JSON request; status is 0 when none was answered.
func doJSON(ctx context.Context, client *http.Client, service, method, endpoint string, header func(http.Header), in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, fmt.Errorf("%s: encode request: %w", service, err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, fmt.Errorf("%s: build request: %w", service, err)
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if header != nil {
		header(req.Header)
	}
	return send(client, service, req, out)
}

// postForm sends an application/x-www-form-urlencoded request.
func postForm(ctx context.Context, client *http.Client, service, endpoint string, form url.Values, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, fmt.Errorf("%s: build request: %w", service, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return send(client, service, req, out)
}

func send(client *http.Client, service string, req *http.Request, out any) (int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s: %s %s: %w", service, req.Method, req.URL.Path, scrubURLError(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBody))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%s: read response: %w", service, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, &RemoteError{Service: service, Status: resp.StatusCode, Message: remoteMessage(raw)}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s: malformed response: %w", service, err)
		}
	}
	return resp.StatusCode, nil
}

// scrubURLError drops the URL (which may hold a query) from a transport
// error, keeping its cause.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// RemoteError is a key service's refusal.
type RemoteError struct {
	Service string
	Status  int
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s: HTTP %d", e.Service, e.Status)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.Service, e.Status, e.Message)
}

// remoteMessage is the service's error text: Google's and Azure's
// {"error": {"message"}}, OAuth's error_description, Vault's {"errors"}.
func remoteMessage(raw []byte) string {
	var body struct {
		Error json.RawMessage `json:"error"`
		Desc  string          `json:"error_description"`
		List  []string        `json:"errors"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	msg := ""
	switch {
	case body.Desc != "":
		msg = body.Desc
	case len(body.List) > 0:
		msg = strings.Join(body.List, "; ")
	case len(body.Error) > 0:
		var nested struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body.Error, &nested) == nil && nested.Message != "" {
			msg = nested.Message
		} else {
			_ = json.Unmarshal(body.Error, &msg)
		}
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// oauthToken is a token endpoint's answer. expires_in is a number, or a
// string from the Azure instance metadata service.
type oauthToken struct {
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
}

func (t oauthToken) ttl() time.Duration {
	s := strings.Trim(string(t.ExpiresIn), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// readSecret is a secret from its file (the Vault agent's), else its value.
func readSecret(value, file, name string) (string, error) {
	if file == "" {
		return value, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	s := strings.TrimRight(string(raw), "\r\n")
	if s == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return s, nil
}
