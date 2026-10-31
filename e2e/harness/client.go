//go:build e2e

package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// T is the part of testing.TB the harness uses, so fixtures can also be
// built in TestMain (see Main).
type T interface {
	Helper()
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
	Cleanup(func())
}

// Client is one caller of an HTTP origin, optionally with a bearer token. It
// never follows redirects, so tests see every Location the server sends.
type Client struct {
	Base   string
	Bearer string
	// Header is added to every request.
	Header http.Header
	http   *http.Client
}

// NewClient returns an anonymous client of the MailOS server.
func (e *Env) NewClient() *Client { return newClient(e.BaseURL) }

func newClient(base string) *Client {
	return &Client{
		Base:   base,
		Header: http.Header{},
		http: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// WithBearer returns a copy of c authenticated with token.
func (c *Client) WithBearer(token string) *Client {
	return &Client{Base: c.Base, Bearer: token, Header: c.Header.Clone(), http: c.http}
}

// Response is a fully read response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Envelope is the API's response shape: {success, data, meta, error}.
type Envelope struct {
	Success   bool            `json:"success"`
	Data      json.RawMessage `json:"data,omitempty"`
	Meta      json.RawMessage `json:"meta,omitempty"`
	Error     *APIError       `json:"error,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
}

// APIError is the envelope's error member.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details []struct {
		Field   string `json:"field"`
		Code    string `json:"code,omitempty"`
		Message string `json:"message"`
	} `json:"details,omitempty"`
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
}

// Envelope decodes the body as the API envelope (zero when it is not one).
func (r *Response) Envelope() Envelope {
	var env Envelope
	_ = json.Unmarshal(r.Body, &env)
	return env
}

// JSON decodes the body as an object (empty when it is not one).
func (r *Response) JSON() map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(r.Body, &out)
	return out
}

// Data is the envelope's "data" member as an object, or the whole body
// when there is no envelope.
func (r *Response) Data() map[string]any {
	body := r.JSON()
	if d, ok := body["data"].(map[string]any); ok {
		return d
	}
	return body
}

// Items is the envelope's "data" member as a list of objects.
func (r *Response) Items() []map[string]any {
	var out []map[string]any
	_ = json.Unmarshal(r.Envelope().Data, &out)
	return out
}

// Decode unmarshals the envelope's "data" member into v and fails the test
// unless the response is a successful envelope.
func (r *Response) Decode(t T, v any) {
	t.Helper()
	env := r.Envelope()
	if !env.Success {
		t.Fatalf("response is not a successful envelope: %s", r)
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		t.Fatalf("decode data: %v: %s", err, r)
	}
}

// ErrorCode is the envelope's error code ("" when there is none).
func (r *Response) ErrorCode() string {
	if e := r.Envelope().Error; e != nil {
		return e.Code
	}
	return ""
}

// Location parses the redirect target.
func (r *Response) Location() *url.URL {
	u, _ := url.Parse(r.Header.Get("Location"))
	if u == nil {
		return &url.URL{}
	}
	return u
}

func (r *Response) String() string {
	body := string(r.Body)
	if len(body) > 2000 {
		body = body[:2000] + "..."
	}
	return fmt.Sprintf("%d %s", r.Status, body)
}

// Do sends a request. A body that is url.Values is form-encoded, []byte is
// sent as is, anything else as JSON. path is relative to Base unless it is
// an absolute URL.
func (c *Client) Do(t T, method, path string, body any, header ...http.Header) *Response {
	t.Helper()
	var rd io.Reader
	contentType := ""
	switch b := body.(type) {
	case nil:
	case url.Values:
		rd, contentType = strings.NewReader(b.Encode()), "application/x-www-form-urlencoded"
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal %s %s: %v", method, path, err)
		}
		rd, contentType = bytes.NewReader(raw), "application/json"
	}
	target := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		target = c.Base + path
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	for k, v := range c.Header {
		req.Header[k] = v
	}
	for _, h := range header {
		for k, v := range h {
			req.Header[k] = v
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

// Expect sends a request and fails the test unless the status matches.
func (c *Client) Expect(t T, want int, method, path string, body any, header ...http.Header) *Response {
	t.Helper()
	r := c.Do(t, method, path, body, header...)
	if r.Status != want {
		t.Fatalf("%s %s = %s, want %d", method, path, r, want)
	}
	return r
}

// ExpectError sends a request and fails the test unless the status matches
// and the envelope carries the error code (any code when code is "").
func (c *Client) ExpectError(t T, want int, code, method, path string, body any, header ...http.Header) *Response {
	t.Helper()
	r := c.Expect(t, want, method, path, body, header...)
	env := r.Envelope()
	if env.Success || env.Error == nil {
		t.Fatalf("%s %s = %s, want an error envelope", method, path, r)
	}
	if code != "" && env.Error.Code != code {
		t.Fatalf("%s %s error code = %q, want %q: %s", method, path, env.Error.Code, code, r)
	}
	return r
}

// Str reads a string member of a decoded JSON object, following dotted paths.
func Str(m map[string]any, path string) string {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	switch v := cur.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// Eventually polls until fetch reports done or the timeout passes. The
// worker and the scheduler act a moment after the request that caused them.
func Eventually(t T, what string, timeout time.Duration, fetch func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if fetch() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("e2e: no %s within %s", what, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
