// Package mailer hands messages to mail providers: an SMTP relay (STARTTLS
// or implicit TLS, DKIM-signed) and the HTTPS APIs of Amazon SES,
// SendGrid, Mailgun and Postmark. Every failure comes back as a
// message.SendError, classified permanent or transient, so the queue knows
// whether to retry and the Router whether to try the tenant's next
// provider.
//
// Transport rules (contract §2): TLS 1.2 or later with certificate
// verification everywhere; plaintext SMTP and http:// API URLs only when
// the caller says the environment allows plaintext (local and test).
// Redirects are never followed, so credentials cannot be carried to
// another host.
package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// Sender hands one message to a provider.
type Sender interface {
	// Send returns the provider's id for the message, or a
	// *message.SendError.
	Send(ctx context.Context, out message.Outgoing) (Result, error)
}

// Result is a provider's acceptance.
type Result struct {
	// ProviderMessageID is the provider's id (SMTP: the Message-ID
	// header), used to match delivery webhooks.
	ProviderMessageID string
	// ProviderID is the tenant provider that sent it; empty for the
	// platform relay. Set by the Router.
	ProviderID string
	// Kind is the provider kind that sent it. Set by the Router.
	Kind provider.Kind
}

// Options are the senders' network rules.
type Options struct {
	// Timeout bounds one exchange with a provider (default 30s).
	Timeout time.Duration
	// Attempts is how many times an HTTP send is tried when the provider
	// says it did not take the message (429, 503) or could not be dialled
	// (default 2). Other transient failures go back to the queue, which
	// owns retries: a retry after an ambiguous failure can send twice.
	Attempts int
	// BackoffBase is the first wait between attempts (default 500ms).
	BackoffBase time.Duration
	// MaxRetryAfter is the longest Retry-After waited in place (default
	// 10s); a longer one is returned to the queue in the error.
	MaxRetryAfter time.Duration
	// RootCAs replaces the system roots (private CAs, tests).
	RootCAs *x509.CertPool
	// AllowPlaintext permits SMTP tls_mode none and http:// base URLs.
	// Set it from config.App.AllowsPlaintext().
	AllowPlaintext bool
	// AllowPrivateNetworks and AllowLoopback let tenant SMTP hosts resolve
	// to private or loopback addresses. Off by default: a tenant must not
	// reach into the deployment (SSRF). The platform relay is exempt.
	AllowPrivateNetworks bool
	AllowLoopback        bool
	// BaseURLs override the API roots per kind (tests, regional
	// endpoints), e.g. {ses: "https://127.0.0.1:4443"}.
	BaseURLs map[provider.Kind]string
	// HELOName is the name sent in EHLO (default "localhost").
	HELOName string
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.Attempts <= 0 {
		o.Attempts = 2
	}
	if o.BackoffBase <= 0 {
		o.BackoffBase = 500 * time.Millisecond
	}
	if o.MaxRetryAfter <= 0 {
		o.MaxRetryAfter = 10 * time.Second
	}
	if o.HELOName == "" {
		o.HELOName = "localhost"
	}
	return o
}

func (o Options) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs, ServerName: serverName}
}

// baseURL returns the override for kind, or def. The URL must be https
// unless plaintext is allowed.
func (o Options) baseURL(kind provider.Kind, def string) (string, error) {
	raw := def
	if v := o.BaseURLs[kind]; v != "" {
		raw = v
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && o.AllowPlaintext)) {
		return "", message.NewSendError(string(kind), message.ReasonConfig, 0, "the API URL must be an https URL")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// Backoff is the wait before attempt n+1 (n ≥ 1): base·2^(n-1) with ±20%
// jitter drawn from crypto/rand.
func Backoff(base time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < time.Hour; i++ {
		d *= 2
	}
	return d + time.Duration((unitRandom()*0.4-0.2)*float64(d))
}

// unitRandom is uniform in [0, 1).
func unitRandom() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// parseRetryAfter reads seconds or an HTTP date.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// classifyHTTP is the status rule every API shares; adapters refine it
// from the error body.
func classifyHTTP(kind provider.Kind, status int, retryAfter string) *message.SendError {
	e := &message.SendError{Provider: string(kind), Status: status}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.Reason, e.Detail = message.ReasonAuth, "the provider refused the credentials"
	case status == http.StatusTooManyRequests:
		e.Reason, e.Detail = message.ReasonRateLimited, "the provider is rate limiting"
		e.RetryAfter = parseRetryAfter(retryAfter)
	case status == http.StatusRequestTimeout:
		e.Reason, e.Detail = message.ReasonNetwork, "the provider timed out"
	case status >= 500:
		e.Reason, e.Detail = message.ReasonUnavailable, "the provider failed"
		e.RetryAfter = parseRetryAfter(retryAfter)
	case status == http.StatusNotFound:
		e.Reason, e.Detail = message.ReasonConfig, "the provider does not know the account or domain"
	default:
		e.Reason, e.Detail = message.ReasonRejected, "the provider refused the message"
	}
	return e
}

// classifyNetwork describes a transport failure without addresses or
// driver text.
func classifyNetwork(ctx context.Context, kind provider.Kind, err error) *message.SendError {
	e := &message.SendError{Provider: string(kind), Reason: message.ReasonNetwork, Err: err, Detail: "could not reach the provider"}
	var ue x509.UnknownAuthorityError
	var he x509.HostnameError
	var ce x509.CertificateInvalidError
	var ve *tls.CertificateVerificationError
	var rh tls.RecordHeaderError
	switch {
	case ctx.Err() != nil:
		e.Detail = "the send was interrupted"
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		e.Detail = "the provider did not answer in time"
	case strings.Contains(err.Error(), "refusing to connect"):
		e.Reason, e.Detail = message.ReasonConfig, "the provider's address is not allowed"
	case errors.As(err, &ue), errors.As(err, &he), errors.As(err, &ce), errors.As(err, &ve), errors.As(err, &rh),
		strings.Contains(err.Error(), "tls:"), strings.Contains(err.Error(), "x509:"):
		e.Reason, e.Detail = message.ReasonConfig, "the provider's TLS certificate is not trusted, or the handshake failed"
	}
	return e
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dialFailed reports a failure before any byte was sent, safe to retry.
func dialFailed(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// httpAPI is the HTTP exchange the API adapters share.
type httpAPI struct {
	kind   provider.Kind
	opts   Options
	client *http.Client
}

func newHTTPAPI(kind provider.Kind, opts Options) *httpAPI {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:       opts.tlsConfig(""),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: opts.Timeout,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &httpAPI{kind: kind, opts: opts, client: &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
		// A redirect could carry the API key to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// CloseIdleConnections drops pooled connections (the Router calls it when
// a provider's settings change).
func (a *httpAPI) CloseIdleConnections() { a.client.CloseIdleConnections() }

// request is one API call. prepare sets the headers (and signs) on each
// attempt; classify refines the shared status rule from the error body.
type request struct {
	url         string
	contentType string
	body        []byte
	prepare     func(*http.Request) error
	classify    func(e *message.SendError, body []byte, h http.Header)
}

// post sends r, retrying only when the provider did not take the message.
// It returns the success response's body and headers.
func (a *httpAPI) post(ctx context.Context, r request) ([]byte, http.Header, error) {
	var last *message.SendError
	for attempt := 1; attempt <= a.opts.Attempts; attempt++ {
		body, h, err, retryable := a.once(ctx, r)
		if err == nil {
			return body, h, nil
		}
		last = err
		if !retryable || attempt == a.opts.Attempts {
			break
		}
		wait := Backoff(a.opts.BackoffBase, attempt)
		if err.RetryAfter > a.opts.MaxRetryAfter {
			break
		}
		wait = max(wait, err.RetryAfter)
		select {
		case <-ctx.Done():
			return nil, nil, classifyNetwork(ctx, a.kind, ctx.Err())
		case <-time.After(wait):
		}
	}
	return nil, nil, last
}

func (a *httpAPI) once(ctx context.Context, r request) (_ []byte, _ http.Header, _ *message.SendError, retryable bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(r.body))
	if err != nil {
		return nil, nil, message.NewSendError(string(a.kind), message.ReasonConfig, 0, "the API URL is not valid"), false
	}
	req.Header.Set("Content-Type", r.contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MailOS")
	if err := r.prepare(req); err != nil {
		return nil, nil, message.NewSendError(string(a.kind), message.ReasonConfig, 0, "the request cannot be authorised"), false
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, classifyNetwork(ctx, a.kind, err), dialFailed(err) && ctx.Err() == nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return data, resp.Header, nil, false
	}
	e := classifyHTTP(a.kind, resp.StatusCode, resp.Header.Get("Retry-After"))
	if r.classify != nil {
		r.classify(e, data, resp.Header)
	}
	return nil, nil, e, resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
}
