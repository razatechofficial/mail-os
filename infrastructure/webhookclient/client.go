// Package webhookclient posts signed webhook deliveries to the URLs
// tenants register. A tenant must not reach into the deployment (SSRF):
// the client refuses private, loopback and link-local addresses at dial
// time (unless allowed for tests), follows no redirect, uses no proxy, and
// bounds time and the response read.
package webhookclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/razatechofficial/mail-os/infrastructure/mailer"
)

// Options are the client's network rules.
type Options struct {
	Timeout              time.Duration
	AllowPrivateNetworks bool
	AllowLoopback        bool
	// TLS replaces the default client TLS (tests trust their CA here).
	TLS *tls.Config
}

// Client posts deliveries.
type Client struct {
	http *http.Client
}

// New returns a client.
func New(opts Options) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	tc := opts.TLS
	if tc == nil {
		tc = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	dialer := &net.Dialer{Timeout: opts.Timeout, Control: mailer.DialGuard(opts.AllowPrivateNetworks, opts.AllowLoopback)}
	return &Client{http: &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext, TLSClientConfig: tc, Proxy: nil,
			TLSHandshakeTimeout: opts.Timeout, ResponseHeaderTimeout: opts.Timeout, MaxIdleConnsPerHost: 2,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Post sends body with headers and returns the status (0 on a transport
// failure).
func (c *Client) Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "MailOS-Webhooks")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}
