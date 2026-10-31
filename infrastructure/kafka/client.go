// Package kafka is MailOS's Kafka client on franz-go: a consumer-group
// Consumer for the signed IAM events and a Producer for the audit stream.
// Both dial the brokers the way contract §2 requires: TLS 1.2+ (a configured
// CA or the system roots, an optional client certificate) and SASL
// SCRAM-SHA-512 or OAUTHBEARER with MailOS's own client-credentials token
// from IAM. config.Validate refuses a plaintext or unauthenticated broker
// connection outside local and test; this package builds what it is given.
package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/razatechofficial/mail-os/config"
)

// DefaultClientID names MailOS to the brokers (quotas, broker logs).
const DefaultClientID = "mailos"

// Option configures a Consumer or a Producer.
type Option func(*options)

type options struct {
	clientID       string
	httpClient     *http.Client
	handlerTimeout time.Duration
	backoff        backoff
	maxPollRecords int
	extra          []kgo.Opt
}

func newOptions(opts []Option) *options {
	o := &options{
		clientID:       DefaultClientID,
		handlerTimeout: 30 * time.Second,
		backoff:        backoff{min: 500 * time.Millisecond, max: 30 * time.Second},
		maxPollRecords: 100,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// WithClientID sets the Kafka client id (default "mailos").
func WithClientID(id string) Option {
	return func(o *options) {
		if id != "" {
			o.clientID = id
		}
	}
}

// WithHTTPClient sets the client that fetches the OAUTHBEARER token (default
// a 10 s timeout and the system roots).
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.httpClient = c }
}

// WithHandlerTimeout bounds one handler call (default 30 s).
func WithHandlerTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.handlerTimeout = d
		}
	}
}

// WithBackoff sets the redelivery delay after a transient handler error:
// it starts at minDelay and doubles up to maxDelay, with jitter (default
// 500 ms to 30 s).
func WithBackoff(minDelay, maxDelay time.Duration) Option {
	return func(o *options) {
		if minDelay > 0 && maxDelay >= minDelay {
			o.backoff = backoff{min: minDelay, max: maxDelay}
		}
	}
}

// WithKgoOptions appends raw franz-go options, applied last.
func WithKgoOptions(opts ...kgo.Opt) Option {
	return func(o *options) { o.extra = append(o.extra, opts...) }
}

// clientOptions are the franz-go options for cfg's brokers, TLS and SASL.
func clientOptions(cfg config.Kafka, o *options) ([]kgo.Opt, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafka: no brokers configured")
	}
	opts := []kgo.Opt{kgo.SeedBrokers(cfg.Brokers...), kgo.ClientID(o.clientID)}
	if cfg.TLS.Enabled {
		tc, err := TLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.DialTLSConfig(tc))
	}
	mech, err := saslMechanism(cfg.SASL, o)
	if err != nil {
		return nil, err
	}
	if mech != nil {
		opts = append(opts, kgo.SASL(mech))
	}
	return append(opts, o.extra...), nil
}

// TLSConfig is the client TLS for the brokers: TLS 1.2 or later, the server
// verified against CAFile (or the system roots), and MailOS's client
// certificate when one is configured. An empty ServerName verifies each
// broker against the host it is dialled by.
func TLSConfig(c config.ClientTLS) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ServerName}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("kafka tls: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kafka tls: %s holds no PEM certificate", c.CAFile)
		}
		tc.RootCAs = pool
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("kafka tls: the client certificate and key must be set together")
	}
	if c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("kafka tls: load client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

// saslMechanism is the configured SASL mechanism, or nil for none.
func saslMechanism(c config.SASL, o *options) (sasl.Mechanism, error) {
	switch c.Mechanism {
	case "", config.SASLNone:
		return nil, nil
	case config.SASLScramSHA512:
		if c.Username == "" || c.Password == "" {
			return nil, errors.New("kafka sasl: SCRAM-SHA-512 needs a username and password")
		}
		return scram.Auth{User: c.Username, Pass: c.Password}.AsSha512Mechanism(), nil
	case config.SASLOAuthBearer:
		ts, err := NewTokenSource(c, o.httpClient)
		if err != nil {
			return nil, err
		}
		return ts.Mechanism(), nil
	default:
		return nil, fmt.Errorf("kafka sasl: unsupported mechanism %q", c.Mechanism)
	}
}
