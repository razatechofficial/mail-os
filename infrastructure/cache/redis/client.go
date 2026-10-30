// Package redis wraps the go-redis client MailOS shares between the asynq
// queues, the replay guards (message signatures, DPoP proofs) and the rate
// limits.
package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
)

// Client is the shared Redis connection pool.
type Client struct {
	*goredis.Client
	opts *goredis.Options
}

// NewClient builds the pool; TLS is used when REDIS_TLS is set (required in
// production by config validation).
func NewClient(cfg config.Redis) (*Client, error) {
	opts := &goredis.Options{
		Addr:         cfg.Addr(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	if cfg.TLS {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}
		if cfg.CAFile != "" {
			pool, err := tlsconfig.LoadPool(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("redis tls: %w", err)
			}
			tc.RootCAs = pool
		}
		opts.TLSConfig = tc
	}
	return &Client{Client: goredis.NewClient(opts), opts: opts}, nil
}

// Options are the connection options, for asynq to dial the same server.
func (c *Client) Options() *goredis.Options { return c.opts }

// Health pings the server.
func (c *Client) Health(ctx context.Context) error {
	return c.Ping(ctx).Err()
}
