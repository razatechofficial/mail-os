package redis

import (
	"context"
	"time"
)

// ClaimOnce records key for ttl and reports whether this call was the first
// to do so (SET NX). Replay guards use it: a second presentation of the same
// proof or signature id within its lifetime gets false. An error means the
// guard could not answer; callers fail closed.
func (c *Client) ClaimOnce(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if ttl < time.Second {
		ttl = time.Second
	}
	return c.SetNX(ctx, key, 1, ttl).Result()
}
