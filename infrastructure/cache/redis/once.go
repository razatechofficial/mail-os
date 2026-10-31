package redis

import (
	"context"
	"strconv"
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

// CountWindow increments the counter of key's current fixed window and
// returns its value; the counter expires with the window.
func (c *Client) CountWindow(ctx context.Context, key string, window time.Duration) (int64, error) {
	bucket := time.Now().UnixNano() / int64(window)
	k := key + ":" + strconv.FormatInt(bucket, 10)
	pipe := c.TxPipeline()
	incr := pipe.Incr(ctx, k)
	pipe.Expire(ctx, k, window+time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}
