package redis

import (
	"context"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// takeScript adds ARGV[1] to KEYS[1] unless that would pass ARGV[2], in
// one step, and gives a new counter its lifetime (ARGV[3] ms). A negative
// amount (returning what was taken) is always applied.
var takeScript = goredis.NewScript(`
local n = tonumber(ARGV[1])
local v = redis.call('INCRBY', KEYS[1], n)
if n > 0 and v > tonumber(ARGV[2]) then
  redis.call('DECRBY', KEYS[1], n)
  return 0
end
if redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
end
return 1`)

// Take counts n against limit on key, atomically: the application quotas
// and rates (application/applications.Counter). It returns false, adding
// nothing, when the total would pass limit.
func (c *Client) Take(ctx context.Context, key string, n, limit int64, ttl time.Duration) (bool, error) {
	ok, err := takeScript.Run(ctx, c.Client, []string{key}, n, limit, ttl.Milliseconds()).Int()
	return ok == 1, err
}

// Peek reads a counter; an absent key is 0.
func (c *Client) Peek(ctx context.Context, key string) (int64, error) {
	v, err := c.Get(ctx, key).Int64()
	if errors.Is(err, goredis.Nil) {
		return 0, nil
	}
	return v, err
}
