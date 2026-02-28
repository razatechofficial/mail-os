package rediscache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/razatechofficial/mail-os/internal/port"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type cache struct {
	rdb *redis.Client
}

func NewCache(client *Client) port.Cache {
	return &cache{rdb: client.Redis()}
}

func (c *cache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, apperrors.ErrNotFound
	}
	return val, err
}

func (c *cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

func (c *cache) Delete(ctx context.Context, key string) error {
	return c.rdb.Del(ctx, key).Err()
}

func (c *cache) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, key).Result()
	return n > 0, err
}

var _ port.Cache = (*cache)(nil)
