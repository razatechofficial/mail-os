// Package port declares the hexagonal architecture port interfaces that
// decouple core business logic from infrastructure adapters (database,
// cache, queue, mailer, crypto, rendering, and eventing).
package port

import (
	"context"
	"time"
)

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
}
