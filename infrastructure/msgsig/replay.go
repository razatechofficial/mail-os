package msgsig

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ReplayKeyPrefix prefixes the key of every used jti.
const ReplayKeyPrefix = "mailos:msgsig:jti:"

// minReplayTTL keeps a record even when its expiry is about to pass.
const minReplayTTL = time.Second

// Claimer sets a key only if it is absent (Redis SET key NX with a TTL) and
// reports whether this call set it. infrastructure/cache/redis's Client
// satisfies it.
type Claimer interface {
	ClaimOnce(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// StoreReplayGuard is the ReplayGuard on a shared store (Redis): the first
// claim of a jti wins across every replica. It fails closed: when the store
// cannot answer, Use returns the error and the message is not accepted.
//
// With a delivery id it first claims jti+delivery, then the jti. A jti
// already taken is a replay only when this delivery is new: the same record
// redelivered after a failure (even a crash between the two claims) is
// accepted again, while a copy republished at another offset is not.
type StoreReplayGuard struct {
	store Claimer
	now   func() time.Time
}

// NewStoreReplayGuard keeps used jtis in store.
func NewStoreReplayGuard(store Claimer) *StoreReplayGuard {
	return &StoreReplayGuard{store: store, now: time.Now}
}

// Use implements ReplayGuard.
func (g *StoreReplayGuard) Use(ctx context.Context, jti, delivery string, expiresAt time.Time) (bool, error) {
	if g == nil || g.store == nil {
		return false, errors.New("replay guard: no store")
	}
	ttl := expiresAt.Sub(g.now())
	if ttl < minReplayTTL {
		ttl = minReplayTTL
	}
	key := ReplayKeyPrefix + jti

	newDelivery := true
	if delivery != "" {
		var err error
		newDelivery, err = g.store.ClaimOnce(ctx, key+"@"+delivery, ttl)
		if err != nil {
			return false, fmt.Errorf("replay guard: claim delivery: %w", err)
		}
	}
	fresh, err := g.store.ClaimOnce(ctx, key, ttl)
	if err != nil {
		return false, fmt.Errorf("replay guard: claim jti: %w", err)
	}
	return !fresh && newDelivery, nil
}
