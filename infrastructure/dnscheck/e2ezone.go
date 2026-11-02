package dnscheck

import (
	"context"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// E2EZone stands in for DNS when the test-only hooks are on
// (MAILOS_E2E_HOOKS), as the mail sink stands in for SMTP: the black-box
// suite publishes the TXT records a domain asks for through the hook
// route, and verification reads them back. It is never used otherwise.
type E2EZone struct {
	rdb *goredis.Client
}

// NewE2EZone keeps the zone in Redis, shared by the server and the worker.
func NewE2EZone(rdb *goredis.Client) *E2EZone { return &E2EZone{rdb: rdb} }

func zoneKey(name string) string {
	return "mailos:e2e:dns:" + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// Publish replaces the TXT values at name for a day.
func (z *E2EZone) Publish(ctx context.Context, name string, values []string) error {
	key := zoneKey(name)
	pipe := z.rdb.TxPipeline()
	pipe.Del(ctx, key)
	for _, v := range values {
		pipe.RPush(ctx, key, v)
	}
	pipe.Expire(ctx, key, 24*time.Hour)
	_, err := pipe.Exec(ctx)
	return err
}

// LookupTXT returns what was published at name (none when nothing was).
func (z *E2EZone) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return z.rdb.LRange(ctx, zoneKey(name), 0, -1).Result()
}
