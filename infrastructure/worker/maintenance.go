package worker

import (
	"context"
	"time"

	"github.com/hibiken/asynq"

	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Scheduled maintenance tasks.
const (
	TypeKeyManagerTick   = "keymanager:tick"
	TypeAuditOutboxRelay = "audit:outbox_relay"
	TypeAuditRetention   = "audit:retention"
	TypeIdempotencyPurge = "idempotency:purge"
)

// ExpiredPurger deletes expired Idempotency-Key responses.
type ExpiredPurger interface {
	PurgeExpired(ctx context.Context) (int64, error)
}

// IdempotencyPurge deletes Idempotency-Key responses past their TTL.
func IdempotencyPurge(p ExpiredPurger) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, _ *asynq.Task) error {
		n, err := p.PurgeExpired(ctx)
		if n > 0 {
			logger.Info("idempotency keys purged", logger.Int64("deleted", n))
		}
		return err
	}
}

// KeyTicker is the key manager schedule.
type KeyTicker interface {
	Tick(ctx context.Context) error
}

// KeyManagerTick rotates due keys, re-encrypts and destroys drained keys.
func KeyManagerTick(k KeyTicker) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, _ *asynq.Task) error { return k.Tick(ctx) }
}

// OutboxStore is the audit outbox.
type OutboxStore interface {
	ClaimOutbox(ctx context.Context, limit int, publish func(postgres.OutboxRow) error, backoff func(int) time.Duration) (int, error)
	Purge(ctx context.Context, before time.Time, limit int) (int64, error)
}

// Publisher writes to the audit stream topic.
type Publisher interface {
	Publish(ctx context.Context, topic, key string, value []byte, headers map[string]string) error
}

// AuditOutboxRelay publishes committed audit events to Kafka
// (FEATURE_AUDIT_STREAM), keyed by event id so the SIEM can deduplicate.
func AuditOutboxRelay(store OutboxStore, pub Publisher, topic string) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, _ *asynq.Task) error {
		for {
			n, err := store.ClaimOutbox(ctx, 200, func(o postgres.OutboxRow) error {
				return pub.Publish(ctx, topic, o.EventID.String(), o.Payload, map[string]string{"service": "mailos"})
			}, func(attempts int) time.Duration { return Backoff(2*time.Second, attempts, 5*time.Minute) })
			if err != nil || n < 200 {
				return err
			}
		}
	}
}

// AuditRetention deletes audit events past AUDIT_RETENTION_DAYS that the
// stream has published.
func AuditRetention(store OutboxStore, days int) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, _ *asynq.Task) error {
		before := time.Now().AddDate(0, 0, -days)
		var total int64
		for {
			n, err := store.Purge(ctx, before, 5000)
			total += n
			if err != nil {
				return err
			}
			if n < 5000 {
				break
			}
		}
		if total > 0 {
			logger.Info("audit retention", logger.Int64("deleted", total), logger.Int("days", days))
		}
		return nil
	}
}
