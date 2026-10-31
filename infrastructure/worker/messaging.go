package worker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hibiken/asynq"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Messaging tasks.
const (
	TypeMessageSend      = "message:send"
	TypeMessageRelease   = "message:release"   // scheduled messages and the stale sweep
	TypeMessageRetention = "message:retention" // body purge
	TypeWebhookDeliver   = "webhook:deliver"
)

type sendPayload struct {
	TenantID  string `json:"tenant_id"`
	MessageID string `json:"message_id"`
}

type webhookPayload struct {
	DeliveryID string `json:"delivery_id"`
}

// MessageQueue queues sends and webhook deliveries.
type MessageQueue struct {
	e        *Enqueuer
	maxRetry int
	timeout  time.Duration
}

// NewMessageQueue returns the queue; maxRetry is WORKER_MAX_RETRY and
// timeout bounds one send (WORKER_SEND_TIMEOUT).
func NewMessageQueue(e *Enqueuer, maxRetry int, timeout time.Duration) *MessageQueue {
	return &MessageQueue{e: e, maxRetry: maxRetry, timeout: timeout}
}

// queueFor puts transactional mail on the critical queue, campaigns and
// every broadcast-stream message low: the streams never share a queue.
func queueFor(m domainmsg.Message) string {
	if m.Stream == domainmsg.StreamBroadcast {
		return QueueLow
	}
	switch m.Type {
	case domainmsg.TypeTransactional:
		return QueueCritical
	case domainmsg.TypeMarketing:
		return QueueLow
	}
	return QueueDefault
}

// EnqueueSend queues m's delivery. The task id is the message id, so a
// message already queued (or waiting to retry) is not queued twice.
func (q *MessageQueue) EnqueueSend(ctx context.Context, m domainmsg.Message) error {
	raw, _ := json.Marshal(sendPayload{TenantID: m.OrgID, MessageID: m.ID})
	return q.e.Enqueue(ctx, TypeMessageSend, raw, asynq.Queue(queueFor(m)), asynq.TaskID("send:"+m.ID),
		asynq.MaxRetry(q.maxRetry), asynq.Timeout(q.timeout+10*time.Second))
}

// EnqueueWebhook queues one delivery.
func (q *MessageQueue) EnqueueWebhook(ctx context.Context, deliveryID string) error {
	raw, _ := json.Marshal(webhookPayload{DeliveryID: deliveryID})
	return q.e.Enqueue(ctx, TypeWebhookDeliver, raw, asynq.Queue(QueueDefault), asynq.TaskID("webhook:"+deliveryID),
		asynq.MaxRetry(q.maxRetry), asynq.Timeout(30*time.Second))
}

// Deliverer sends one message.
type Deliverer interface {
	Deliver(ctx context.Context, tenantID, id string) error
}

// missingRetries is how often a send whose message row is not visible yet
// is retried: an event's message is queued inside the inbound
// transaction, so the task can run before the commit.
const missingRetries = 3

// MessageSend runs a delivery. A RetryError is retried after the
// provider's Retry-After or the jittered backoff (RetryDelay); a message
// that is not there is retried a few times (its transaction may not have
// committed), then dropped. The sweep requeues anything left queued.
func MessageSend(d Deliverer) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, t *asynq.Task) error {
		var p sendPayload
		if err := json.Unmarshal(t.Payload(), &p); err != nil || p.MessageID == "" {
			return errors.Join(asynq.SkipRetry, errors.New("malformed send task"))
		}
		err := d.Deliver(ctx, p.TenantID, p.MessageID)
		if apperrors.IsNotFound(err) {
			if n, _ := asynq.GetRetryCount(ctx); n < missingRetries {
				return err
			}
			return errors.Join(asynq.SkipRetry, err)
		}
		return err
	}
}

// WebhookDeliverer posts one delivery; final marks the last attempt.
type WebhookDeliverer interface {
	Deliver(ctx context.Context, deliveryID string, final bool) error
}

// WebhookDeliver runs a webhook delivery with retries.
func WebhookDeliver(d WebhookDeliverer) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, t *asynq.Task) error {
		var p webhookPayload
		if err := json.Unmarshal(t.Payload(), &p); err != nil || p.DeliveryID == "" {
			return errors.Join(asynq.SkipRetry, errors.New("malformed webhook task"))
		}
		n, _ := asynq.GetRetryCount(ctx)
		limit, _ := asynq.GetMaxRetry(ctx)
		err := d.Deliver(ctx, p.DeliveryID, n >= limit)
		if apperrors.IsNotFound(err) {
			return errors.Join(asynq.SkipRetry, err)
		}
		return err
	}
}

// Releaser releases scheduled messages and requeues lost ones.
type Releaser interface {
	ReleaseScheduled(ctx context.Context) (int, error)
	Sweep(ctx context.Context) (int, error)
}

// MessageRelease is the scheduler tick.
func MessageRelease(r Releaser) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, _ *asynq.Task) error {
		released, err := r.ReleaseScheduled(ctx)
		if err != nil {
			return err
		}
		swept, err := r.Sweep(ctx)
		if released+swept > 0 {
			logger.Info("messages released", logger.Int("scheduled", released), logger.Int("requeued", swept))
		}
		return err
	}
}

// Purger erases bodies past retention.
type Purger interface {
	Purge(ctx context.Context) (map[string]int, error)
}

// MessageRetention runs the purge.
func MessageRetention(p Purger) func(context.Context, *asynq.Task) error {
	return func(ctx context.Context, _ *asynq.Task) error {
		counts, err := p.Purge(ctx)
		total := 0
		for _, n := range counts {
			total += n
		}
		if total > 0 {
			logger.Info("message bodies purged", logger.Int("count", total), logger.Int("tenants", len(counts)))
		}
		return err
	}
}
