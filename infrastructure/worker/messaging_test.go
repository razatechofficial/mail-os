package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hibiken/asynq"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type deliverFunc func(ctx context.Context, tenantID, id string) error

func (f deliverFunc) Deliver(ctx context.Context, tenantID, id string) error { return f(ctx, tenantID, id) }

func TestMessageSendHonoursRetryAfterAndSkipsMissing(t *testing.T) {
	task := asynq.NewTask(TypeMessageSend, []byte(`{"tenant_id":"t1","message_id":"m1"}`))
	retry := &appmsg.RetryError{Err: errors.New("429"), After: 45 * time.Minute}
	err := MessageSend(deliverFunc(func(_ context.Context, tenant, id string) error {
		if tenant != "t1" || id != "m1" {
			t.Fatal(tenant, id)
		}
		return retry
	}))(context.Background(), task)
	if d := RetryDelay(0, err, task); d < 44*time.Minute {
		t.Fatalf("Retry-After ignored: %v", d)
	}
	err = MessageSend(deliverFunc(func(context.Context, string, string) error { return apperrors.NotFound("gone") }))(context.Background(), task)
	if !errors.Is(err, asynq.SkipRetry) {
		t.Fatal("a missing message is retried")
	}
	if err := MessageSend(nil)(context.Background(), asynq.NewTask(TypeMessageSend, []byte("{"))); !errors.Is(err, asynq.SkipRetry) {
		t.Fatal("malformed task retried")
	}
}

func TestQueueForType(t *testing.T) {
	if queueFor(domainmsg.TypeTransactional) != QueueCritical || queueFor(domainmsg.TypeMarketing) != QueueLow || queueFor(domainmsg.TypeNotification) != QueueDefault {
		t.Fatal("queue mapping")
	}
}
