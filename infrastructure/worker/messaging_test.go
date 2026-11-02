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

func (f deliverFunc) Deliver(ctx context.Context, tenantID, id string) error {
	return f(ctx, tenantID, id)
}

func TestMessageSendHonoursRetryAfterAndRetriesMissing(t *testing.T) {
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
	// Outside a task context (retry count unknown, 0) a missing row is
	// retried: its transaction may not have committed yet.
	err = MessageSend(deliverFunc(func(context.Context, string, string) error { return apperrors.NotFound("gone") }))(context.Background(), task)
	if err == nil || errors.Is(err, asynq.SkipRetry) {
		t.Fatal("a not-yet-committed message is dropped at once")
	}
	if err := MessageSend(nil)(context.Background(), asynq.NewTask(TypeMessageSend, []byte("{"))); !errors.Is(err, asynq.SkipRetry) {
		t.Fatal("malformed task retried")
	}
}

func TestQueueForTypeAndStream(t *testing.T) {
	of := func(typ domainmsg.Type, st domainmsg.Stream) string {
		return queueFor(domainmsg.Message{Type: typ, Stream: st})
	}
	if of(domainmsg.TypeTransactional, "") != QueueCritical || of(domainmsg.TypeMarketing, "") != QueueLow ||
		of(domainmsg.TypeNotification, domainmsg.StreamTransactional) != QueueDefault {
		t.Fatal("queue mapping")
	}
	if of(domainmsg.TypeTransactional, domainmsg.StreamBroadcast) != QueueLow {
		t.Fatal("a broadcast stream shared the transactional queue")
	}
}
