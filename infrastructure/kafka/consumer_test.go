package kafka

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/domain/event"
)

const testTopic = "iam.auth.password_reset_requested"

// newCluster starts an in-memory cluster with testTopic (one partition, so
// offsets are the produce order).
func newCluster(t *testing.T, opts ...kfake.Opt) (*kfake.Cluster, config.Kafka) {
	t.Helper()
	c, err := kfake.NewCluster(append([]kfake.Opt{kfake.NumBrokers(1), kfake.SeedTopics(1, testTopic)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, config.Kafka{Brokers: c.ListenAddrs(), GroupID: "mailos-test"}
}

func publish(t *testing.T, cfg config.Kafka, values ...string) {
	t.Helper()
	p, err := NewProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, v := range values {
		if err := p.Publish(ctx, testTopic, "k-"+v, []byte(v), map[string]string{"iam-msg-sig": "sig-" + v}); err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
	}
}

// recorder is a handler that records each call and answers from script.
type recorder struct {
	mu     sync.Mutex
	calls  []Record
	script func(r Record, attempt int) error
	seen   map[int64]int
	wake   chan struct{}
}

func newRecorder(script func(r Record, attempt int) error) *recorder {
	return &recorder{script: script, seen: map[int64]int{}, wake: make(chan struct{}, 100)}
}

func (h *recorder) handle(_ context.Context, r Record) error {
	h.mu.Lock()
	h.calls = append(h.calls, r)
	attempt := h.seen[r.Offset]
	h.seen[r.Offset]++
	h.mu.Unlock()
	defer func() { h.wake <- struct{}{} }()
	if h.script == nil {
		return nil
	}
	return h.script(r, attempt)
}

func (h *recorder) offsets() []int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]int64, len(h.calls))
	for i, c := range h.calls {
		out[i] = c.Offset
	}
	return out
}

// waitCalls waits until the handler was called n times.
func (h *recorder) waitCalls(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for len(h.offsets()) < n {
		select {
		case <-h.wake:
		case <-deadline:
			t.Fatalf("handler called %v, want %d calls", h.offsets(), n)
		}
	}
}

func startConsumer(t *testing.T, cfg config.Kafka, h *recorder) (*Consumer, chan error) {
	t.Helper()
	c, err := NewConsumer(cfg, []string{testTopic}, h.handle, WithBackoff(5*time.Millisecond, 20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Run(context.Background()) }()
	t.Cleanup(c.Close)
	return c, done
}

func equalOffsets(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

var errTransient = errors.New("database unavailable")

func TestConsumerRetriesTransientAndCommitsAfterRejection(t *testing.T) {
	_, cfg := newCluster(t)
	publish(t, cfg, "a", "b", "c")

	h := newRecorder(func(r Record, attempt int) error {
		switch r.Offset {
		case 1:
			if attempt < 2 {
				return errTransient
			}
		case 2:
			return event.Reject(event.ReasonBadSignature, nil)
		}
		return nil
	})
	c, done := startConsumer(t, cfg, h)
	h.waitCalls(t, 5)
	c.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Offset 1 is redelivered in place; nothing after it runs first.
	if got := h.offsets(); !equalOffsets(got, []int64{0, 1, 1, 1, 2}) {
		t.Fatalf("handled offsets %v", got)
	}
	first := h.calls[0]
	if string(first.Key) != "k-a" || string(first.Value) != "a" || string(first.Headers["iam-msg-sig"]) != "sig-a" {
		t.Fatalf("record = %+v", first)
	}
	if first.DeliveryID() != testTopic+"/0/0" {
		t.Fatalf("DeliveryID = %q", first.DeliveryID())
	}

	// The group committed past the rejection: a new member starts at 3.
	publish(t, cfg, "d")
	h2 := newRecorder(nil)
	startConsumer(t, cfg, h2)
	h2.waitCalls(t, 1)
	if got := h2.offsets(); got[0] != 3 {
		t.Fatalf("after restart the group resumed at %v, want 3", got)
	}
}

func TestConsumerStopKeepsTheFailingRecord(t *testing.T) {
	_, cfg := newCluster(t)
	publish(t, cfg, "a", "b", "c")

	h := newRecorder(func(r Record, _ int) error {
		if r.Offset == 1 {
			return errTransient
		}
		return nil
	})
	c, done := startConsumer(t, cfg, h)
	h.waitCalls(t, 3) // 0, then 1 failing twice
	c.Close()
	<-done
	for _, o := range h.offsets() {
		if o == 2 {
			t.Fatalf("offset 2 was handled before 1 succeeded: %v", h.offsets())
		}
	}

	// Offset 0 was committed, offset 1 was not: it is delivered again.
	h2 := newRecorder(nil)
	startConsumer(t, cfg, h2)
	h2.waitCalls(t, 2)
	if got := h2.offsets(); !equalOffsets(got[:2], []int64{1, 2}) {
		t.Fatalf("after restart got %v, want 1 then 2", got)
	}
}

func TestConsumerPanicIsTransient(t *testing.T) {
	_, cfg := newCluster(t)
	publish(t, cfg, "a")
	h := newRecorder(func(_ Record, attempt int) error {
		if attempt == 0 {
			panic("boom")
		}
		return nil
	})
	startConsumer(t, cfg, h)
	h.waitCalls(t, 2)
	if got := h.offsets(); !equalOffsets(got, []int64{0, 0}) {
		t.Fatalf("handled offsets %v", got)
	}
}

func TestConsumerRunOnceAndCloseWithoutRun(t *testing.T) {
	_, cfg := newCluster(t)
	c, err := NewConsumer(cfg, []string{testTopic}, func(context.Context, Record) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close()
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("Run after Close started")
	}
}

func TestNewConsumerValidates(t *testing.T) {
	cfg := config.Kafka{Brokers: []string{"127.0.0.1:1"}, GroupID: "g"}
	ok := func(context.Context, Record) error { return nil }
	if _, err := NewConsumer(cfg, nil, ok); err == nil {
		t.Error("no topics accepted")
	}
	if _, err := NewConsumer(cfg, []string{testTopic}, nil); err == nil {
		t.Error("no handler accepted")
	}
	if _, err := NewConsumer(config.Kafka{Brokers: cfg.Brokers}, []string{testTopic}, ok); err == nil {
		t.Error("no group accepted")
	}
	if _, err := NewConsumer(config.Kafka{GroupID: "g"}, []string{testTopic}, ok); err == nil {
		t.Error("no brokers accepted")
	}
	cfg.Topics = []string{testTopic}
	c, err := NewConsumer(cfg, nil, ok)
	if err != nil {
		t.Fatalf("topics from config refused: %v", err)
	}
	c.Close()
}

func TestProducerPublishJSON(t *testing.T) {
	_, cfg := newCluster(t)
	p, err := NewProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx := context.Background()
	if err := p.PublishJSON(ctx, testTopic, "tenant-1", map[string]string{"action": "template.published"}); err != nil {
		t.Fatalf("PublishJSON: %v", err)
	}
	if err := p.PublishJSON(ctx, testTopic, "k", func() {}); err == nil {
		t.Fatal("an unmarshalable value was published")
	}
	if err := p.Publish(ctx, "", "k", nil, nil); err == nil {
		t.Fatal("a record without a topic was published")
	}

	h := newRecorder(nil)
	startConsumer(t, cfg, h)
	h.waitCalls(t, 1)
	r := h.calls[0]
	if string(r.Key) != "tenant-1" || string(r.Value) != `{"action":"template.published"}` {
		t.Fatalf("record = %s %s", r.Key, r.Value)
	}
}

func TestProducerFailsWhenTheBrokerIsGone(t *testing.T) {
	c, cfg := newCluster(t)
	p, err := NewProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.PublishJSON(ctx, testTopic, "k", map[string]int{"n": 1}); err == nil {
		t.Fatal("publish to a stopped cluster succeeded")
	}
}

func TestIsPermanent(t *testing.T) {
	if !IsPermanent(errors.Join(errTransient, event.Reject(event.ReasonReplayed, nil))) {
		t.Error("a wrapped rejection is not permanent")
	}
	if IsPermanent(errTransient) || IsPermanent(nil) {
		t.Error("a plain error is permanent")
	}
}

func TestBackoffIsCappedAndJittered(t *testing.T) {
	b := backoff{min: 100 * time.Millisecond, max: time.Second}
	for attempt := 0; attempt < 70; attempt++ {
		want := b.min << attempt
		if attempt >= 4 || want <= 0 {
			want = b.max
		}
		for range 20 {
			d := b.delay(attempt)
			if d < want/2 || d > want {
				t.Fatalf("attempt %d: delay %s outside [%s, %s]", attempt, d, want/2, want)
			}
		}
	}
	if jitter(0) != 0 {
		t.Fatal("jitter(0) != 0")
	}
}
