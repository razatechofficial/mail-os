package kafka

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Record is one consumed message.
type Record struct {
	Topic string
	Key   []byte
	Value []byte
	// Headers holds the record's headers; when a key repeats, the first wins.
	Headers   map[string][]byte
	Partition int32
	Offset    int64
}

// DeliveryID names this record ("topic/partition/offset"). A redelivery of
// the record has the same id; a copy republished elsewhere does not.
func (r Record) DeliveryID() string {
	return r.Topic + "/" + strconv.FormatInt(int64(r.Partition), 10) + "/" + strconv.FormatInt(r.Offset, 10)
}

// Handler processes one record. nil, or an error that reports Permanent()
// (an *event.Rejection), commits the record; any other error is transient
// and the record is delivered again after a backoff.
type Handler func(ctx context.Context, r Record) error

// IsPermanent reports whether err, or an error it wraps, has a
// Permanent() bool method that returns true.
func IsPermanent(err error) bool {
	var p interface{ Permanent() bool }
	return errors.As(err, &p) && p.Permanent()
}

// Consumer reads topics as a member of a consumer group, at least once:
// each partition's records reach the handler in order, an offset is
// committed only after the handler accepted or permanently rejected the
// record, and a record that failed transiently is retried (exponential
// backoff with jitter) before any later record of the batch. A new group
// starts at the earliest retained offset; expired signatures there are
// rejected, never silently skipped.
type Consumer struct {
	cl             *kgo.Client
	handler        Handler
	handlerTimeout time.Duration
	backoff        backoff
	maxPollRecords int

	mu        sync.Mutex
	started   bool
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
}

// NewConsumer joins cfg.GroupID on cfg's brokers for topics (cfg.Topics
// when topics is empty) and hands every record to handler. It does not
// connect until Run.
func NewConsumer(cfg config.Kafka, topics []string, handler Handler, opts ...Option) (*Consumer, error) {
	if handler == nil {
		return nil, errors.New("kafka consumer: a handler is required")
	}
	if len(topics) == 0 {
		topics = cfg.Topics
	}
	if len(topics) == 0 {
		return nil, errors.New("kafka consumer: no topics to consume")
	}
	if cfg.GroupID == "" {
		return nil, errors.New("kafka consumer: a group id is required")
	}
	o := newOptions(opts)
	base, err := clientOptions(cfg, o)
	if err != nil {
		return nil, err
	}
	kopts := append([]kgo.Opt{
		kgo.ConsumerGroup(cfg.GroupID),
		kgo.ConsumeTopics(topics...),
		// Commit only what the handler marked, and keep a rebalance from
		// moving partitions while a polled batch is being handled.
		kgo.AutoCommitMarks(),
		kgo.BlockRebalanceOnPoll(),
	}, base...)
	cl, err := kgo.NewClient(kopts...)
	if err != nil {
		return nil, fmt.Errorf("kafka consumer: %w", err)
	}
	return &Consumer{
		cl:             cl,
		handler:        handler,
		handlerTimeout: o.handlerTimeout,
		backoff:        o.backoff,
		maxPollRecords: o.maxPollRecords,
	}, nil
}

// Run consumes until ctx is done or Close is called, then commits what was
// handled and leaves the group. A handler call in flight finishes (bounded
// by the handler timeout); a backoff wait does not. Run may be called once.
func (c *Consumer) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("kafka consumer: already run")
	}
	c.started = true
	ctx, c.cancel = context.WithCancel(ctx)
	c.done = make(chan struct{})
	c.mu.Unlock()
	defer close(c.done)
	defer c.release()

	for {
		fetches := c.cl.PollRecords(ctx, c.maxPollRecords)
		if fetches.IsClientClosed() || ctx.Err() != nil {
			return nil
		}
		fetches.EachError(func(topic string, partition int32, err error) {
			logger.Warn("kafka consumer: fetch error",
				logger.String("topic", topic), logger.Int("partition", int(partition)), logger.Err(err))
		})
		stopped := false
		for _, kr := range fetches.Records() {
			if ctx.Err() != nil || !c.handle(ctx, kr) {
				stopped = true
				break
			}
			c.cl.MarkCommitRecords(kr)
		}
		c.commit()
		c.cl.AllowRebalance()
		if stopped {
			return nil
		}
	}
}

// Close stops Run, waits for it to commit and leave the group, and releases
// the client. It is safe to call more than once and without Run.
func (c *Consumer) Close() {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.started = true // a Run after Close refuses to start
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	c.release()
}

func (c *Consumer) release() {
	c.closeOnce.Do(func() {
		c.commit()
		c.cl.AllowRebalance()
		c.cl.Close()
	})
}

// commit commits the marked offsets; AutoCommitMarks retries a failure.
func (c *Consumer) commit() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.cl.CommitMarkedOffsets(ctx); err != nil {
		logger.Warn("kafka consumer: commit offsets", logger.Err(err))
	}
}

// handle delivers kr until the handler accepts or permanently rejects it,
// and reports false if ctx ended first (the record stays uncommitted).
func (c *Consumer) handle(ctx context.Context, kr *kgo.Record) bool {
	r := toRecord(kr)
	for attempt := 0; ; attempt++ {
		err := c.call(ctx, r)
		if err == nil {
			return true
		}
		if IsPermanent(err) {
			logger.Warn("kafka consumer: record rejected",
				logger.String("topic", r.Topic), logger.Int("partition", int(r.Partition)),
				logger.Int64("offset", r.Offset), logger.Err(err))
			return true
		}
		delay := c.backoff.delay(attempt)
		logger.Warn("kafka consumer: handler failed, redelivering",
			logger.String("topic", r.Topic), logger.Int("partition", int(r.Partition)),
			logger.Int64("offset", r.Offset), logger.Int("attempt", attempt+1),
			logger.Duration("backoff", delay), logger.Err(err))
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
}

// call runs the handler once. It is not cancelled by a stop, so the record
// in flight is finished; a panic is a transient failure.
func (c *Consumer) call(ctx context.Context, r Record) (err error) {
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.handlerTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("handler panic: %v", p)
		}
	}()
	return c.handler(hctx, r)
}

func toRecord(kr *kgo.Record) Record {
	headers := make(map[string][]byte, len(kr.Headers))
	for _, h := range kr.Headers {
		if _, seen := headers[h.Key]; !seen {
			headers[h.Key] = h.Value
		}
	}
	return Record{
		Topic:     kr.Topic,
		Key:       kr.Key,
		Value:     kr.Value,
		Headers:   headers,
		Partition: kr.Partition,
		Offset:    kr.Offset,
	}
}

// backoff is capped exponential backoff with "equal jitter": half the delay
// is fixed and half random, so retries of many replicas spread out.
type backoff struct {
	min, max time.Duration
}

func (b backoff) delay(attempt int) time.Duration {
	d := b.max
	if attempt < 32 {
		if next := b.min << attempt; next > 0 && next < b.max {
			d = next
		}
	}
	half := d / 2
	return half + jitter(d-half)
}

// jitter is a uniform random duration in [0, n], from crypto/rand.
func jitter(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)+1))
	if err != nil {
		return n
	}
	return time.Duration(v.Int64())
}
