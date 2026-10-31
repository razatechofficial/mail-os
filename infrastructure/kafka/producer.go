package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/razatechofficial/mail-os/config"
)

// deliveryTimeout bounds how long a record is retried before Publish fails.
const deliveryTimeout = 30 * time.Second

// Producer publishes MailOS's audit events (FEATURE_AUDIT_STREAM). Each
// publish waits for every in-sync replica to acknowledge it.
type Producer struct {
	cl *kgo.Client
}

// NewProducer connects to cfg's brokers; cfg.GroupID and cfg.Topics are not
// used. It does not dial until the first publish.
func NewProducer(cfg config.Kafka, opts ...Option) (*Producer, error) {
	o := newOptions(opts)
	base, err := clientOptions(cfg, o)
	if err != nil {
		return nil, err
	}
	kopts := append([]kgo.Opt{
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordDeliveryTimeout(deliveryTimeout),
	}, base...)
	cl, err := kgo.NewClient(kopts...)
	if err != nil {
		return nil, fmt.Errorf("kafka producer: %w", err)
	}
	return &Producer{cl: cl}, nil
}

// PublishJSON publishes v as JSON on topic with key (records with the same
// key keep their order) and waits for the brokers to acknowledge it.
func (p *Producer) PublishJSON(ctx context.Context, topic, key string, v any) error {
	value, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("kafka producer: marshal for %s: %w", topic, err)
	}
	return p.Publish(ctx, topic, key, value, nil)
}

// Publish publishes value on topic with key and headers and waits for the
// brokers to acknowledge it.
func (p *Producer) Publish(ctx context.Context, topic, key string, value []byte, headers map[string]string) error {
	if topic == "" {
		return errors.New("kafka producer: a topic is required")
	}
	r := &kgo.Record{Topic: topic, Value: value}
	if key != "" {
		r.Key = []byte(key)
	}
	for k, v := range headers {
		r.Headers = append(r.Headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
	}
	if err := p.cl.ProduceSync(ctx, r).FirstErr(); err != nil {
		return fmt.Errorf("kafka producer: publish to %s: %w", topic, err)
	}
	return nil
}

// Close flushes nothing further and releases the client; publishes in
// flight fail.
func (p *Producer) Close() { p.cl.Close() }
