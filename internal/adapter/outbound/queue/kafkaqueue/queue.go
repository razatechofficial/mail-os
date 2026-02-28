package kafkaqueue

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"

	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

var (
	_ port.Publisher = (*publisher)(nil)
	_ port.Consumer  = (*consumer)(nil)
)

const (
	consumerGroup = "mailos-workers"
	writeTimeout  = 10 * time.Second
	readTimeout   = 10 * time.Second
	commitInterval = 1 * time.Second
	minBytes      = 1
	maxBytes      = 10 * 1024 * 1024 // 10 MB
)

type publisher struct {
	brokers []string
	writers map[string]*kafka.Writer
}

type consumer struct {
	brokers []string
}

func NewPublisher(brokers string) port.Publisher {
	return &publisher{
		brokers: strings.Split(brokers, ","),
		writers: make(map[string]*kafka.Writer),
	}
}

func NewConsumer(brokers string) port.Consumer {
	return &consumer{
		brokers: strings.Split(brokers, ","),
	}
}

func (p *publisher) writerFor(topic string) *kafka.Writer {
	if w, ok := p.writers[topic]; ok {
		return w
	}
	w := &kafka.Writer{
		Addr:         kafka.TCP(p.brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: writeTimeout,
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}
	p.writers[topic] = w
	return w
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	o := port.ApplyPublishOptions(opts...)

	headers := []kafka.Header{}
	if o.Delay > 0 {
		deliverAt := time.Now().Add(o.Delay).Format(time.RFC3339Nano)
		headers = append(headers, kafka.Header{Key: "deliver-at", Value: []byte(deliverAt)})
	}

	return p.writerFor(topic).WriteMessages(ctx, kafka.Message{
		Value:   payload,
		Headers: headers,
	})
}

func (p *publisher) Close() error {
	var firstErr error
	for _, w := range p.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	p, err := c.ensureTopic(topic)
	if err != nil {
		logger.Warn("kafka: topic auto-create not available, assuming topic exists",
			logger.String("topic", topic), logger.Err(err))
	} else {
		p.Close()
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        c.brokers,
		GroupID:        consumerGroup,
		Topic:          topic,
		MinBytes:       minBytes,
		MaxBytes:       maxBytes,
		ReadBackoffMin: 200 * time.Millisecond,
		ReadBackoffMax: 2 * time.Second,
		CommitInterval: commitInterval,
		StartOffset:    kafka.LastOffset,
	})

	go func() {
		defer reader.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			msg, err := reader.FetchMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Warn("kafka: fetch error", logger.Err(err))
				time.Sleep(500 * time.Millisecond)
				continue
			}

			if sleep := getDelayDuration(msg.Headers); sleep > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(sleep):
				}
			}

			if err := handler(ctx, msg.Value); err != nil {
				logger.Warn("kafka: handler failed",
					logger.String("topic", topic), logger.Err(err))
				continue
			}

			if err := reader.CommitMessages(ctx, msg); err != nil {
				logger.Warn("kafka: commit failed", logger.Err(err))
			}
		}
	}()

	return nil
}

func (c *consumer) ensureTopic(topic string) (*kafka.Conn, error) {
	if len(c.brokers) == 0 {
		return nil, fmt.Errorf("no brokers configured")
	}
	conn, err := kafka.Dial("tcp", c.brokers[0])
	if err != nil {
		return nil, err
	}
	return conn, conn.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     3,
		ReplicationFactor: 1,
	})
}

func getDelayDuration(headers []kafka.Header) time.Duration {
	for _, h := range headers {
		if h.Key == "deliver-at" {
			t, err := time.Parse(time.RFC3339Nano, string(h.Value))
			if err == nil {
				d := time.Until(t)
				if d > 0 {
					return d
				}
			}
		}
	}
	return 0
}

func (c *consumer) Close() error {
	return nil
}
