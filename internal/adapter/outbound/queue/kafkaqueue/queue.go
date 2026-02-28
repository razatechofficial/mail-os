package kafkaqueue

import (
	"context"
	"fmt"

	"github.com/razatechofficial/mail-os/internal/port"
)

var (
	_ port.Publisher = (*publisher)(nil)
	_ port.Consumer  = (*consumer)(nil)
)

type publisher struct {
	brokers string
}

type consumer struct {
	brokers string
}

func NewPublisher(brokers string) port.Publisher {
	return &publisher{brokers: brokers}
}

func NewConsumer(brokers string) port.Consumer {
	return &consumer{brokers: brokers}
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	return fmt.Errorf("kafka queue: not implemented")
}

func (p *publisher) Close() error {
	return nil
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	return fmt.Errorf("kafka queue: not implemented")
}

func (c *consumer) Close() error {
	return nil
}
