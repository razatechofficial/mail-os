package rabbitmq

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
	url string
}

type consumer struct {
	url string
}

func NewPublisher(url string) port.Publisher {
	return &publisher{url: url}
}

func NewConsumer(url string) port.Consumer {
	return &consumer{url: url}
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	return fmt.Errorf("rabbitmq queue: not implemented")
}

func (p *publisher) Close() error {
	return nil
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	return fmt.Errorf("rabbitmq queue: not implemented")
}

func (c *consumer) Close() error {
	return nil
}
