package redisqueue

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
	addr string
}

type consumer struct {
	addr string
}

func NewPublisher(addr string) port.Publisher {
	return &publisher{addr: addr}
}

func NewConsumer(addr string) port.Consumer {
	return &consumer{addr: addr}
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	return fmt.Errorf("redis queue: not implemented")
}

func (p *publisher) Close() error {
	return nil
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	return fmt.Errorf("redis queue: not implemented")
}

func (c *consumer) Close() error {
	return nil
}
