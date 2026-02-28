package rabbitmq

import (
	"context"
	"fmt"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

var (
	_ port.Publisher = (*publisher)(nil)
	_ port.Consumer  = (*consumer)(nil)
)

const (
	reconnectDelay = 3 * time.Second
	publishTimeout = 10 * time.Second
)

type publisher struct {
	url  string
	mu   sync.Mutex
	conn *amqp.Connection
	ch   *amqp.Channel
}

type consumer struct {
	url  string
	conn *amqp.Connection
}

func NewPublisher(url string) port.Publisher {
	return &publisher{url: url}
}

func NewConsumer(url string) port.Consumer {
	return &consumer{url: url}
}

func (p *publisher) connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ch != nil {
		return nil
	}

	conn, err := amqp.Dial(p.url)
	if err != nil {
		return fmt.Errorf("rabbitmq: dial: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("rabbitmq: open channel: %w", err)
	}

	p.conn = conn
	p.ch = ch
	return nil
}

func (p *publisher) ensureQueue(name string) error {
	_, err := p.ch.QueueDeclare(name, true, false, false, false, amqp.Table{
		"x-queue-type": "quorum",
	})
	return err
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	if err := p.connect(); err != nil {
		return err
	}

	o := port.ApplyPublishOptions(opts...)

	if err := p.ensureQueue(topic); err != nil {
		return fmt.Errorf("rabbitmq: declare queue: %w", err)
	}

	headers := amqp.Table{}
	if o.Delay > 0 {
		headers["x-delay"] = int64(o.Delay.Milliseconds())
	}

	pubCtx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()

	return p.ch.PublishWithContext(pubCtx, "", topic, false, false, amqp.Publishing{
		DeliveryMode: amqp.Persistent,
		ContentType:  "application/octet-stream",
		Body:         payload,
		Headers:      headers,
	})
}

func (p *publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ch != nil {
		p.ch.Close()
	}
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	conn, err := amqp.Dial(c.url)
	if err != nil {
		return fmt.Errorf("rabbitmq: dial: %w", err)
	}
	c.conn = conn

	ch, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("rabbitmq: open channel: %w", err)
	}

	if err := ch.Qos(10, 0, false); err != nil {
		return fmt.Errorf("rabbitmq: set qos: %w", err)
	}

	_, err = ch.QueueDeclare(topic, true, false, false, false, amqp.Table{
		"x-queue-type": "quorum",
	})
	if err != nil {
		return fmt.Errorf("rabbitmq: declare queue: %w", err)
	}

	msgs, err := ch.Consume(topic, "", false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("rabbitmq: consume: %w", err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				ch.Close()
				return
			case msg, ok := <-msgs:
				if !ok {
					logger.Warn("rabbitmq: delivery channel closed, reconnecting")
					time.Sleep(reconnectDelay)
					if err := c.Subscribe(ctx, topic, handler); err != nil {
						logger.Error("rabbitmq: reconnect failed", logger.Err(err))
					}
					return
				}
				if err := handler(ctx, msg.Body); err != nil {
					logger.Warn("rabbitmq: handler failed, nacking",
						logger.String("topic", topic), logger.Err(err))
					msg.Nack(false, true)
					continue
				}
				msg.Ack(false)
			}
		}
	}()

	return nil
}

func (c *consumer) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
