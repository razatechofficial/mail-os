package natsqueue

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

var (
	_ port.Publisher = (*publisher)(nil)
	_ port.Consumer  = (*consumer)(nil)
)

const (
	streamName    = "MAILOS"
	durableName   = "mailos-workers"
	ackWait       = 30 * time.Second
	fetchTimeout  = 5 * time.Second
	maxDeliver    = 5
	reconnectWait = 2 * time.Second
	maxReconnects = 60
	connTimeout   = 10 * time.Second
)

type publisher struct {
	url string
	nc  *nats.Conn
	js  jetstream.JetStream
}

type consumer struct {
	url string
	nc  *nats.Conn
}

func NewPublisher(url string) port.Publisher {
	return &publisher{url: url}
}

func NewConsumer(url string) port.Consumer {
	return &consumer{url: url}
}

func connect(url string) (*nats.Conn, jetstream.JetStream, error) {
	nc, err := nats.Connect(url,
		nats.Timeout(connTimeout),
		nats.PingInterval(20*time.Second),
		nats.ReconnectWait(reconnectWait),
		nats.MaxReconnects(maxReconnects),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Warn("nats: disconnected", logger.Err(err))
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Info("nats: reconnected")
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("nats: connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, fmt.Errorf("nats: jetstream: %w", err)
	}

	return nc, js, nil
}

func (p *publisher) ensureStream(ctx context.Context, topic string) error {
	_, err := p.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      streamName,
		Subjects:  []string{streamName + ".>"},
		Retention: jetstream.WorkQueuePolicy,
		MaxAge:    72 * time.Hour,
		Storage:   jetstream.FileStorage,
		Replicas:  1,
	})
	return err
}

func (p *publisher) Publish(ctx context.Context, topic string, payload []byte, opts ...port.PublishOption) error {
	if p.nc == nil {
		nc, js, err := connect(p.url)
		if err != nil {
			return err
		}
		p.nc = nc
		p.js = js
	}

	if err := p.ensureStream(ctx, topic); err != nil {
		return fmt.Errorf("nats: ensure stream: %w", err)
	}

	o := port.ApplyPublishOptions(opts...)

	subject := streamName + "." + topic

	headers := nats.Header{}
	if o.Delay > 0 {
		deliverAt := time.Now().Add(o.Delay)
		headers.Set("Deliver-At", deliverAt.Format(time.RFC3339Nano))
	}

	msg := &nats.Msg{
		Subject: subject,
		Data:    payload,
		Header:  headers,
	}

	pubCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := p.js.PublishMsg(pubCtx, msg)
	return err
}

func (p *publisher) Close() error {
	if p.nc != nil {
		p.nc.Close()
	}
	return nil
}

func (c *consumer) Subscribe(ctx context.Context, topic string, handler port.JobHandler) error {
	nc, js, err := connect(c.url)
	if err != nil {
		return err
	}
	c.nc = nc

	subject := streamName + "." + topic

	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      streamName,
		Subjects:  []string{streamName + ".>"},
		Retention: jetstream.WorkQueuePolicy,
		MaxAge:    72 * time.Hour,
		Storage:   jetstream.FileStorage,
		Replicas:  1,
	})
	if err != nil {
		return fmt.Errorf("nats: ensure stream: %w", err)
	}

	cons, err := js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:       durableName + "-" + strings.ReplaceAll(topic, ".", "_"),
		FilterSubject: subject,
		AckWait:       ackWait,
		MaxDeliver:    maxDeliver,
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("nats: create consumer: %w", err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			batch, err := cons.Fetch(10, jetstream.FetchMaxWait(fetchTimeout))
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}

			for msg := range batch.Messages() {
				if err := handler(ctx, msg.Data()); err != nil {
					logger.Warn("nats: handler failed, naking",
						logger.String("subject", subject), logger.Err(err))
					msg.Nak()
					continue
				}
				msg.Ack()
			}
		}
	}()

	return nil
}

func (c *consumer) Close() error {
	if c.nc != nil {
		c.nc.Close()
	}
	return nil
}
