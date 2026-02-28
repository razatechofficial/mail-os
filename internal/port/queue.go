package port

import (
	"context"
	"time"
)

type PublishOption func(*publishOptions)

type publishOptions struct {
	Delay    time.Duration
	Priority int
}

func WithDelay(d time.Duration) PublishOption {
	return func(o *publishOptions) { o.Delay = d }
}

func WithPriority(p int) PublishOption {
	return func(o *publishOptions) { o.Priority = p }
}

func ApplyPublishOptions(opts ...PublishOption) publishOptions {
	o := publishOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

type Publisher interface {
	Publish(ctx context.Context, topic string, payload []byte, opts ...PublishOption) error
	Close() error
}

type Consumer interface {
	Subscribe(ctx context.Context, topic string, handler JobHandler) error
	Close() error
}

type JobHandler func(ctx context.Context, payload []byte) error
