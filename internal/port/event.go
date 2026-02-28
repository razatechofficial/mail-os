package port

import (
	"context"
	"time"
)

type DomainEvent interface {
	EventType() string
	OccurredAt() time.Time
}

type EventPublisher interface {
	Publish(ctx context.Context, event DomainEvent) error
}

type EventSubscriber interface {
	Subscribe(eventType string, handler func(ctx context.Context, event DomainEvent) error)
}
