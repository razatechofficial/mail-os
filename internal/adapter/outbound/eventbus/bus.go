package eventbus

import (
	"context"
	"strings"
	"sync"

	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]func(ctx context.Context, event port.DomainEvent) error
}

func New() *Bus {
	return &Bus{
		handlers: make(map[string][]func(ctx context.Context, event port.DomainEvent) error),
	}
}

func (b *Bus) Publish(ctx context.Context, event port.DomainEvent) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for pattern, handlers := range b.handlers {
		if matchEvent(pattern, event.EventType()) {
			for _, h := range handlers {
				if err := h(ctx, event); err != nil {
					logger.Error("event handler failed",
						logger.String("event", event.EventType()),
						logger.Err(err),
					)
				}
			}
		}
	}
	return nil
}

func (b *Bus) Subscribe(eventType string, handler func(ctx context.Context, event port.DomainEvent) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

func matchEvent(pattern, eventType string) bool {
	if pattern == eventType {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(eventType, prefix+".")
	}
	return false
}

var _ port.EventPublisher = (*Bus)(nil)
var _ port.EventSubscriber = (*Bus)(nil)
