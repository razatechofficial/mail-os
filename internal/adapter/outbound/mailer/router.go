package mailer

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/concurrency"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

type providerEntry struct {
	sender   port.EmailSender
	breaker  *concurrency.CircuitBreaker
	priority int
	weight   int
}

type Router struct {
	mu        sync.RWMutex
	providers []providerEntry
}

func NewRouter() *Router {
	return &Router{}
}

func (r *Router) AddProvider(sender port.EmailSender, priority, weight int, maxFailures int, breakerTimeout time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = append(r.providers, providerEntry{
		sender:   sender,
		breaker:  concurrency.NewCircuitBreaker(maxFailures, breakerTimeout),
		priority: priority,
		weight:   weight,
	})
	sort.Slice(r.providers, func(i, j int) bool {
		return r.providers[i].priority > r.providers[j].priority
	})
}

func (r *Router) Route(ctx context.Context, orgID domain.OrganizationID, req port.SendRequest) (*port.SendResult, error) {
	r.mu.RLock()
	providers := make([]providerEntry, len(r.providers))
	copy(providers, r.providers)
	r.mu.RUnlock()

	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}

	var lastErr error
	for _, p := range providers {
		var result *port.SendResult
		err := p.breaker.Execute(func() error {
			var sendErr error
			result, sendErr = p.sender.Send(ctx, req)
			return sendErr
		})
		if err == nil {
			return result, nil
		}
		lastErr = err
		if err != concurrency.ErrCircuitOpen {
			logger.Warn("provider failed, trying next", logger.String("provider", p.sender.Name()), logger.Err(err))
		}
	}
	return nil, fmt.Errorf("all providers failed: %w", lastErr)
}

var _ port.ProviderRouter = (*Router)(nil)
