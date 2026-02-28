package concurrency

import (
	"context"
	"sync"
	"time"
)

type TokenBucket struct {
	ch    chan struct{}
	stop  chan struct{}
	wg    sync.WaitGroup
	mu    sync.Mutex
	stopped bool
}

func NewTokenBucket(rate float64, burst int) *TokenBucket {
	if burst < 1 {
		burst = 1
	}
	if rate <= 0 {
		rate = 1
	}
	interval := time.Duration(float64(time.Second) / rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	tb := &TokenBucket{
		ch:   make(chan struct{}, burst),
		stop: make(chan struct{}),
	}
	for i := 0; i < burst; i++ {
		tb.ch <- struct{}{}
	}
	tb.wg.Add(1)
	go func() {
		defer tb.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-tb.stop:
				return
			case <-ticker.C:
				select {
				case tb.ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return tb
}

func (tb *TokenBucket) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tb.ch:
		return nil
	}
}

func (tb *TokenBucket) TryAcquire() bool {
	select {
	case <-tb.ch:
		return true
	default:
		return false
	}
}

func (tb *TokenBucket) Stop() {
	tb.mu.Lock()
	if tb.stopped {
		tb.mu.Unlock()
		return
	}
	tb.stopped = true
	close(tb.stop)
	tb.mu.Unlock()
	tb.wg.Wait()
}
