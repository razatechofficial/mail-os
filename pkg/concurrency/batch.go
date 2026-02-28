package concurrency

import (
	"sync"
	"time"
)

type BatchProcessor[T any] struct {
	size    int
	interval time.Duration
	flush   func(items []T)
	items   []T
	mu      sync.Mutex
	ticker  *time.Ticker
	done    chan struct{}
	once    sync.Once
}

func NewBatchProcessor[T any](size int, interval time.Duration, flush func(items []T)) *BatchProcessor[T] {
	b := &BatchProcessor[T]{
		size:     size,
		interval: interval,
		flush:    flush,
		items:    make([]T, 0, size),
		done:     make(chan struct{}),
	}
	if interval > 0 {
		b.ticker = time.NewTicker(interval)
		go b.tickLoop()
	}
	return b
}

func (b *BatchProcessor[T]) tickLoop() {
	for {
		select {
		case <-b.done:
			return
		case <-b.ticker.C:
			b.flushIfReady(true)
		}
	}
}

func (b *BatchProcessor[T]) flushIfReady(timeBased bool) {
	b.mu.Lock()
	if len(b.items) == 0 {
		b.mu.Unlock()
		return
	}
	doFlush := timeBased || len(b.items) >= b.size
	if !doFlush {
		b.mu.Unlock()
		return
	}
	batch := make([]T, len(b.items))
	copy(batch, b.items)
	b.items = b.items[:0]
	b.mu.Unlock()
	b.flush(batch)
}

func (b *BatchProcessor[T]) Add(item T) {
	b.mu.Lock()
	b.items = append(b.items, item)
	needFlush := len(b.items) >= b.size
	b.mu.Unlock()
	if needFlush {
		b.flushIfReady(false)
	}
}

func (b *BatchProcessor[T]) Shutdown() {
	b.once.Do(func() {
		close(b.done)
		if b.ticker != nil {
			b.ticker.Stop()
		}
		b.mu.Lock()
		if len(b.items) > 0 {
			batch := make([]T, len(b.items))
			copy(batch, b.items)
			b.items = nil
			b.mu.Unlock()
			b.flush(batch)
		} else {
			b.mu.Unlock()
		}
	})
}
