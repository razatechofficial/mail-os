package concurrency

import (
	"context"
	"sync"
)

type FanOutResult[T any] struct {
	Value T
	Err   error
	Index int
}

func FanOut[T any](ctx context.Context, workers int, items []T, fn func(ctx context.Context, item T) error) []error {
	if len(items) == 0 {
		return nil
	}
	if workers < 1 {
		workers = 1
	}
	errs := make([]error, len(items))
	var mu sync.Mutex
	var wg sync.WaitGroup
	chunk := (len(items) + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start := w * chunk
		end := start + chunk
		if end > len(items) {
			end = len(items)
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				select {
				case <-ctx.Done():
					mu.Lock()
					if errs[i] == nil {
						errs[i] = ctx.Err()
					}
					mu.Unlock()
					return
				default:
					err := fn(ctx, items[i])
					mu.Lock()
					errs[i] = err
					mu.Unlock()
				}
			}
		}(start, end)
	}
	wg.Wait()
	return errs
}
