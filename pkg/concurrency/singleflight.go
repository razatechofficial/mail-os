package concurrency

import (
	"sync"
)

type call[T any] struct {
	wg  sync.WaitGroup
	val T
	err error
}

type SingleFlight[T any] struct {
	mu sync.Mutex
	m  map[string]*call[T]
}

func NewSingleFlight[T any]() *SingleFlight[T] {
	return &SingleFlight[T]{m: make(map[string]*call[T])}
}

func (sf *SingleFlight[T]) Do(key string, fn func() (T, error)) (T, error) {
	sf.mu.Lock()
	if c, ok := sf.m[key]; ok {
		sf.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &call[T]{}
	c.wg.Add(1)
	sf.m[key] = c
	sf.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	sf.mu.Lock()
	delete(sf.m, key)
	sf.mu.Unlock()

	return c.val, c.err
}
