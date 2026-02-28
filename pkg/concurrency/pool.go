// Package concurrency provides reusable primitives for parallel work:
// worker pools, fan-out/fan-in, batch processing, circuit breakers,
// token-bucket rate limiters, and single-flight deduplication.
package concurrency

import (
	"sync"
)

type task struct {
	run    func() error
	result chan error
}

type WorkerPool struct {
	size   int
	tasks  chan task
	wg     sync.WaitGroup
	once   sync.Once
	mu     sync.Mutex
	closed bool
}

func NewWorkerPool(size int) *WorkerPool {
	if size < 1 {
		size = 1
	}
	p := &WorkerPool{
		size:  size,
		tasks: make(chan task, size*2),
	}
	for i := 0; i < size; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return p
}

func (p *WorkerPool) worker() {
	defer p.wg.Done()
	for t := range p.tasks {
		err := t.run()
		if t.result != nil {
			t.result <- err
			close(t.result)
		}
	}
}

func (p *WorkerPool) Submit(fn func()) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	p.tasks <- task{
		run:    func() error { fn(); return nil },
		result: nil,
	}
}

func (p *WorkerPool) SubmitWait(fn func() error) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	res := make(chan error, 1)
	p.tasks <- task{run: fn, result: res}
	return <-res
}

func (p *WorkerPool) Shutdown() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		close(p.tasks)
		p.wg.Wait()
	})
}
