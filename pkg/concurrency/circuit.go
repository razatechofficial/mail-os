package concurrency

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var ErrCircuitOpen = errors.New("circuit breaker is open")

type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

type CircuitBreaker struct {
	maxFailures int
	timeout     time.Duration
	state       atomic.Int32
	failures    atomic.Int64
	lastFail    atomic.Int64
	mu          sync.RWMutex
	halfOpenMu  sync.Mutex
}

func NewCircuitBreaker(maxFailures int, timeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		maxFailures: maxFailures,
		timeout:     timeout,
	}
	cb.state.Store(int32(StateClosed))
	return cb
}

func (cb *CircuitBreaker) Execute(fn func() error) error {
	s := State(cb.state.Load())
	if s == StateOpen {
		if time.Since(time.Unix(0, cb.lastFail.Load())) >= cb.timeout {
			cb.halfOpenMu.Lock()
			if cb.state.CompareAndSwap(int32(StateOpen), int32(StateHalfOpen)) {
				cb.failures.Store(0)
			}
			cb.halfOpenMu.Unlock()
			s = StateHalfOpen
		} else {
			return ErrCircuitOpen
		}
	}
	if s == StateHalfOpen {
		cb.halfOpenMu.Lock()
		if cb.state.Load() != int32(StateHalfOpen) {
			cb.halfOpenMu.Unlock()
			return cb.Execute(fn)
		}
		err := fn()
		if err != nil {
			cb.state.Store(int32(StateOpen))
			cb.lastFail.Store(time.Now().UnixNano())
			cb.halfOpenMu.Unlock()
			return err
		}
		cb.state.Store(int32(StateClosed))
		cb.failures.Store(0)
		cb.halfOpenMu.Unlock()
		return nil
	}
	err := fn()
	if err != nil {
		n := cb.failures.Add(1)
		cb.lastFail.Store(time.Now().UnixNano())
		if int(n) >= cb.maxFailures {
			cb.state.Store(int32(StateOpen))
		}
		return err
	}
	cb.failures.Store(0)
	return nil
}

func (cb *CircuitBreaker) State() State {
	s := State(cb.state.Load())
	if s == StateOpen && time.Since(time.Unix(0, cb.lastFail.Load())) >= cb.timeout {
		return StateHalfOpen
	}
	return s
}
