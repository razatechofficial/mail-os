// Package idempotency is the storage contract of the Idempotency-Key
// header on the send endpoints: the first response for a key is kept, per
// application, until it expires, and replayed for the same request.
package idempotency

import (
	"context"
	"time"
)

// Record is a stored key. Status 0 means the first request is still
// running.
type Record struct {
	RequestSHA256 string
	Status        int
	Body          []byte
}

// Store keeps the first response for a (scope, key) until it expires.
type Store interface {
	// Claim records the key for a request with hash unless an unexpired
	// record exists; then it returns that record and false.
	Claim(ctx context.Context, scope, key, hash string, expires time.Time) (Record, bool, error)
	// Complete stores the response of a claimed key.
	Complete(ctx context.Context, scope, key string, status int, body []byte) error
	// Release forgets a claimed key, so the request can be tried again.
	Release(ctx context.Context, scope, key string) error
}
