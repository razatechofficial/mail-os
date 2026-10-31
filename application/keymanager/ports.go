// Package keymanager is the key manager use case: it keeps one active data
// key per purpose, seals and opens secrets with it, rotates keys at the end
// of their cryptoperiod or on request, re-encrypts what retired keys sealed,
// and destroys a retired key once nothing it sealed remains (IAM's
// key-manager design, docs/rfp/progress/key-manager.md §3).
package keymanager

import (
	"context"
	"time"

	"github.com/google/uuid"

	domain "github.com/razatechofficial/mail-os/domain/keymanager"
)

// Provider wraps data keys under the master key (software) or an HSM.
type Provider interface {
	Name() string
	// NewDataKey creates a random AES-256 key and returns it wrapped.
	NewDataKey(ctx context.Context, aad []byte) ([]byte, error)
	// UnwrapDataKey returns the raw key of a wrapped reference.
	UnwrapDataKey(ctx context.Context, ref, aad []byte) ([]byte, error)
}

// Store persists keys.
type Store interface {
	ListKeys(ctx context.Context) ([]domain.EncryptionKey, error)
	// InsertKey fails with a unique violation when another replica already
	// activated a key for the purpose.
	InsertKey(ctx context.Context, k domain.EncryptionKey) error
	RetireKey(ctx context.Context, id uuid.UUID, at time.Time) error
	DeleteKey(ctx context.Context, id uuid.UUID) error
	// WithLock runs fn under a cluster-wide advisory lock; ran is false when
	// another replica holds it.
	WithLock(ctx context.Context, fn func(ctx context.Context) error) (ran bool, err error)
}

// SealedColumn is one table column holding values of one purpose. The
// repositories that own sealed secrets implement it, so the key manager can
// count and re-encrypt what each key sealed.
type SealedColumn interface {
	Purpose() domain.Purpose
	Name() string
	CountByKID(ctx context.Context, kid string) (int, error)
	// Reencrypt rewraps up to limit values sealed by kid, swapping each only
	// if it is still the value read (compare-and-swap), so a secret changed
	// meanwhile is never overwritten.
	Reencrypt(ctx context.Context, kid string, limit int, rewrap func(old string) (string, error)) (int, error)
}

// Auditor records key events.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Cipher seals and opens the secrets of one purpose.
type Cipher interface {
	Seal(ctx context.Context, plaintext []byte) (string, error)
	Open(ctx context.Context, ciphertext string) ([]byte, error)
}
