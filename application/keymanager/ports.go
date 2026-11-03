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

// KEK is a key-encryption key: it wraps data keys and never leaves where
// it lives (a master key from Vault, an HSM, a cloud KMS).
type KEK interface {
	// ID names the KEK (domain.KEKID); it is stored beside each data key
	// the KEK wraps.
	ID() string
	// Wrap encrypts a data key, bound to aad.
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	// Unwrap returns the data key Wrap encrypted with the same aad.
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// Store persists keys and KEK rotations.
type Store interface {
	ListKeys(ctx context.Context) ([]domain.EncryptionKey, error)
	// InsertKey fails with a unique violation when another replica already
	// activated a key for the purpose.
	InsertKey(ctx context.Context, k domain.EncryptionKey) error
	RetireKey(ctx context.Context, id uuid.UUID, at time.Time) error
	DeleteKey(ctx context.Context, id uuid.UUID) error
	// ReplaceKeyRef stores a data key re-wrapped under kekID if the row
	// still holds oldRef; false means it changed or was deleted meanwhile.
	ReplaceKeyRef(ctx context.Context, id uuid.UUID, oldRef, newRef []byte, kekID string) (bool, error)
	// WithLock runs fn under a cluster-wide advisory lock; ran is false when
	// another replica holds it.
	WithLock(ctx context.Context, fn func(ctx context.Context) error) (ran bool, err error)

	// LatestKEKRotation returns the newest KEK rotation, nil when none ran.
	LatestKEKRotation(ctx context.Context) (*domain.KEKRotation, error)
	ListKEKRotations(ctx context.Context, limit int) ([]domain.KEKRotation, error)
	// InsertKEKRotation fails when another rotation is running.
	InsertKEKRotation(ctx context.Context, r domain.KEKRotation) error
	UpdateKEKRotation(ctx context.Context, r domain.KEKRotation) error
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
