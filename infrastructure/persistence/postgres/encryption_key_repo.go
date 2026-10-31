package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	app "github.com/razatechofficial/mail-os/application/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
)

// keyManagerLock is the advisory lock id of the key schedule.
const keyManagerLock = 0x6d61696c6f73_01 // "mailos" + 1

// EncryptionKeyRepository stores the key manager's data keys.
type EncryptionKeyRepository struct {
	db *Pool
}

var _ app.Store = (*EncryptionKeyRepository)(nil)

// NewEncryptionKeyRepository returns the repository.
func NewEncryptionKeyRepository(db *Pool) *EncryptionKeyRepository {
	return &EncryptionKeyRepository{db: db}
}

// ListKeys returns every key, oldest first.
func (r *EncryptionKeyRepository) ListKeys(ctx context.Context) ([]domain.EncryptionKey, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `
		SELECT id, kid, purpose, state, provider, key_ref, COALESCE(created_by, ''), created_at, retired_at
		FROM encryption_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EncryptionKey
	for rows.Next() {
		var k domain.EncryptionKey
		var purpose, state string
		if err := rows.Scan(&k.ID, &k.KID, &purpose, &state, &k.Provider, &k.KeyRef, &k.CreatedBy, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		k.Purpose, k.State = domain.Purpose(purpose), domain.State(state)
		out = append(out, k)
	}
	return out, rows.Err()
}

// InsertKey adds a key; the partial unique index refuses a second active
// key for a purpose.
func (r *EncryptionKeyRepository) InsertKey(ctx context.Context, k domain.EncryptionKey) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO encryption_keys (id, kid, purpose, state, provider, key_ref, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8)`,
		k.ID, k.KID, string(k.Purpose), string(k.State), k.Provider, k.KeyRef, k.CreatedBy, k.CreatedAt)
	return err
}

// RetireKey makes a key decrypt-only.
func (r *EncryptionKeyRepository) RetireKey(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`UPDATE encryption_keys SET state = 'retired', retired_at = $2 WHERE id = $1 AND state = 'active'`, id, at)
	return err
}

// DeleteKey destroys a drained key's wrapped material.
func (r *EncryptionKeyRepository) DeleteKey(ctx context.Context, id uuid.UUID) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `DELETE FROM encryption_keys WHERE id = $1 AND state = 'retired'`, id)
	return err
}

// WithLock runs fn in a transaction holding the schedule's advisory lock
// (pg_try_advisory_xact_lock), so one replica works at a time.
func (r *EncryptionKeyRepository) WithLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error) {
	ran := false
	err := r.db.InTx(ctx, func(ctx context.Context) error {
		var got bool
		if err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(keyManagerLock)).Scan(&got); err != nil {
			return err
		}
		if !got {
			return nil
		}
		ran = true
		return fn(ctx)
	})
	return ran, err
}
