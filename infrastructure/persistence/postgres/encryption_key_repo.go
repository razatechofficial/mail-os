package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
		SELECT id, kid, purpose, state, provider, COALESCE(kek_id, ''), key_ref, COALESCE(created_by, ''), created_at, retired_at
		FROM encryption_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EncryptionKey
	for rows.Next() {
		var k domain.EncryptionKey
		var purpose, state string
		if err := rows.Scan(&k.ID, &k.KID, &purpose, &state, &k.Provider, &k.KEKID, &k.KeyRef, &k.CreatedBy, &k.CreatedAt, &k.RetiredAt); err != nil {
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
		INSERT INTO encryption_keys (id, kid, purpose, state, provider, kek_id, key_ref, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9)`,
		k.ID, k.KID, string(k.Purpose), string(k.State), k.Provider, k.KEKID, k.KeyRef, k.CreatedBy, k.CreatedAt)
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

// ReplaceKeyRef stores a data key re-wrapped under kekID if the row still
// holds oldRef (compare-and-swap).
func (r *EncryptionKeyRepository) ReplaceKeyRef(ctx context.Context, id uuid.UUID, oldRef, newRef []byte, kekID string) (bool, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE encryption_keys SET key_ref = $3, kek_id = $4, provider = split_part($4, ':', 1)
		WHERE id = $1 AND key_ref = $2`, id, oldRef, newRef, kekID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
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

const kekRotationColumns = `id, from_kek_id, to_kek_id, state, reason, requested_by, started_at, completed_at,
	total, rewrapped, remaining, failed, last_error`

func scanKEKRotation(row pgx.Row) (domain.KEKRotation, error) {
	var k domain.KEKRotation
	var state string
	err := row.Scan(&k.ID, &k.FromKEK, &k.ToKEK, &state, &k.Reason, &k.RequestedBy, &k.StartedAt, &k.CompletedAt,
		&k.Total, &k.Rewrapped, &k.Remaining, &k.Failed, &k.LastError)
	k.State = domain.RotationState(state)
	return k, err
}

// LatestKEKRotation returns the newest KEK rotation, nil when none ran.
func (r *EncryptionKeyRepository) LatestKEKRotation(ctx context.Context) (*domain.KEKRotation, error) {
	k, err := scanKEKRotation(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+kekRotationColumns+` FROM kek_rotations ORDER BY started_at DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ListKEKRotations returns up to limit KEK rotations, newest first.
func (r *EncryptionKeyRepository) ListKEKRotations(ctx context.Context, limit int) ([]domain.KEKRotation, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx,
		`SELECT `+kekRotationColumns+` FROM kek_rotations ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.KEKRotation
	for rows.Next() {
		k, err := scanKEKRotation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// InsertKEKRotation stores a new rotation; the partial unique index refuses
// a second running one.
func (r *EncryptionKeyRepository) InsertKEKRotation(ctx context.Context, k domain.KEKRotation) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `INSERT INTO kek_rotations (`+kekRotationColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		k.ID, k.FromKEK, k.ToKEK, string(k.State), k.Reason, k.RequestedBy, k.StartedAt, k.CompletedAt,
		k.Total, k.Rewrapped, k.Remaining, k.Failed, k.LastError)
	return err
}

// UpdateKEKRotation saves a rotation's progress.
func (r *EncryptionKeyRepository) UpdateKEKRotation(ctx context.Context, k domain.KEKRotation) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE kek_rotations SET state = $2, completed_at = $3, total = $4,
		rewrapped = $5, remaining = $6, failed = $7, last_error = $8 WHERE id = $1`,
		k.ID, string(k.State), k.CompletedAt, k.Total, k.Rewrapped, k.Remaining, k.Failed, k.LastError)
	return err
}
