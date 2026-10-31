package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/razatechofficial/mail-os/application/idempotency"
)

// IdempotencyRepository keeps Idempotency-Key responses in
// idempotency_keys until they expire.
type IdempotencyRepository struct {
	db *Pool
}

var _ idempotency.Store = (*IdempotencyRepository)(nil)

// NewIdempotencyRepository returns the repository.
func NewIdempotencyRepository(db *Pool) *IdempotencyRepository { return &IdempotencyRepository{db: db} }

// Claim inserts the key, or takes over an expired one; a live key is
// returned as it is. Two concurrent first requests cannot both claim: the
// primary key decides.
func (r *IdempotencyRepository) Claim(ctx context.Context, scope, key, hash string, expires time.Time) (idempotency.Record, bool, error) {
	q := QuerierFromContext(ctx, r.db)
	var claimed bool
	err := q.QueryRow(ctx, `
		INSERT INTO idempotency_keys (scope, key, request_sha256, expires_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (scope, key) DO UPDATE SET request_sha256 = EXCLUDED.request_sha256, status_code = 0, response = NULL,
			created_at = now(), expires_at = EXCLUDED.expires_at
		WHERE idempotency_keys.expires_at <= now()
		RETURNING true`, scope, key, hash, expires).Scan(&claimed)
	if err == nil {
		return idempotency.Record{}, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return idempotency.Record{}, false, err
	}
	var rec idempotency.Record
	err = q.QueryRow(ctx, `SELECT request_sha256, status_code, COALESCE(response, ''::bytea) FROM idempotency_keys
		WHERE scope = $1 AND key = $2`, scope, key).Scan(&rec.RequestSHA256, &rec.Status, &rec.Body)
	return rec, false, err
}

// Complete stores the response of a claimed key.
func (r *IdempotencyRepository) Complete(ctx context.Context, scope, key string, status int, body []byte) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`UPDATE idempotency_keys SET status_code = $3, response = $4 WHERE scope = $1 AND key = $2`, scope, key, status, body)
	return err
}

// Release deletes a key whose request did not take effect.
func (r *IdempotencyRepository) Release(ctx context.Context, scope, key string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `DELETE FROM idempotency_keys WHERE scope = $1 AND key = $2`, scope, key)
	return err
}

// PurgeExpired deletes expired keys and reports how many.
func (r *IdempotencyRepository) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `DELETE FROM idempotency_keys WHERE expires_at <= now()`)
	return tag.RowsAffected(), err
}
