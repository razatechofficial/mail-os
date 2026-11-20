package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/message"
	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
)

// MessageSecretRepository stores the sealed live secrets of
// authentication-class messages (message_secrets). It never sees them in
// clear: the message use case seals them with the key manager first.
type MessageSecretRepository struct {
	db *Pool
}

var _ app.SecretStore = (*MessageSecretRepository)(nil)

// NewMessageSecretRepository returns the repository.
func NewMessageSecretRepository(db *Pool) *MessageSecretRepository {
	return &MessageSecretRepository{db: db}
}

// SealedColumn is message_secrets.sealed, for the key schedule.
func (r *MessageSecretRepository) SealedColumn() appkm.SealedColumn {
	return sealedColumn{db: r.db, purpose: domainkm.PurposeMessageSecret, table: "message_secrets", column: "sealed", key: "message_id"}
}

// InTx runs fn in one transaction.
func (r *MessageSecretRepository) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return r.db.InTx(ctx, fn)
}

// Put stores a message's sealed secrets.
func (r *MessageSecretRepository) Put(ctx context.Context, tenantID, messageID, sealed string, createdAt, expiresAt time.Time) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO message_secrets (message_id, org_id, sealed, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		messageID, tenantID, sealed, createdAt, expiresAt)
	return err
}

// Get returns the message's sealed secrets unless expired by now.
func (r *MessageSecretRepository) Get(ctx context.Context, tenantID, messageID string, now time.Time) (string, bool, error) {
	var sealed string
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `
		SELECT sealed FROM message_secrets WHERE message_id = $1 AND org_id = $2 AND expires_at > $3`,
		messageID, tenantID, now).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return sealed, err == nil, err
}

// Delete removes the message's secrets.
func (r *MessageSecretRepository) Delete(ctx context.Context, tenantID, messageID string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`DELETE FROM message_secrets WHERE message_id = $1 AND org_id = $2`, messageID, tenantID)
	return err
}

// DeleteExpired removes every row expired by now.
func (r *MessageSecretRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `DELETE FROM message_secrets WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
