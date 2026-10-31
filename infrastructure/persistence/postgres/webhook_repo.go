package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	app "github.com/razatechofficial/mail-os/application/webhook"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/webhook"
)

// WebhookRepository stores webhooks, their secrets sealed in place in
// secret, and their deliveries.
type WebhookRepository struct {
	db *Pool
}

var _ app.Repository = (*WebhookRepository)(nil)

// NewWebhookRepository returns the repository.
func NewWebhookRepository(db *Pool) *WebhookRepository { return &WebhookRepository{db: db} }

// SealedColumn is webhooks.secret, for the key schedule.
func (r *WebhookRepository) SealedColumn() appkm.SealedColumn {
	return sealedColumn{db: r.db, purpose: domainkm.PurposeWebhook, table: "webhooks", column: "secret"}
}

const webhookCols = `w.id, w.org_id, w.url, COALESCE(w.events, '{}'), w.is_active, COALESCE(w.created_by, ''),
	COALESCE(w.updated_by, ''), w.created_at, w.updated_at, w.secret`

func scanWebhook(row pgx.Row) (app.Stored, error) {
	var s app.Stored
	w := &s.Webhook
	err := row.Scan(&w.ID, &w.OrgID, &w.URL, &w.Events, &w.Active, &w.CreatedBy, &w.UpdatedBy, &w.CreatedAt, &w.UpdatedAt, &s.Sealed)
	return s, err
}

// Create inserts a webhook.
func (r *WebhookRepository) Create(ctx context.Context, s app.Stored) error {
	w := s.Webhook
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO webhooks (id, org_id, url, secret, events, is_active, created_by, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), $9, $10)`,
		w.ID, w.OrgID, w.URL, s.Sealed, nonNil(w.Events), w.Active, w.CreatedBy, w.UpdatedBy, w.CreatedAt, w.UpdatedAt)
	return err
}

// Update saves w, and the secret when sealed is set.
func (r *WebhookRepository) Update(ctx context.Context, w domain.Webhook, sealed *string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE webhooks SET url = $3, events = $4, is_active = $5, updated_by = NULLIF($6, ''), updated_at = $7,
			secret = CASE WHEN $8::boolean THEN $9 ELSE secret END
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
		w.ID, w.OrgID, w.URL, nonNil(w.Events), w.Active, w.UpdatedBy, w.UpdatedAt, sealed != nil, deref(sealed))
	return err
}

// Delete soft-deletes a webhook.
func (r *WebhookRepository) Delete(ctx context.Context, tenantID, id string, at time.Time) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE webhooks SET deleted_at = $3, is_active = false, updated_at = $3
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenantID, at)
	return err
}

// Get reads one of the tenant's webhooks.
func (r *WebhookRepository) Get(ctx context.Context, tenantID, id string) (app.Stored, error) {
	s, err := scanWebhook(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+webhookCols+` FROM webhooks w WHERE w.id = $1 AND w.org_id = $2 AND w.deleted_at IS NULL`, id, tenantID))
	return s, notFound(err, "webhook")
}

func (r *WebhookRepository) scan(ctx context.Context, sql string, args ...any) ([]domain.Webhook, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Webhook
	for rows.Next() {
		s, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s.Webhook)
	}
	return out, rows.Err()
}

// List returns a page of webhooks.
func (r *WebhookRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Webhook, int, error) {
	var total int
	if err := QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT count(*) FROM webhooks WHERE org_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	list, err := r.scan(ctx, `SELECT `+webhookCols+` FROM webhooks w WHERE w.org_id = $1 AND w.deleted_at IS NULL
		ORDER BY w.created_at LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	return list, total, err
}

// Subscribed lists the tenant's active webhooks for event.
func (r *WebhookRepository) Subscribed(ctx context.Context, tenantID, event string) ([]domain.Webhook, error) {
	return r.scan(ctx, `SELECT `+webhookCols+` FROM webhooks w WHERE w.org_id = $1 AND w.is_active AND w.deleted_at IS NULL
		AND $2 = ANY(w.events)`, tenantID, event)
}

// CreateDelivery inserts a pending delivery.
func (r *WebhookRepository) CreateDelivery(ctx context.Context, d domain.Delivery) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO webhook_deliveries (id, webhook_id, message_id, event_type, payload, status, attempts, created_at, updated_at)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, 0, $7, $8)`,
		d.ID, d.WebhookID, d.MessageID, d.Event, string(d.Payload), string(d.Status), d.CreatedAt, d.UpdatedAt)
	return err
}

// Delivery reads a delivery and its webhook.
func (r *WebhookRepository) Delivery(ctx context.Context, id string) (domain.Delivery, app.Stored, error) {
	var d domain.Delivery
	var status, payload string
	var code *int
	var s app.Stored
	w := &s.Webhook
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `
		SELECT d.id, d.webhook_id, COALESCE(d.message_id, ''), d.event_type, d.payload, d.status, d.status_code, d.attempts,
			COALESCE(d.last_error, ''), d.delivered_at, d.created_at, d.updated_at, `+webhookCols+`
		FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE d.id = $1`, id).
		Scan(&d.ID, &d.WebhookID, &d.MessageID, &d.Event, &payload, &status, &code, &d.Attempts, &d.LastError, &d.DeliveredAt,
			&d.CreatedAt, &d.UpdatedAt, &w.ID, &w.OrgID, &w.URL, &w.Events, &w.Active, &w.CreatedBy, &w.UpdatedBy,
			&w.CreatedAt, &w.UpdatedAt, &s.Sealed)
	if err != nil {
		return d, s, notFound(err, "webhook delivery")
	}
	d.Payload, d.Status = []byte(payload), domain.DeliveryStatus(status)
	if code != nil {
		d.StatusCode = *code
	}
	return d, s, nil
}

// UpdateDelivery saves an attempt's outcome.
func (r *WebhookRepository) UpdateDelivery(ctx context.Context, d domain.Delivery) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE webhook_deliveries SET status = $2, status_code = NULLIF($3, 0),
		attempts = $4, last_error = NULLIF($5, ''), delivered_at = $6, updated_at = $7 WHERE id = $1`,
		d.ID, string(d.Status), d.StatusCode, d.Attempts, d.LastError, d.DeliveredAt, d.UpdatedAt)
	return err
}

// Legacy lists webhooks whose secret is not a sealed value.
func (r *WebhookRepository) Legacy(ctx context.Context) ([]app.LegacyRow, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT id, secret FROM webhooks WHERE secret NOT LIKE 'km1.%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.LegacyRow
	for rows.Next() {
		var lr app.LegacyRow
		if err := rows.Scan(&lr.ID, &lr.Secret); err != nil {
			return nil, err
		}
		out = append(out, lr)
	}
	return out, rows.Err()
}

// ReplaceLegacy stores the sealed secret over the plaintext one.
func (r *WebhookRepository) ReplaceLegacy(ctx context.Context, id, sealed string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE webhooks SET secret = $2 WHERE id = $1 AND secret NOT LIKE 'km1.%'`, id, sealed)
	return err
}

// WithLock runs fn under the webhook conversion's advisory lock.
func (r *WebhookRepository) WithLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error) {
	return withAdvisoryLock(ctx, r.db, webhookLegacyLock, fn)
}
