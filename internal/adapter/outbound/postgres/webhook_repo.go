package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/webhook"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type webhookRepo struct {
	pool *pgxpool.Pool
}

var _ webhook.Repository = (*webhookRepo)(nil)

func NewWebhookRepo(pool *pgxpool.Pool) webhook.Repository {
	return &webhookRepo{pool: pool}
}

func (r *webhookRepo) Create(ctx context.Context, w *domain.Webhook) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO webhooks (id, org_id, url, secret, events, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5::text[], $6, $7, $8)
	`, string(w.ID), string(w.OrgID), w.URL, w.Secret, formatTextArray(w.Events), w.IsActive, w.CreatedAt, w.UpdatedAt)
	return err
}

func (r *webhookRepo) FindByID(ctx context.Context, id domain.WebhookID) (*domain.Webhook, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, url, secret, events, is_active, created_at, updated_at, deleted_at
		FROM webhooks WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	w, err := scanWebhook(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return w, nil
}

func (r *webhookRepo) Update(ctx context.Context, w *domain.Webhook) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE webhooks SET url = $2, secret = $3, events = $4::text[], is_active = $5, updated_at = $6
		WHERE id = $1 AND deleted_at IS NULL
	`, string(w.ID), w.URL, w.Secret, formatTextArray(w.Events), w.IsActive, w.UpdatedAt)
	return err
}

func (r *webhookRepo) SoftDelete(ctx context.Context, id domain.WebhookID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE webhooks SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *webhookRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params webhook.ListParams) ([]*domain.Webhook, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "url"}, "created_at")
	sortOrder := "ASC"
	if params.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset()

	var total int
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM webhooks WHERE org_id = $1 AND deleted_at IS NULL`, string(orgID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `
		SELECT id, org_id, url, secret, events, is_active, created_at, updated_at, deleted_at
		FROM webhooks WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3
	`, string(orgID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var webhooks []*domain.Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, 0, err
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, total, rows.Err()
}

func (r *webhookRepo) FindActiveByOrg(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Webhook, error) {
	q := QuerierFromContext(ctx, r.pool)
	rows, err := q.Query(ctx, `
		SELECT id, org_id, url, secret, events, is_active, created_at, updated_at, deleted_at
		FROM webhooks WHERE org_id = $1 AND is_active = true AND deleted_at IS NULL
	`, string(orgID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*domain.Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, rows.Err()
}

func (r *webhookRepo) CreateDelivery(ctx context.Context, d *domain.WebhookDelivery) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, status_code, attempts, last_error, next_retry_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, d.ID, string(d.WebhookID), d.EventType, d.Payload, string(d.Status), nullInt(d.StatusCode), d.Attempts, nullStr(d.LastError), nullTime(d.NextRetryAt), d.CreatedAt, d.UpdatedAt)
	return err
}

func (r *webhookRepo) UpdateDelivery(ctx context.Context, d *domain.WebhookDelivery) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE webhook_deliveries SET status = $2, status_code = $3, attempts = $4, last_error = $5, next_retry_at = $6, updated_at = $7
		WHERE id = $8
	`, string(d.Status), nullInt(d.StatusCode), d.Attempts, nullStr(d.LastError), nullTime(d.NextRetryAt), d.UpdatedAt, d.ID)
	return err
}

func (r *webhookRepo) FindPendingDeliveries(ctx context.Context, limit int) ([]*domain.WebhookDelivery, error) {
	q := QuerierFromContext(ctx, r.pool)
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.Query(ctx, `
		SELECT id, webhook_id, event_type, payload, status, status_code, attempts, last_error, next_retry_at, created_at, updated_at
		FROM webhook_deliveries
		WHERE status = 'pending' AND (next_retry_at IS NULL OR next_retry_at <= NOW())
		ORDER BY created_at ASC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*domain.WebhookDelivery
	for rows.Next() {
		d, err := scanWebhookDelivery(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

func scanWebhook(row pgx.Row) (*domain.Webhook, error) {
	var id, orgID, url, secret string
	var events pq.StringArray
	var isActive bool
	var createdAt, updatedAt time.Time
	var deletedAt *time.Time
	err := row.Scan(&id, &orgID, &url, &secret, &events, &isActive, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	eventsArr := []string(events)
	if eventsArr == nil {
		eventsArr = []string{}
	}
	return &domain.Webhook{
		ID:        domain.WebhookID(id),
		OrgID:     domain.OrganizationID(orgID),
		URL:       url,
		Secret:    secret,
		Events:    eventsArr,
		IsActive:  isActive,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		DeletedAt: deletedAt,
	}, nil
}

func scanWebhookDelivery(row pgx.Row) (*domain.WebhookDelivery, error) {
	var id, webhookID, eventType, payload, status string
	var lastError *string
	var statusCode *int
	var attempts int
	var nextRetryAt *time.Time
	var createdAt, updatedAt time.Time
	err := row.Scan(&id, &webhookID, &eventType, &payload, &status, &statusCode, &attempts, &lastError, &nextRetryAt, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	statusCodeVal := 0
	if statusCode != nil {
		statusCodeVal = *statusCode
	}
	d := &domain.WebhookDelivery{
		ID:          id,
		WebhookID:   domain.WebhookID(webhookID),
		EventType:   eventType,
		Payload:     payload,
		Status:      domain.DeliveryStatus(status),
		StatusCode:  statusCodeVal,
		Attempts:    attempts,
		NextRetryAt: nextRetryAt,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
	if lastError != nil {
		d.LastError = *lastError
	}
	return d, nil
}

func nullInt(i int) interface{} {
	if i == 0 {
		return nil
	}
	return i
}
