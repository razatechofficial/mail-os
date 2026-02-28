package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/message"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type messageRepo struct {
	pool *pgxpool.Pool
}

var _ message.Repository = (*messageRepo)(nil)

func NewMessageRepo(pool *pgxpool.Pool) message.Repository {
	return &messageRepo{pool: pool}
}

func (r *messageRepo) Create(ctx context.Context, msg *domain.Message) error {
	q := QuerierFromContext(ctx, r.pool)
	metadata, _ := json.Marshal(msg.Metadata)
	_, err := q.Exec(ctx, `
		INSERT INTO messages (id, org_id, campaign_id, provider_id, from_name, from_email, to_email, to_name, subject, html_body, text_body,
			type, status, priority, tags, metadata, idempotency_key, provider_msg_id, attempts, last_attempt_at, sent_at, delivered_at,
			opened_at, clicked_at, bounced_at, scheduled_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
	`, string(msg.ID), string(msg.OrgID), nullStr(string(msg.CampaignID)), nullStr(string(msg.ProviderID)), msg.FromName, msg.FromEmail,
		msg.ToEmail, msg.ToName, msg.Subject, msg.HTMLBody, msg.TextBody, string(msg.Type), string(msg.Status), int(msg.Priority),
		msg.Tags, metadata, nullStr(msg.IdempotencyKey), nullStr(msg.ProviderMsgID), msg.Attempts, nullTime(msg.LastAttemptAt),
		nullTime(msg.SentAt), nullTime(msg.DeliveredAt), nullTime(msg.OpenedAt), nullTime(msg.ClickedAt), nullTime(msg.BouncedAt),
		nullTime(msg.ScheduledAt), msg.CreatedAt, msg.UpdatedAt)
	return err
}

func (r *messageRepo) FindByID(ctx context.Context, id domain.MessageID) (*domain.Message, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, campaign_id, provider_id, from_name, from_email, to_email, to_name, subject, html_body, text_body,
			type, status, priority, tags, metadata, idempotency_key, provider_msg_id, attempts, last_attempt_at, sent_at, delivered_at,
			opened_at, clicked_at, bounced_at, scheduled_at, created_at, updated_at
		FROM messages WHERE id = $1
	`, string(id))
	m, err := scanMessage(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return m, nil
}

func (r *messageRepo) FindAll(ctx context.Context, params message.MessageListParams) ([]*domain.Message, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "sent_at", "status"}, "created_at")
	sortOrder := "ASC"
	if params.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset()

	base := `FROM messages WHERE org_id = $1`
	args := []interface{}{params.OrgID}
	argIdx := 2
	if params.Status != "" {
		base += fmt.Sprintf(` AND status = $%d`, argIdx)
		args = append(args, params.Status)
		argIdx++
	}
	if params.Type != "" {
		base += fmt.Sprintf(` AND type = $%d`, argIdx)
		args = append(args, params.Type)
		argIdx++
	}

	var total int
	err := q.QueryRow(ctx, `SELECT COUNT(*) `+base, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := q.Query(ctx, fmt.Sprintf(`
		SELECT id, org_id, campaign_id, provider_id, from_name, from_email, to_email, to_name, subject, html_body, text_body,
			type, status, priority, tags, metadata, idempotency_key, provider_msg_id, attempts, last_attempt_at, sent_at, delivered_at,
			opened_at, clicked_at, bounced_at, scheduled_at, created_at, updated_at
		%s ORDER BY %s %s LIMIT $%d OFFSET $%d
	`, base, sortBy, sortOrder, argIdx, argIdx+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var messages []*domain.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, 0, err
		}
		messages = append(messages, m)
	}
	return messages, total, rows.Err()
}

func (r *messageRepo) FindScheduledDue(ctx context.Context, limit int) ([]*domain.Message, error) {
	if limit <= 0 {
		limit = 100
	}
	q := QuerierFromContext(ctx, r.pool)
	rows, err := q.Query(ctx, `
		SELECT id, org_id, campaign_id, provider_id, from_name, from_email, to_email, to_name, subject, html_body, text_body,
			type, status, priority, tags, metadata, idempotency_key, provider_msg_id, attempts, last_attempt_at, sent_at, delivered_at,
			opened_at, clicked_at, bounced_at, scheduled_at, created_at, updated_at
		FROM messages
		WHERE status = $1 AND scheduled_at IS NOT NULL AND scheduled_at <= NOW()
		ORDER BY scheduled_at ASC
		LIMIT $2
	`, string(domain.MessageStatusScheduled), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []*domain.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

func (r *messageRepo) UpdateStatus(ctx context.Context, id domain.MessageID, status domain.MessageStatus, fields map[string]any) error {
	q := QuerierFromContext(ctx, r.pool)
	updates := []string{"status = $2", "updated_at = NOW()"}
	args := []interface{}{string(id), string(status)}
	idx := 3
	if fields != nil {
		if v, ok := fields["provider_msg_id"]; ok {
			updates = append(updates, fmt.Sprintf("provider_msg_id = $%d", idx))
			args = append(args, v)
			idx++
		}
		if v, ok := fields["attempts"]; ok {
			updates = append(updates, fmt.Sprintf("attempts = $%d", idx))
			args = append(args, v)
			idx++
		}
		if v, ok := fields["last_attempt_at"]; ok {
			updates = append(updates, fmt.Sprintf("last_attempt_at = $%d", idx))
			args = append(args, v)
			idx++
		}
		if v, ok := fields["sent_at"]; ok {
			updates = append(updates, fmt.Sprintf("sent_at = $%d", idx))
			args = append(args, v)
			idx++
		}
		if v, ok := fields["delivered_at"]; ok {
			updates = append(updates, fmt.Sprintf("delivered_at = $%d", idx))
			args = append(args, v)
			idx++
		}
		if v, ok := fields["opened_at"]; ok {
			updates = append(updates, fmt.Sprintf("opened_at = $%d", idx))
			args = append(args, v)
			idx++
		}
		if v, ok := fields["clicked_at"]; ok {
			updates = append(updates, fmt.Sprintf("clicked_at = $%d", idx))
			args = append(args, v)
			idx++
		}
		if v, ok := fields["bounced_at"]; ok {
			updates = append(updates, fmt.Sprintf("bounced_at = $%d", idx))
			args = append(args, v)
			idx++
		}
	}
	_, err := q.Exec(ctx, `UPDATE messages SET `+strings.Join(updates, ", ")+` WHERE id = $1`, args...)
	return err
}

func (r *messageRepo) FindByIdempotencyKey(ctx context.Context, orgID domain.OrganizationID, key string) (*domain.Message, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, campaign_id, provider_id, from_name, from_email, to_email, to_name, subject, html_body, text_body,
			type, status, priority, tags, metadata, idempotency_key, provider_msg_id, attempts, last_attempt_at, sent_at, delivered_at,
			opened_at, clicked_at, bounced_at, scheduled_at, created_at, updated_at
		FROM messages WHERE org_id = $1 AND idempotency_key = $2
	`, string(orgID), key)
	m, err := scanMessage(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return m, nil
}

func scanMessage(row pgx.Row) (*domain.Message, error) {
	var id, orgID, fromName, fromEmail, toEmail, msgType, status string
	var toName, subject, htmlBody, textBody, idempotencyKey, providerMsgID, campaignID, providerID *string
	var metadata []byte
	var tags []string
	var priority, attempts int
	var lastAttemptAt, sentAt, deliveredAt, openedAt, clickedAt, bouncedAt, scheduledAt *time.Time
	var createdAt, updatedAt time.Time
	err := row.Scan(&id, &orgID, &campaignID, &providerID, &fromName, &fromEmail, &toEmail, &toName, &subject, &htmlBody, &textBody,
		&msgType, &status, &priority, &tags, &metadata, &idempotencyKey, &providerMsgID, &attempts, &lastAttemptAt, &sentAt, &deliveredAt,
		&openedAt, &clickedAt, &bouncedAt, &scheduledAt, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	var metadataMap map[string]any
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &metadataMap)
	}
	if tags == nil {
		tags = []string{}
	}
	return &domain.Message{
		ID:             domain.MessageID(id),
		OrgID:          domain.OrganizationID(orgID),
		CampaignID:     domain.CampaignID(strVal(campaignID)),
		ProviderID:     domain.ProviderID(strVal(providerID)),
		FromName:       fromName,
		FromEmail:      fromEmail,
		ToEmail:        toEmail,
		ToName:         strVal(toName),
		Subject:        strVal(subject),
		HTMLBody:       strVal(htmlBody),
		TextBody:       strVal(textBody),
		Type:           domain.MessageType(msgType),
		Status:         domain.MessageStatus(status),
		Priority:       domain.MessagePriority(priority),
		Tags:           tags,
		Metadata:       metadataMap,
		IdempotencyKey: strVal(idempotencyKey),
		ProviderMsgID:  strVal(providerMsgID),
		Attempts:       attempts,
		LastAttemptAt:  lastAttemptAt,
		SentAt:         sentAt,
		DeliveredAt:    deliveredAt,
		OpenedAt:       openedAt,
		ClickedAt:      clickedAt,
		BouncedAt:      bouncedAt,
		ScheduledAt:    scheduledAt,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}, nil
}
