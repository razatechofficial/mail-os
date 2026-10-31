package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/message"
	domain "github.com/razatechofficial/mail-os/domain/message"
)

// MessageRepository stores messages. The provider's id is kept in the
// original provider_msg_id column.
type MessageRepository struct {
	db *Pool
}

var _ app.Repository = (*MessageRepository)(nil)

// NewMessageRepository returns the repository.
func NewMessageRepository(db *Pool) *MessageRepository { return &MessageRepository{db: db} }

const messageCols = `id, org_id, COALESCE(campaign_id, ''), COALESCE(provider_id, ''), from_name, from_email, to_email,
	COALESCE(to_name, ''), COALESCE(reply_to, ''), subject, COALESCE(html_body, ''), COALESCE(text_body, ''), type, status,
	priority, COALESCE(tags, '{}'), metadata, COALESCE(topic, ''), COALESCE(template_id, ''), COALESCE(template_version_id, ''),
	COALESCE(locale, ''), template_data, secret_keys, COALESCE(event_id, ''), COALESCE(actor_type, ''), COALESCE(actor_id, ''),
	COALESCE(idempotency_key, ''), COALESCE(provider_msg_id, ''), attempts, COALESCE(last_error, ''), scheduled_at,
	last_attempt_at, sent_at, delivered_at, bounced_at, failed_at, cancelled_at, opened_at, clicked_at, body_purged_at,
	created_at, updated_at`

// finalStatuses are the statuses whose body the purge may erase.
const finalStatuses = `('sent', 'delivered', 'bounced', 'failed', 'cancelled', 'suppressed')`

func scanMessage(row pgx.Row) (domain.Message, error) {
	var m domain.Message
	var typ, status, actorType string
	var priority int
	var meta, data []byte
	err := row.Scan(&m.ID, &m.OrgID, &m.CampaignID, &m.ProviderID, &m.FromName, &m.FromEmail, &m.ToEmail, &m.ToName, &m.ReplyTo,
		&m.Subject, &m.HTMLBody, &m.TextBody, &typ, &status, &priority, &m.Tags, &meta, &m.Topic, &m.TemplateID,
		&m.TemplateVersionID, &m.Locale, &data, &m.SecretKeys, &m.EventID, &actorType, &m.Actor.ID, &m.IdempotencyKey,
		&m.ProviderMessageID, &m.Attempts, &m.LastError, &m.ScheduledAt, &m.LastAttemptAt, &m.SentAt, &m.DeliveredAt,
		&m.BouncedAt, &m.FailedAt, &m.CancelledAt, &m.OpenedAt, &m.ClickedAt, &m.BodyPurgedAt, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return m, err
	}
	m.Type, m.Status, m.Priority, m.Actor.Type = domain.Type(typ), domain.Status(status), domain.Priority(priority), domain.ActorType(actorType)
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &m.Metadata)
	}
	if len(data) > 0 && string(data) != "null" {
		_ = json.Unmarshal(data, &m.TemplateData)
	}
	return m, nil
}

func jsonOrNil(v map[string]any) []byte {
	if v == nil {
		return nil
	}
	raw, _ := json.Marshal(v)
	return raw
}

func jsonObject(v map[string]any) []byte {
	if v == nil {
		return []byte("{}")
	}
	raw, _ := json.Marshal(v)
	return raw
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Create inserts a message.
func (r *MessageRepository) Create(ctx context.Context, m domain.Message) error {
	source, _ := m.Metadata["source"].(string)
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO messages (id, org_id, campaign_id, provider_id, from_name, from_email, to_email, to_name, reply_to, subject,
			html_body, text_body, type, status, priority, tags, metadata, topic, source, template_id, template_version_id, locale,
			template_data, secret_keys, event_id, actor_type, actor_id, idempotency_key, provider_msg_id, attempts, last_error,
			scheduled_at, created_at, updated_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10, NULLIF($11, ''),
			NULLIF($12, ''), $13, $14, $15, $16, $17, NULLIF($18, ''), NULLIF($19, ''), NULLIF($20, ''), NULLIF($21, ''),
			NULLIF($22, ''), $23, $24, NULLIF($25, ''), NULLIF($26, ''), NULLIF($27, ''), NULLIF($28, ''), NULLIF($29, ''),
			$30, NULLIF($31, ''), $32, $33, $34)`,
		m.ID, m.OrgID, m.CampaignID, m.ProviderID, m.FromName, m.FromEmail, m.ToEmail, m.ToName, m.ReplyTo, m.Subject,
		m.HTMLBody, m.TextBody, string(m.Type), string(m.Status), int(m.Priority), nonNil(m.Tags), jsonObject(m.Metadata),
		m.Topic, source, m.TemplateID, m.TemplateVersionID, m.Locale, jsonOrNil(m.TemplateData), nonNil(m.SecretKeys),
		m.EventID, string(m.Actor.Type), m.Actor.ID, m.IdempotencyKey, m.ProviderMessageID, m.Attempts, m.LastError,
		m.ScheduledAt, m.CreatedAt, m.UpdatedAt)
	if IsUniqueViolation(err) && m.IdempotencyKey != "" {
		return app.ErrDuplicateKey
	}
	return err
}

// Get reads one of the tenant's messages.
func (r *MessageRepository) Get(ctx context.Context, tenantID, id string) (domain.Message, error) {
	m, err := scanMessage(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+messageCols+` FROM messages WHERE id = $1 AND org_id = $2`, id, tenantID))
	return m, notFound(err, "message")
}

// ByIdempotencyKey finds the tenant's message with key.
func (r *MessageRepository) ByIdempotencyKey(ctx context.Context, tenantID, key string) (*domain.Message, error) {
	m, err := scanMessage(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+messageCols+` FROM messages WHERE org_id = $1 AND idempotency_key = $2`, tenantID, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *MessageRepository) query(ctx context.Context, sql string, args ...any) ([]domain.Message, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// List returns a page of the tenant's messages, newest first.
func (r *MessageRepository) List(ctx context.Context, f app.Filter) ([]domain.Message, int, error) {
	where := []string{"org_id = $1"}
	args := []any{f.TenantID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if f.Status != "" {
		add("status = ?", f.Status)
	}
	if f.Type != "" {
		add("type = ?", f.Type)
	}
	if f.Topic != "" {
		add("topic = ?", f.Topic)
	}
	if f.To != "" {
		add("lower(to_email) = lower(?)", f.To)
	}
	if f.From != nil {
		add("created_at >= ?", *f.From)
	}
	if f.Until != nil {
		add("created_at < ?", *f.Until)
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `SELECT count(*) FROM messages WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	args = append(args, limit, max(f.Offset, 0))
	list, err := r.query(ctx, `SELECT `+messageCols+` FROM messages WHERE `+cond+` ORDER BY created_at DESC, id DESC LIMIT $`+
		strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	return list, total, err
}

// Update saves the delivery fields when the status is still expect.
func (r *MessageRepository) Update(ctx context.Context, m domain.Message, expect domain.Status) (bool, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE messages SET subject = $4, html_body = NULLIF($5, ''), text_body = NULLIF($6, ''), status = $7,
			provider_id = NULLIF($8, ''), provider_msg_id = NULLIF($9, ''), attempts = $10, last_error = NULLIF($11, ''),
			scheduled_at = $12, last_attempt_at = $13, sent_at = $14, delivered_at = $15, bounced_at = $16, failed_at = $17,
			cancelled_at = $18, updated_at = $19
		WHERE id = $1 AND org_id = $2 AND status = $3`,
		m.ID, m.OrgID, string(expect), m.Subject, m.HTMLBody, m.TextBody, string(m.Status), m.ProviderID, m.ProviderMessageID,
		m.Attempts, m.LastError, m.ScheduledAt, m.LastAttemptAt, m.SentAt, m.DeliveredAt, m.BouncedAt, m.FailedAt,
		m.CancelledAt, m.UpdatedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// DueScheduled lists scheduled messages due by now.
func (r *MessageRepository) DueScheduled(ctx context.Context, now time.Time, limit int) ([]domain.Message, error) {
	return r.query(ctx, `SELECT `+messageCols+` FROM messages WHERE status = 'scheduled' AND scheduled_at <= $1
		ORDER BY scheduled_at LIMIT $2`, now, limit)
}

// Stale lists queued and sending messages left untouched.
func (r *MessageRepository) Stale(ctx context.Context, queuedBefore, sendingBefore time.Time, limit int) ([]domain.Message, error) {
	return r.query(ctx, `SELECT `+messageCols+` FROM messages
		WHERE (status = 'queued' AND updated_at < $1) OR (status = 'sending' AND updated_at < $2)
		ORDER BY updated_at LIMIT $3`, queuedBefore, sendingBefore, limit)
}

// PurgeTenants lists tenants holding bodies of final messages.
func (r *MessageRepository) PurgeTenants(ctx context.Context) ([]string, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx,
		`SELECT DISTINCT org_id FROM messages WHERE body_purged_at IS NULL AND status IN `+finalStatuses)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PurgeCandidates lists final messages past retention with their bodies.
func (r *MessageRepository) PurgeCandidates(ctx context.Context, tenantID string, before time.Time, limit int) ([]domain.Message, error) {
	return r.query(ctx, `SELECT `+messageCols+` FROM messages WHERE org_id = $1 AND body_purged_at IS NULL
		AND created_at < $2 AND status IN `+finalStatuses+` ORDER BY created_at LIMIT $3`, tenantID, before, limit)
}

// SavePurged erases the bodies and template data and stores the masked
// subject.
func (r *MessageRepository) SavePurged(ctx context.Context, m domain.Message) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE messages SET subject = $3, html_body = NULL, text_body = NULL, template_data = NULL,
			body_purged_at = $4, updated_at = $4
		WHERE id = $1 AND org_id = $2`, m.ID, m.OrgID, m.Subject, m.BodyPurgedAt)
	return err
}

// SentSince counts each provider's messages sent since t.
func (r *MessageRepository) SentSince(ctx context.Context, providerIDs []string, t time.Time) (map[string]int, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT provider_id, count(*) FROM messages
		WHERE provider_id = ANY($1) AND sent_at >= $2 GROUP BY provider_id`, providerIDs, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
