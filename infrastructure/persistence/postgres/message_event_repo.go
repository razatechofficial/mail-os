package postgres

import (
	"context"
	"encoding/json"

	app "github.com/razatechofficial/mail-os/application/message"
	domain "github.com/razatechofficial/mail-os/domain/message"
)

// MessageEventRepository stores the providers' delivery events in
// message_events and finds messages by the provider's id.
type MessageEventRepository struct {
	db *Pool
}

var _ app.DeliveryEvents = (*MessageEventRepository)(nil)

// NewMessageEventRepository returns the repository.
func NewMessageEventRepository(db *Pool) *MessageEventRepository { return &MessageEventRepository{db: db} }

// ByProviderMessageID finds the tenant's message the provider sent under
// its own id.
func (r *MessageEventRepository) ByProviderMessageID(ctx context.Context, tenantID, providerID, providerMessageID string) (domain.Message, error) {
	m, err := scanMessage(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+messageCols+` FROM messages WHERE org_id = $1 AND provider_id = $2 AND provider_msg_id = $3
		ORDER BY created_at DESC LIMIT 1`, tenantID, providerID, providerMessageID))
	return m, notFound(err, "message")
}

// Add records e unless the same (message, type, key) is already there.
func (r *MessageEventRepository) Add(ctx context.Context, e domain.DeliveryEvent) (bool, error) {
	meta, _ := json.Marshal(map[string]any{"source": "provider_webhook"})
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO message_events (id, message_id, org_id, type, provider, provider_id, event_key, reason, occurred_at, metadata, created_at)
		VALUES ($1, $2, $3, $4, (SELECT type FROM providers WHERE id = $5), $5, $6, NULLIF($7, ''), $8, $9, $10)
		ON CONFLICT (message_id, type, event_key) WHERE event_key IS NOT NULL DO NOTHING`,
		e.ID, e.MessageID, e.TenantID, string(e.Type), e.ProviderID, e.Key, e.Reason, e.OccurredAt, meta, e.CreatedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// List returns the message's provider events, oldest first.
func (r *MessageEventRepository) List(ctx context.Context, tenantID, messageID string) ([]domain.DeliveryEvent, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `
		SELECT id, message_id, org_id, type, COALESCE(provider_id, ''), COALESCE(event_key, ''), COALESCE(reason, ''),
			COALESCE(occurred_at, created_at), created_at
		FROM message_events WHERE org_id = $1 AND message_id = $2 AND event_key IS NOT NULL
		ORDER BY COALESCE(occurred_at, created_at), created_at`, tenantID, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.DeliveryEvent
	for rows.Next() {
		var e domain.DeliveryEvent
		var typ string
		if err := rows.Scan(&e.ID, &e.MessageID, &e.TenantID, &typ, &e.ProviderID, &e.Key, &e.Reason, &e.OccurredAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Type = domain.EventType(typ)
		out = append(out, e)
	}
	return out, rows.Err()
}
