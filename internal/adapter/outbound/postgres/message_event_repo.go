package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/razatechofficial/mail-os/internal/core/analytics"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type messageEventRepo struct {
	pool *pgxpool.Pool
}

var _ analytics.MessageEventRepository = (*messageEventRepo)(nil)

func NewMessageEventRepo(pool *pgxpool.Pool) analytics.MessageEventRepository {
	return &messageEventRepo{pool: pool}
}

func (r *messageEventRepo) Create(ctx context.Context, event *domain.MessageEvent) error {
	q := QuerierFromContext(ctx, r.pool)
	metadata, _ := json.Marshal(event.Metadata)
	_, err := q.Exec(ctx, `
		INSERT INTO message_events (id, message_id, org_id, type, provider, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, event.ID, string(event.MessageID), string(event.OrgID), string(event.Type), nullStr(event.Provider), metadata, event.CreatedAt)
	return err
}

func (r *messageEventRepo) FindByMessageID(ctx context.Context, messageID domain.MessageID) ([]*domain.MessageEvent, error) {
	q := QuerierFromContext(ctx, r.pool)
	rows, err := q.Query(ctx, `
		SELECT id, message_id, org_id, type, provider, metadata, created_at
		FROM message_events WHERE message_id = $1 ORDER BY created_at ASC
	`, string(messageID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*domain.MessageEvent
	for rows.Next() {
		ev, err := scanMessageEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

func scanMessageEvent(row pgx.Row) (*domain.MessageEvent, error) {
	var id, messageID, orgID, evType, provider string
	var metadata []byte
	var createdAt time.Time
	err := row.Scan(&id, &messageID, &orgID, &evType, &provider, &metadata, &createdAt)
	if err != nil {
		return nil, err
	}
	var metadataMap map[string]any
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &metadataMap)
	}
	return &domain.MessageEvent{
		ID:        id,
		MessageID: domain.MessageID(messageID),
		OrgID:     domain.OrganizationID(orgID),
		Type:      domain.EventType(evType),
		Provider:  provider,
		Metadata:  metadataMap,
		CreatedAt: createdAt,
	}, nil
}
