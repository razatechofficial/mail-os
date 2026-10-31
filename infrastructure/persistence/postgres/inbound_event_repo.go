package postgres

import (
	"context"

	"github.com/razatechofficial/mail-os/application/inbound"
)

// InboundEventRepository records received events once per (tenant, event
// id) in inbound_events.
type InboundEventRepository struct {
	db *Pool
}

var _ inbound.Store = (*InboundEventRepository)(nil)

// NewInboundEventRepository returns the repository.
func NewInboundEventRepository(db *Pool) *InboundEventRepository {
	return &InboundEventRepository{db: db}
}

// Claim inserts r unless the event exists, and returns the existing row
// otherwise. A concurrent claim of the same event waits for the first
// transaction: it sees the row once that commits, or claims it if that
// rolls back.
func (r *InboundEventRepository) Claim(ctx context.Context, rec inbound.Record) (inbound.Record, bool, error) {
	q := QuerierFromContext(ctx, r.db)
	tag, err := q.Exec(ctx, `
		INSERT INTO inbound_events (org_id, event_id, topic, client_id, transport, data_sha256, received_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (org_id, event_id) DO NOTHING`,
		rec.TenantID, rec.EventID, rec.Topic, rec.ClientID, rec.Transport, rec.DataSHA256, rec.ReceivedAt)
	if err != nil {
		return inbound.Record{}, false, err
	}
	if tag.RowsAffected() == 1 {
		return inbound.Record{}, true, nil
	}
	var prior inbound.Record
	err = q.QueryRow(ctx, `
		SELECT org_id, event_id, topic, client_id, transport, data_sha256, COALESCE(message_id, ''), received_at
		FROM inbound_events WHERE org_id = $1 AND event_id = $2`, rec.TenantID, rec.EventID).
		Scan(&prior.TenantID, &prior.EventID, &prior.Topic, &prior.ClientID, &prior.Transport,
			&prior.DataSHA256, &prior.MessageID, &prior.ReceivedAt)
	return prior, false, err
}

// Complete stores the message id the event became.
func (r *InboundEventRepository) Complete(ctx context.Context, tenantID, eventID, messageID string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`UPDATE inbound_events SET message_id = $3 WHERE org_id = $1 AND event_id = $2`, tenantID, eventID, messageID)
	return err
}
