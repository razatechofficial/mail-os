package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/infrastructure/audit"
)

// AuditRepository stores audit events and their outbox rows.
type AuditRepository struct {
	db *Pool
}

var _ audit.Store = (*AuditRepository)(nil)

// NewAuditRepository returns the repository.
func NewAuditRepository(db *Pool) *AuditRepository { return &AuditRepository{db: db} }

// Insert writes the event, and with stream its outbox row, in one
// transaction (joining the caller's when ctx carries one).
func (r *AuditRepository) Insert(ctx context.Context, ev audit.Event, stream bool) error {
	meta, err := json.Marshal(ev.Metadata)
	if err != nil {
		return err
	}
	return r.db.InTx(ctx, func(ctx context.Context) error {
		q := QuerierFromContext(ctx, r.db)
		if _, err := q.Exec(ctx, `
			INSERT INTO audit_events (event_id, service, tier, severity, actor_uuid, actor_type, tenant_uuid,
				organization_uuid, resource_type, resource_id, action, ip_address, user_agent, metadata, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULLIF($12, '')::inet, NULLIF($13, ''), $14, $15)`,
			ev.EventID, ev.Service, ev.Tier, int(ev.Severity), ev.ActorUUID, ev.ActorType, ev.TenantUUID,
			ev.OrganizationUUID, ev.ResourceType, ev.ResourceID, ev.Action, cleanIP(ev.IPAddress), ev.UserAgent, meta, ev.CreatedAt); err != nil {
			return fmt.Errorf("insert audit event: %w", err)
		}
		if !stream {
			return nil
		}
		payload, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		_, err = q.Exec(ctx, `INSERT INTO audit_outbox (event_id, payload) VALUES ($1, $2)`, ev.EventID, payload)
		return err
	})
}

// cleanIP keeps only a parseable address so a malformed header never fails
// the audit insert.
func cleanIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if strings.ContainsAny(ip, " ,") {
		return ""
	}
	return ip
}

// AuditFilter narrows an audit listing; TenantUUID is always set by the use case.
type AuditFilter struct {
	TenantUUID   uuid.UUID
	Action       string
	ResourceType string
	ResourceID   string
	ActorUUID    *uuid.UUID
	From, To     *time.Time
	Limit        int
	Offset       int
}

// List returns a tenant's events, newest first, and the total count.
func (r *AuditRepository) List(ctx context.Context, f AuditFilter) ([]audit.Event, int, error) {
	where := []string{"tenant_uuid = $1"}
	args := []any{f.TenantUUID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.ResourceType != "" {
		add("resource_type = $%d", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("resource_id = $%d", f.ResourceID)
	}
	if f.ActorUUID != nil {
		add("actor_uuid = $%d", *f.ActorUUID)
	}
	if f.From != nil {
		add("created_at >= $%d", *f.From)
	}
	if f.To != nil {
		add("created_at < $%d", *f.To)
	}
	cond := strings.Join(where, " AND ")
	q := QuerierFromContext(ctx, r.db)
	var total int
	if err := q.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE "+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := q.Query(ctx, `
		SELECT event_id, service, tier, severity, actor_uuid, actor_type, tenant_uuid, organization_uuid,
			resource_type, resource_id, action, COALESCE(host(ip_address), ''), COALESCE(user_agent, ''), metadata, created_at
		FROM audit_events WHERE `+cond+fmt.Sprintf(" ORDER BY created_at DESC, event_id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []audit.Event
	for rows.Next() {
		var ev audit.Event
		var sev int
		var meta []byte
		if err := rows.Scan(&ev.EventID, &ev.Service, &ev.Tier, &sev, &ev.ActorUUID, &ev.ActorType, &ev.TenantUUID,
			&ev.OrganizationUUID, &ev.ResourceType, &ev.ResourceID, &ev.Action, &ev.IPAddress, &ev.UserAgent, &meta, &ev.CreatedAt); err != nil {
			return nil, 0, err
		}
		ev.Severity = audit.Severity(sev)
		_ = json.Unmarshal(meta, &ev.Metadata)
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// OutboxRow is one event waiting for the audit stream.
type OutboxRow struct {
	EventID  uuid.UUID
	Payload  []byte
	Attempts int
}

// ClaimOutbox locks up to limit due rows (SKIP LOCKED, so replicas share the
// work) and hands them to publish; rows publish returns nil for are marked
// published, the others are retried with backoff.
func (r *AuditRepository) ClaimOutbox(ctx context.Context, limit int, publish func(OutboxRow) error, backoff func(attempts int) time.Duration) (int, error) {
	done := 0
	err := r.db.InTx(ctx, func(ctx context.Context) error {
		q := QuerierFromContext(ctx, r.db)
		rows, err := q.Query(ctx, `
			SELECT event_id, payload, attempt_count FROM audit_outbox
			WHERE status = 'pending' AND next_attempt_at <= now()
			ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
		if err != nil {
			return err
		}
		var batch []OutboxRow
		for rows.Next() {
			var o OutboxRow
			if err := rows.Scan(&o.EventID, &o.Payload, &o.Attempts); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, o := range batch {
			if perr := publish(o); perr != nil {
				if _, err := q.Exec(ctx, `UPDATE audit_outbox SET attempt_count = attempt_count + 1, last_error = $2,
					next_attempt_at = now() + make_interval(secs => $3) WHERE event_id = $1`,
					o.EventID, perr.Error(), backoff(o.Attempts+1).Seconds()); err != nil {
					return err
				}
				continue
			}
			if _, err := q.Exec(ctx, `UPDATE audit_outbox SET status = 'published', published_at = now() WHERE event_id = $1`, o.EventID); err != nil {
				return err
			}
			done++
		}
		return nil
	})
	return done, err
}

// Purge deletes events older than before that the stream no longer needs
// (PCI DSS 10.5.1 keeps at least a year; the config enforces it).
func (r *AuditRepository) Purge(ctx context.Context, before time.Time, limit int) (int64, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		DELETE FROM audit_events WHERE event_id IN (
			SELECT e.event_id FROM audit_events e
			LEFT JOIN audit_outbox o ON o.event_id = e.event_id AND o.status = 'pending'
			WHERE e.created_at < $1 AND o.event_id IS NULL LIMIT $2)`, before, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
