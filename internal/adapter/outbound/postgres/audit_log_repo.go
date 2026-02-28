package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/razatechofficial/mail-os/internal/core/analytics"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type auditLogRepo struct {
	pool *pgxpool.Pool
}

var _ analytics.AuditLogRepository = (*auditLogRepo)(nil)

func NewAuditLogRepo(pool *pgxpool.Pool) analytics.AuditLogRepository {
	return &auditLogRepo{pool: pool}
}

func (r *auditLogRepo) Create(ctx context.Context, log *domain.AuditLog) error {
	q := QuerierFromContext(ctx, r.pool)
	changes, _ := json.Marshal(log.Changes)
	_, err := q.Exec(ctx, `
		INSERT INTO audit_logs (id, org_id, actor_type, actor_id, action, resource, resource_id, changes, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, log.ID, string(log.OrgID), string(log.ActorType), log.ActorID, log.Action, log.Resource, nullStr(log.ResourceID),
		changes, nullStr(log.IPAddress), nullStr(log.UserAgent), log.CreatedAt)
	return err
}

func (r *auditLogRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params analytics.AuditLogParams) ([]*domain.AuditLog, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "resource", "action"}, "created_at")
	sortOrder := "ASC"
	if params.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset()

	base := `FROM audit_logs WHERE org_id = $1`
	args := []interface{}{string(orgID)}
	argIdx := 2
	if params.Resource != "" {
		base += fmt.Sprintf(` AND resource = $%d`, argIdx)
		args = append(args, params.Resource)
		argIdx++
	}

	var total int
	err := q.QueryRow(ctx, `SELECT COUNT(*) `+base, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := q.Query(ctx, fmt.Sprintf(`
		SELECT id, org_id, actor_type, actor_id, action, resource, resource_id, changes, ip_address, user_agent, created_at
		%s ORDER BY %s %s LIMIT $%d OFFSET $%d
	`, base, sortBy, sortOrder, argIdx, argIdx+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		l, err := scanAuditLog(rows)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

func scanAuditLog(row pgx.Row) (*domain.AuditLog, error) {
	var id, orgID, actorType, actorID, action, resource string
	var resourceID, ipAddress, userAgent *string
	var changes []byte
	var createdAt time.Time
	err := row.Scan(&id, &orgID, &actorType, &actorID, &action, &resource, &resourceID, &changes, &ipAddress, &userAgent, &createdAt)
	if err != nil {
		return nil, err
	}
	var changesMap map[string]any
	if len(changes) > 0 {
		_ = json.Unmarshal(changes, &changesMap)
	}
	return &domain.AuditLog{
		ID:         id,
		OrgID:      domain.OrganizationID(orgID),
		ActorType:  domain.ActorType(actorType),
		ActorID:    actorID,
		Action:     action,
		Resource:   resource,
		ResourceID: strVal(resourceID),
		Changes:    changesMap,
		IPAddress:  strVal(ipAddress),
		UserAgent:  strVal(userAgent),
		CreatedAt:  createdAt,
	}, nil
}
