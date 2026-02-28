package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/provider"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type providerRepo struct {
	pool *pgxpool.Pool
}

var _ provider.Repository = (*providerRepo)(nil)

func NewProviderRepo(pool *pgxpool.Pool) provider.Repository {
	return &providerRepo{pool: pool}
}

func (r *providerRepo) Create(ctx context.Context, p *domain.Provider) error {
	q := QuerierFromContext(ctx, r.pool)
	config, _ := json.Marshal(p.Configuration)
	if p.Configuration == nil {
		config = []byte("{}")
	}
	_, err := q.Exec(ctx, `
		INSERT INTO providers (id, org_id, name, type, configuration, priority, weight, daily_limit, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, string(p.ID), string(p.OrgID), p.Name, string(p.Type), config, p.Priority, p.Weight, p.DailyLimit, p.IsActive, p.CreatedAt, p.UpdatedAt)
	return err
}

func (r *providerRepo) FindByID(ctx context.Context, id domain.ProviderID) (*domain.Provider, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, name, type, configuration, priority, weight, daily_limit, is_active, created_at, updated_at, deleted_at
		FROM providers WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	pv, err := scanProvider(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return pv, nil
}

func (r *providerRepo) Update(ctx context.Context, p *domain.Provider) error {
	q := QuerierFromContext(ctx, r.pool)
	config, _ := json.Marshal(p.Configuration)
	if p.Configuration == nil {
		config = []byte("{}")
	}
	_, err := q.Exec(ctx, `
		UPDATE providers SET name = $2, type = $3, configuration = $4, priority = $5, weight = $6, daily_limit = $7, is_active = $8, updated_at = $9
		WHERE id = $1 AND deleted_at IS NULL
	`, string(p.ID), p.Name, string(p.Type), config, p.Priority, p.Weight, p.DailyLimit, p.IsActive, p.UpdatedAt)
	return err
}

func (r *providerRepo) SoftDelete(ctx context.Context, id domain.ProviderID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE providers SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *providerRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params provider.ListParams) ([]*domain.Provider, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "name", "priority"}, "created_at")
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
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM providers WHERE org_id = $1 AND deleted_at IS NULL`, string(orgID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `SELECT id, org_id, name, type, configuration, priority, weight, daily_limit, is_active, created_at, updated_at, deleted_at
		FROM providers WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3`, string(orgID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []*domain.Provider
	for rows.Next() {
		pv, err := scanProvider(rows)
		if err != nil {
			return nil, 0, err
		}
		list = append(list, pv)
	}
	return list, total, rows.Err()
}

func (r *providerRepo) FindActive(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Provider, error) {
	q := QuerierFromContext(ctx, r.pool)
	rows, err := q.Query(ctx, `
		SELECT id, org_id, name, type, configuration, priority, weight, daily_limit, is_active, created_at, updated_at, deleted_at
		FROM providers WHERE org_id = $1 AND deleted_at IS NULL AND is_active = true
		ORDER BY priority ASC, weight DESC
	`, string(orgID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*domain.Provider
	for rows.Next() {
		pv, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, pv)
	}
	return list, rows.Err()
}

func scanProvider(row pgx.Row) (*domain.Provider, error) {
	var id, orgID, name, ptype string
	var config []byte
	var priority, weight, dailyLimit int
	var isActive bool
	var createdAt, updatedAt time.Time
	var deletedAt *time.Time
	err := row.Scan(&id, &orgID, &name, &ptype, &config, &priority, &weight, &dailyLimit, &isActive, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	var configMap map[string]any
	if len(config) > 0 {
		_ = json.Unmarshal(config, &configMap)
	}
	return &domain.Provider{
		ID:            domain.ProviderID(id),
		OrgID:         domain.OrganizationID(orgID),
		Name:          name,
		Type:          domain.ProviderType(ptype),
		Configuration: configMap,
		Priority:      priority,
		Weight:        weight,
		DailyLimit:    dailyLimit,
		IsActive:      isActive,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		DeletedAt:     deletedAt,
	}, nil
}
