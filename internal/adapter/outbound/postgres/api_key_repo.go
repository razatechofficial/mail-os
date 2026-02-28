package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/apikey"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type apiKeyRepo struct {
	pool *pgxpool.Pool
}

var _ apikey.Repository = (*apiKeyRepo)(nil)

func NewAPIKeyRepo(pool *pgxpool.Pool) apikey.Repository {
	return &apiKeyRepo{pool: pool}
}

func (r *apiKeyRepo) Create(ctx context.Context, key *domain.APIKey) error {
	q := QuerierFromContext(ctx, r.pool)
	scopes := key.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	_, err := q.Exec(ctx, `
		INSERT INTO api_keys (id, org_id, name, key_hash, prefix, scopes, expires_at, last_used_at, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, string(key.ID), string(key.OrgID), key.Name, key.KeyHash, key.Prefix, scopes, key.ExpiresAt, key.LastUsedAt, key.IsActive, key.CreatedAt, key.UpdatedAt)
	return err
}

func (r *apiKeyRepo) FindByID(ctx context.Context, id domain.APIKeyID) (*domain.APIKey, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, name, key_hash, prefix, scopes, expires_at, last_used_at, is_active, created_at, updated_at, deleted_at
		FROM api_keys WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	key, err := scanAPIKey(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return key, nil
}

func (r *apiKeyRepo) FindByPrefix(ctx context.Context, prefix string) ([]*domain.APIKey, error) {
	q := QuerierFromContext(ctx, r.pool)
	rows, err := q.Query(ctx, `
		SELECT id, org_id, name, key_hash, prefix, scopes, expires_at, last_used_at, is_active, created_at, updated_at, deleted_at
		FROM api_keys WHERE prefix = $1 AND deleted_at IS NULL AND is_active = true
	`, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*domain.APIKey
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *apiKeyRepo) Update(ctx context.Context, key *domain.APIKey) error {
	q := QuerierFromContext(ctx, r.pool)
	scopes := key.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	_, err := q.Exec(ctx, `
		UPDATE api_keys SET name = $2, key_hash = $3, prefix = $4, scopes = $5, expires_at = $6, last_used_at = $7, is_active = $8, updated_at = $9
		WHERE id = $1 AND deleted_at IS NULL
	`, string(key.ID), key.Name, key.KeyHash, key.Prefix, scopes, key.ExpiresAt, key.LastUsedAt, key.IsActive, key.UpdatedAt)
	return err
}

func (r *apiKeyRepo) SoftDelete(ctx context.Context, id domain.APIKeyID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE api_keys SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *apiKeyRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params apikey.ListParams) ([]*domain.APIKey, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "name"}, "created_at")
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
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys WHERE org_id = $1 AND deleted_at IS NULL`, string(orgID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `SELECT id, org_id, name, key_hash, prefix, scopes, expires_at, last_used_at, is_active, created_at, updated_at, deleted_at
		FROM api_keys WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3`, string(orgID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var keys []*domain.APIKey
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, 0, err
		}
		keys = append(keys, key)
	}
	return keys, total, rows.Err()
}

func scanAPIKey(row pgx.Row) (*domain.APIKey, error) {
	var id, orgID, name, keyHash, prefix string
	var scopes []string
	var expiresAt, lastUsedAt, deletedAt *time.Time
	var isActive bool
	var createdAt, updatedAt time.Time
	err := row.Scan(&id, &orgID, &name, &keyHash, &prefix, &scopes, &expiresAt, &lastUsedAt, &isActive, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	return &domain.APIKey{
		ID:         domain.APIKeyID(id),
		OrgID:      domain.OrganizationID(orgID),
		Name:       name,
		KeyHash:    keyHash,
		Prefix:     prefix,
		Scopes:     scopes,
		ExpiresAt:  expiresAt,
		LastUsedAt: lastUsedAt,
		IsActive:   isActive,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
		DeletedAt:  deletedAt,
	}, nil
}
