package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/organization"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type organizationRepo struct {
	pool *pgxpool.Pool
}

var _ organization.Repository = (*organizationRepo)(nil)

func NewOrganizationRepo(pool *pgxpool.Pool) organization.Repository {
	return &organizationRepo{pool: pool}
}

func (r *organizationRepo) Create(ctx context.Context, org *domain.Organization) error {
	q := QuerierFromContext(ctx, r.pool)
	settings, _ := json.Marshal(org.Settings)
	_, err := q.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, webhook_url, webhook_secret, settings, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, string(org.ID), org.Name, org.Slug, org.WebhookURL, org.WebhookSecret, settings, org.IsActive, org.CreatedAt, org.UpdatedAt)
	return err
}

func (r *organizationRepo) FindByID(ctx context.Context, id domain.OrganizationID) (*domain.Organization, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, name, slug, webhook_url, webhook_secret, settings, is_active, created_at, updated_at, deleted_at
		FROM organizations WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	org, err := scanOrganization(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return org, nil
}

func (r *organizationRepo) FindBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, name, slug, webhook_url, webhook_secret, settings, is_active, created_at, updated_at, deleted_at
		FROM organizations WHERE slug = $1 AND deleted_at IS NULL
	`, slug)
	org, err := scanOrganization(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return org, nil
}

func (r *organizationRepo) Update(ctx context.Context, org *domain.Organization) error {
	q := QuerierFromContext(ctx, r.pool)
	settings, _ := json.Marshal(org.Settings)
	_, err := q.Exec(ctx, `
		UPDATE organizations SET name = $2, slug = $3, webhook_url = $4, webhook_secret = $5, settings = $6, is_active = $7, updated_at = $8
		WHERE id = $1 AND deleted_at IS NULL
	`, string(org.ID), org.Name, org.Slug, org.WebhookURL, org.WebhookSecret, settings, org.IsActive, org.UpdatedAt)
	return err
}

func (r *organizationRepo) SoftDelete(ctx context.Context, id domain.OrganizationID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE organizations SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *organizationRepo) FindAll(ctx context.Context, params organization.ListParams) ([]*domain.Organization, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "name", "slug"}, "created_at")
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
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM organizations WHERE deleted_at IS NULL`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `SELECT id, name, slug, webhook_url, webhook_secret, settings, is_active, created_at, updated_at, deleted_at
		FROM organizations WHERE deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var orgs []*domain.Organization
	for rows.Next() {
		org, err := scanOrganization(rows)
		if err != nil {
			return nil, 0, err
		}
		orgs = append(orgs, org)
	}
	return orgs, total, rows.Err()
}

func scanOrganization(row pgx.Row) (*domain.Organization, error) {
	var id, name, slug string
	var webhookURL, webhookSecret *string
	var settings []byte
	var isActive bool
	var createdAt, updatedAt time.Time
	var deletedAt *time.Time
	err := row.Scan(&id, &name, &slug, &webhookURL, &webhookSecret, &settings, &isActive, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	var settingsMap map[string]any
	if len(settings) > 0 {
		_ = json.Unmarshal(settings, &settingsMap)
	}
	org := &domain.Organization{
		ID:        domain.OrganizationID(id),
		Name:      name,
		Slug:      slug,
		Settings:  settingsMap,
		IsActive:  isActive,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		DeletedAt: deletedAt,
	}
	if webhookURL != nil {
		org.WebhookURL = *webhookURL
	}
	if webhookSecret != nil {
		org.WebhookSecret = *webhookSecret
	}
	return org, nil
}
