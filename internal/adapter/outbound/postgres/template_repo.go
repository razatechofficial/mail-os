package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/template"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type templateRepo struct {
	pool *pgxpool.Pool
}

var _ template.Repository = (*templateRepo)(nil)

func NewTemplateRepo(pool *pgxpool.Pool) template.Repository {
	return &templateRepo{pool: pool}
}

func (r *templateRepo) Create(ctx context.Context, t *domain.Template) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO templates (id, org_id, name, slug, category, description, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, string(t.ID), string(t.OrgID), t.Name, t.Slug, string(t.Category), t.Description, t.IsActive, t.CreatedAt, t.UpdatedAt)
	return err
}

func (r *templateRepo) FindByID(ctx context.Context, id domain.TemplateID) (*domain.Template, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, name, slug, category, description, is_active, created_at, updated_at, deleted_at
		FROM templates WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	tpl, err := scanTemplate(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return tpl, nil
}

func (r *templateRepo) FindBySlug(ctx context.Context, orgID domain.OrganizationID, slug string) (*domain.Template, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, name, slug, category, description, is_active, created_at, updated_at, deleted_at
		FROM templates WHERE org_id = $1 AND slug = $2 AND deleted_at IS NULL
	`, string(orgID), slug)
	tpl, err := scanTemplate(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return tpl, nil
}

func (r *templateRepo) Update(ctx context.Context, t *domain.Template) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE templates SET name = $2, slug = $3, category = $4, description = $5, is_active = $6, updated_at = $7
		WHERE id = $1 AND deleted_at IS NULL
	`, string(t.ID), t.Name, t.Slug, string(t.Category), t.Description, t.IsActive, t.UpdatedAt)
	return err
}

func (r *templateRepo) SoftDelete(ctx context.Context, id domain.TemplateID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE templates SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *templateRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params template.ListParams) ([]*domain.Template, int, error) {
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
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM templates WHERE org_id = $1 AND deleted_at IS NULL`, string(orgID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `SELECT id, org_id, name, slug, category, description, is_active, created_at, updated_at, deleted_at
		FROM templates WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3`, string(orgID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []*domain.Template
	for rows.Next() {
		tpl, err := scanTemplate(rows)
		if err != nil {
			return nil, 0, err
		}
		list = append(list, tpl)
	}
	return list, total, rows.Err()
}

func (r *templateRepo) CreateVersion(ctx context.Context, v *domain.TemplateVersion) error {
	q := QuerierFromContext(ctx, r.pool)
	variables := v.Variables
	if variables == nil {
		variables = []string{}
	}
	if _, err := q.Exec(ctx, `UPDATE template_versions SET is_active = false WHERE template_id = $1`, string(v.TemplateID)); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		INSERT INTO template_versions (id, template_id, version, subject, html_body, text_body, variables, is_active, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, string(v.ID), string(v.TemplateID), v.Version, v.Subject, v.HTMLBody, v.TextBody, variables, v.IsActive, v.CreatedAt)
	return err
}

func (r *templateRepo) FindActiveVersion(ctx context.Context, templateID domain.TemplateID) (*domain.TemplateVersion, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, template_id, version, subject, html_body, text_body, variables, is_active, created_at
		FROM template_versions WHERE template_id = $1 AND is_active = true
	`, string(templateID))
	v, err := scanTemplateVersion(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return v, nil
}

func (r *templateRepo) FindVersions(ctx context.Context, templateID domain.TemplateID) ([]*domain.TemplateVersion, error) {
	q := QuerierFromContext(ctx, r.pool)
	rows, err := q.Query(ctx, `
		SELECT id, template_id, version, subject, html_body, text_body, variables, is_active, created_at
		FROM template_versions WHERE template_id = $1 ORDER BY version DESC
	`, string(templateID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*domain.TemplateVersion
	for rows.Next() {
		v, err := scanTemplateVersion(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, v)
	}
	return list, rows.Err()
}

func (r *templateRepo) FindLatestVersionNumber(ctx context.Context, templateID domain.TemplateID) (int, error) {
	q := QuerierFromContext(ctx, r.pool)
	var version int
	err := q.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM template_versions WHERE template_id = $1`, string(templateID)).Scan(&version)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func scanTemplate(row pgx.Row) (*domain.Template, error) {
	var id, orgID, name, slug, category string
	var description *string
	var isActive bool
	var createdAt, updatedAt time.Time
	var deletedAt *time.Time
	err := row.Scan(&id, &orgID, &name, &slug, &category, &description, &isActive, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	tpl := &domain.Template{
		ID:        domain.TemplateID(id),
		OrgID:     domain.OrganizationID(orgID),
		Name:      name,
		Slug:      slug,
		Category:  domain.TemplateCategory(category),
		IsActive:  isActive,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		DeletedAt: deletedAt,
	}
	if description != nil {
		tpl.Description = *description
	}
	return tpl, nil
}

func scanTemplateVersion(row pgx.Row) (*domain.TemplateVersion, error) {
	var id, templateID, subject, htmlBody, textBody string
	var version int
	var variables []string
	var isActive bool
	var createdAt time.Time
	err := row.Scan(&id, &templateID, &version, &subject, &htmlBody, &textBody, &variables, &isActive, &createdAt)
	if err != nil {
		return nil, err
	}
	return &domain.TemplateVersion{
		ID:         domain.TemplateVersionID(id),
		TemplateID: domain.TemplateID(templateID),
		Version:    version,
		Subject:    subject,
		HTMLBody:   htmlBody,
		TextBody:   textBody,
		Variables:  variables,
		IsActive:   isActive,
		CreatedAt:  createdAt,
	}, nil
}
