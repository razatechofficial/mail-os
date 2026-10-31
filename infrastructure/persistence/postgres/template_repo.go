package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	app "github.com/razatechofficial/mail-os/application/template"
	domain "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// TemplateRepository stores templates (templates), their drafts
// (template_drafts), published versions (template_versions) and the
// organization's branding (template_branding). Template reads are scoped
// to the tenant (org_id) and skip soft-deleted rows.
type TemplateRepository struct {
	db *Pool
}

var _ app.Repository = (*TemplateRepository)(nil)

// NewTemplateRepository returns the repository.
func NewTemplateRepository(db *Pool) *TemplateRepository { return &TemplateRepository{db: db} }

// InTx runs fn in a transaction.
func (r *TemplateRepository) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return r.db.InTx(ctx, fn)
}

const templateColumns = `id, org_id, name, slug, category, COALESCE(description, ''), topic, default_locale, is_active, created_at, updated_at`

func scanTemplate(row pgx.Row) (domain.Template, error) {
	var t domain.Template
	err := row.Scan(&t.ID, &t.OrgID, &t.Name, &t.Slug, &t.Category, &t.Description, &t.Topic, &t.DefaultLocale,
		&t.IsActive, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Template{}, apperrors.NotFound("template not found")
	}
	return t, err
}

// List returns one page of the tenant's templates, newest first.
func (r *TemplateRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Template, int, error) {
	q := QuerierFromContext(ctx, r.db)
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM templates WHERE org_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query(ctx, `SELECT `+templateColumns+` FROM templates
		WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.Template
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

func (r *TemplateRepository) getWhere(ctx context.Context, where, suffix string, args ...any) (domain.Template, error) {
	return scanTemplate(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+templateColumns+` FROM templates WHERE org_id = $1 AND deleted_at IS NULL AND `+where+suffix, args...))
}

// Get reads one template of the tenant.
func (r *TemplateRepository) Get(ctx context.Context, tenantID, templateID string) (domain.Template, error) {
	return r.getWhere(ctx, "id = $2", "", tenantID, templateID)
}

// GetForUpdate reads and locks one template of the tenant.
func (r *TemplateRepository) GetForUpdate(ctx context.Context, tenantID, templateID string) (domain.Template, error) {
	return r.getWhere(ctx, "id = $2", " FOR UPDATE", tenantID, templateID)
}

// GetBySlug reads a template by slug.
func (r *TemplateRepository) GetBySlug(ctx context.Context, tenantID, slug string) (domain.Template, error) {
	return r.getWhere(ctx, "slug = $2", "", tenantID, slug)
}

// GetByTopic reads the template serving a topic.
func (r *TemplateRepository) GetByTopic(ctx context.Context, tenantID, topic string) (domain.Template, error) {
	return r.getWhere(ctx, "topic = $2 AND topic <> ''", "", tenantID, topic)
}

// uniqueTaken maps the slug and topic unique indexes to their field errors.
func uniqueTaken(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != uniqueViolation {
		return err
	}
	switch pgErr.ConstraintName {
	case "idx_templates_org_slug":
		return app.ErrSlugTaken
	case "idx_templates_org_topic":
		return app.ErrTopicTaken
	}
	return err
}

// Create inserts a template.
func (r *TemplateRepository) Create(ctx context.Context, t domain.Template) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO templates (id, org_id, name, slug, category, description, topic, default_locale, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		t.ID, t.OrgID, t.Name, t.Slug, t.Category, t.Description, t.Topic, t.DefaultLocale, t.IsActive, t.CreatedAt, t.UpdatedAt)
	return uniqueTaken(err)
}

// Update writes a template's metadata.
func (r *TemplateRepository) Update(ctx context.Context, t domain.Template) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE templates SET name = $3, slug = $4, category = $5, description = $6, topic = $7, default_locale = $8,
			is_active = $9, updated_at = $10
		WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL`,
		t.OrgID, t.ID, t.Name, t.Slug, t.Category, t.Description, t.Topic, t.DefaultLocale, t.IsActive, t.UpdatedAt)
	if err != nil {
		return uniqueTaken(err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.NotFound("template not found")
	}
	return nil
}

// Delete soft-deletes a template; its slug and topic are free again.
func (r *TemplateRepository) Delete(ctx context.Context, tenantID, templateID string, at time.Time) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE templates SET deleted_at = $3, updated_at = $3 WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL`,
		tenantID, templateID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apperrors.NotFound("template not found")
	}
	return nil
}

// ── drafts ────────────────────────────────────────────────────────────────

// Draft reads the saved draft of a locale.
func (r *TemplateRepository) Draft(ctx context.Context, templateID string, locale domain.Locale) (domain.Draft, bool, error) {
	var d domain.Draft
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `
		SELECT template_id, locale, subject, preheader, design, html_body, text_body, variables, revision, updated_by, updated_at
		FROM template_drafts WHERE template_id = $1 AND locale = $2`, templateID, locale).
		Scan(&d.TemplateID, &d.Locale, &d.Subject, &d.Preheader, &d.Design, &d.HTMLBody, &d.TextBody, &d.Variables,
			&d.Revision, &d.UpdatedBy, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Draft{Revision: 0}, false, nil
	}
	if err != nil {
		return domain.Draft{}, false, err
	}
	return d, true, nil
}

// SaveDraft inserts the first revision or updates the stored one when it
// is still prev; anything else is a CONFLICT, so two concurrent saves of
// one revision never both win.
func (r *TemplateRepository) SaveDraft(ctx context.Context, d domain.Draft, prev int) error {
	q := QuerierFromContext(ctx, r.db)
	vars := d.Variables
	if vars == nil {
		vars = []string{}
	}
	conflict := apperrors.Conflict("the draft was saved by someone else; reload it")
	if prev == 0 {
		_, err := q.Exec(ctx, `
			INSERT INTO template_drafts (template_id, locale, subject, preheader, design, html_body, text_body, variables, revision, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			d.TemplateID, d.Locale, d.Subject, d.Preheader, jsonOrNull(d.Design), d.HTMLBody, d.TextBody, vars, d.Revision, d.UpdatedBy, d.UpdatedAt)
		if IsUniqueViolation(err) {
			return conflict
		}
		return err
	}
	tag, err := q.Exec(ctx, `
		UPDATE template_drafts SET subject = $4, preheader = $5, design = $6, html_body = $7, text_body = $8, variables = $9,
			revision = $10, updated_by = $11, updated_at = $12
		WHERE template_id = $1 AND locale = $2 AND revision = $3`,
		d.TemplateID, d.Locale, prev, d.Subject, d.Preheader, jsonOrNull(d.Design), d.HTMLBody, d.TextBody, vars, d.Revision, d.UpdatedBy, d.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return conflict
	}
	return nil
}

// jsonOrNull passes a design as JSON, or SQL NULL when there is none.
func jsonOrNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// ── versions ──────────────────────────────────────────────────────────────

const versionColumns = `v.id, v.template_id, v.version, v.locale, v.subject, v.preheader, v.design, v.html_body,
	COALESCE(v.text_body, ''), COALESCE(v.variables, '{}'), v.status, v.is_active, COALESCE(v.published_by, ''),
	COALESCE(v.published_at, v.created_at), v.created_at`

func scanVersion(row pgx.Row) (domain.Version, error) {
	var v domain.Version
	err := row.Scan(&v.ID, &v.TemplateID, &v.Number, &v.Locale, &v.Subject, &v.Preheader, &v.Design, &v.HTMLBody,
		&v.TextBody, &v.Variables, &v.Status, &v.IsActive, &v.PublishedBy, &v.PublishedAt, &v.CreatedAt)
	return v, NotFound(err)
}

// Versions lists a template's versions newest first.
func (r *TemplateRepository) Versions(ctx context.Context, templateID string, locale domain.Locale) ([]domain.Version, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT `+versionColumns+` FROM template_versions v
		WHERE v.template_id = $1 AND ($2 = '' OR v.locale = $2) ORDER BY v.version DESC`, templateID, string(locale))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Version{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ActiveVersion reads a locale's active version.
func (r *TemplateRepository) ActiveVersion(ctx context.Context, templateID string, locale domain.Locale) (domain.Version, error) {
	return scanVersion(QuerierFromContext(ctx, r.db).QueryRow(ctx, `SELECT `+versionColumns+` FROM template_versions v
		WHERE v.template_id = $1 AND v.locale = $2 AND v.is_active`, templateID, locale))
}

// VersionByNumber reads one version.
func (r *TemplateRepository) VersionByNumber(ctx context.Context, templateID string, number int) (domain.Version, error) {
	return scanVersion(QuerierFromContext(ctx, r.db).QueryRow(ctx, `SELECT `+versionColumns+` FROM template_versions v
		WHERE v.template_id = $1 AND v.version = $2`, templateID, number))
}

// VersionByID reads a version of one of the tenant's live templates.
func (r *TemplateRepository) VersionByID(ctx context.Context, tenantID, versionID string) (domain.Version, error) {
	return scanVersion(QuerierFromContext(ctx, r.db).QueryRow(ctx, `SELECT `+versionColumns+` FROM template_versions v
		JOIN templates t ON t.id = v.template_id
		WHERE v.id = $2 AND t.org_id = $1 AND t.deleted_at IS NULL`, tenantID, versionID))
}

// MaxVersionNumber is the template's highest version number, 0 for none.
func (r *TemplateRepository) MaxVersionNumber(ctx context.Context, templateID string) (int, error) {
	var n int
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT COALESCE(max(version), 0) FROM template_versions WHERE template_id = $1`, templateID).Scan(&n)
	return n, err
}

// InsertVersion deactivates the locale's active version and inserts v as
// the active one. Run it in the publish transaction.
func (r *TemplateRepository) InsertVersion(ctx context.Context, v domain.Version) error {
	return r.db.InTx(ctx, func(ctx context.Context) error {
		q := QuerierFromContext(ctx, r.db)
		if _, err := q.Exec(ctx, `UPDATE template_versions SET is_active = false WHERE template_id = $1 AND locale = $2 AND is_active`,
			v.TemplateID, v.Locale); err != nil {
			return err
		}
		vars := v.Variables
		if vars == nil {
			vars = []string{}
		}
		_, err := q.Exec(ctx, `
			INSERT INTO template_versions (id, template_id, version, locale, subject, preheader, design, html_body, text_body,
				variables, status, is_active, published_by, published_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			v.ID, v.TemplateID, v.Number, v.Locale, v.Subject, v.Preheader, jsonOrNull(v.Design), v.HTMLBody, v.TextBody,
			vars, v.Status, v.IsActive, v.PublishedBy, v.PublishedAt, v.CreatedAt)
		if IsUniqueViolation(err) {
			return apperrors.Conflict("another version was published at the same time; reload and publish again")
		}
		return err
	})
}

// ── branding ──────────────────────────────────────────────────────────────

// Branding reads the organization's saved branding.
func (r *TemplateRepository) Branding(ctx context.Context, tenantID string) (domain.Branding, bool, error) {
	var b domain.Branding
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `
		SELECT org_id, company_name, logo_url, logo_alt, primary_color, background_color, content_background_color,
			text_color, link_color, font_family, company_address, footer_text, updated_at
		FROM template_branding WHERE org_id = $1`, tenantID).
		Scan(&b.OrgID, &b.CompanyName, &b.LogoURL, &b.LogoAlt, &b.PrimaryColor, &b.BackgroundColor, &b.ContentBackgroundColor,
			&b.TextColor, &b.LinkColor, &b.FontFamily, &b.CompanyAddress, &b.FooterText, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Branding{}, false, nil
	}
	if err != nil {
		return domain.Branding{}, false, err
	}
	return b, true, nil
}

// SaveBranding upserts the organization's branding.
func (r *TemplateRepository) SaveBranding(ctx context.Context, b domain.Branding, by string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO template_branding (org_id, company_name, logo_url, logo_alt, primary_color, background_color,
			content_background_color, text_color, link_color, font_family, company_address, footer_text, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULLIF($13, ''), $14)
		ON CONFLICT (org_id) DO UPDATE SET company_name = EXCLUDED.company_name, logo_url = EXCLUDED.logo_url,
			logo_alt = EXCLUDED.logo_alt, primary_color = EXCLUDED.primary_color, background_color = EXCLUDED.background_color,
			content_background_color = EXCLUDED.content_background_color, text_color = EXCLUDED.text_color,
			link_color = EXCLUDED.link_color, font_family = EXCLUDED.font_family, company_address = EXCLUDED.company_address,
			footer_text = EXCLUDED.footer_text, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		b.OrgID, b.CompanyName, b.LogoURL, b.LogoAlt, b.PrimaryColor, b.BackgroundColor, b.ContentBackgroundColor,
		b.TextColor, b.LinkColor, b.FontFamily, b.CompanyAddress, b.FooterText, by, b.UpdatedAt)
	return err
}
