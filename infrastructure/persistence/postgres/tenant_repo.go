package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/tenant"
	domain "github.com/razatechofficial/mail-os/domain/tenant"
)

// TenantRepository maps tenants onto the organizations table (id = IAM
// tenant UUID) and tenant_settings.
type TenantRepository struct {
	db *Pool
}

var _ app.Repository = (*TenantRepository)(nil)

// NewTenantRepository returns the repository.
func NewTenantRepository(db *Pool) *TenantRepository { return &TenantRepository{db: db} }

// Get reads one tenant.
func (r *TenantRepository) Get(ctx context.Context, id string) (domain.Tenant, error) {
	var t domain.Tenant
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT id, name, is_active AND deleted_at IS NULL, created_at FROM organizations WHERE id = $1`, id).
		Scan(&t.ID, &t.Name, &t.Active, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Tenant{}, domain.ErrNotFound
	}
	return t, err
}

// Create inserts the tenant unless it exists (the slug is the id).
func (r *TenantRepository) Create(ctx context.Context, t domain.Tenant) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO organizations (id, name, slug, is_active, created_at, updated_at)
		VALUES ($1, $2, $1, $3, $4, $4) ON CONFLICT DO NOTHING`, t.ID, t.Name, t.Active, t.CreatedAt)
	return err
}

// Settings returns saved settings, or the defaults.
func (r *TenantRepository) Settings(ctx context.Context, id string) (domain.Settings, error) {
	s := domain.Settings{TenantID: id}
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx, `
		SELECT four_eyes_publish, message_retention_days, COALESCE(updated_by, ''), updated_at
		FROM tenant_settings WHERE org_id = $1`, id).
		Scan(&s.FourEyesPublish, &s.MessageRetentionDays, &s.UpdatedBy, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	return s, err
}

// SaveSettings upserts settings.
func (r *TenantRepository) SaveSettings(ctx context.Context, s domain.Settings) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO tenant_settings (org_id, four_eyes_publish, message_retention_days, updated_by, updated_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5)
		ON CONFLICT (org_id) DO UPDATE SET four_eyes_publish = EXCLUDED.four_eyes_publish,
			message_retention_days = EXCLUDED.message_retention_days, updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at`,
		s.TenantID, s.FourEyesPublish, s.MessageRetentionDays, s.UpdatedBy, s.UpdatedAt)
	return err
}
