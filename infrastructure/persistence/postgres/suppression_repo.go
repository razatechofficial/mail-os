package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/suppression"
	domain "github.com/razatechofficial/mail-os/domain/suppression"
)

// SuppressionRepository stores the suppression list: one row per tenant,
// lowercased address and scope (application_id, NULL for tenant-wide).
type SuppressionRepository struct {
	db *Pool
}

var _ app.Repository = (*SuppressionRepository)(nil)

// NewSuppressionRepository returns the repository.
func NewSuppressionRepository(db *Pool) *SuppressionRepository { return &SuppressionRepository{db: db} }

const suppressionCols = `id, org_id, email, type, COALESCE(reason, ''), COALESCE(source, ''), COALESCE(created_by, ''), created_at,
	COALESCE(application_id, '')`

func scanSuppression(row pgx.Row) (domain.Suppression, error) {
	var s domain.Suppression
	var typ string
	err := row.Scan(&s.ID, &s.OrgID, &s.Email, &typ, &s.Reason, &s.Source, &s.CreatedBy, &s.CreatedAt, &s.ApplicationID)
	s.Type = domain.Type(typ)
	return s, err
}

// Upsert adds s unless the address is listed, and returns the stored row.
func (r *SuppressionRepository) Upsert(ctx context.Context, s domain.Suppression) (domain.Suppression, error) {
	q := QuerierFromContext(ctx, r.db)
	_, err := q.Exec(ctx, `INSERT INTO suppressions (id, org_id, email, type, reason, source, created_by, created_at, application_id)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8, NULLIF($9, ''))
		ON CONFLICT (org_id, email, (COALESCE(application_id, ''))) DO NOTHING`,
		s.ID, s.OrgID, s.Email, string(s.Type), s.Reason, s.Source, s.CreatedBy, s.CreatedAt, s.ApplicationID)
	if err != nil {
		return domain.Suppression{}, err
	}
	return scanSuppression(q.QueryRow(ctx, `SELECT `+suppressionCols+` FROM suppressions
		WHERE org_id = $1 AND email = $2 AND COALESCE(application_id, '') = $3`, s.OrgID, s.Email, s.ApplicationID))
}

// Delete removes the address from one scope.
func (r *SuppressionRepository) Delete(ctx context.Context, tenantID, applicationID, email string) (bool, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`DELETE FROM suppressions WHERE org_id = $1 AND email = $2 AND COALESCE(application_id, '') = $3`, tenantID, email, applicationID)
	return err == nil && tag.RowsAffected() > 0, err
}

// Find returns the address's tenant-wide entry and the application's.
func (r *SuppressionRepository) Find(ctx context.Context, tenantID, applicationID, email string) ([]domain.Suppression, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT `+suppressionCols+` FROM suppressions
		WHERE org_id = $1 AND email = $2 AND (application_id IS NULL OR ($3 <> '' AND application_id = $3))
		ORDER BY application_id NULLS FIRST`, tenantID, email, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Suppression
	for rows.Next() {
		s, err := scanSuppression(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// List returns a page, newest first.
func (r *SuppressionRepository) List(ctx context.Context, f app.Filter) ([]domain.Suppression, int, error) {
	q := QuerierFromContext(ctx, r.db)
	where := `org_id = $1 AND ($2 = '' OR type = $2) AND ($3 = '' OR application_id = $3)`
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM suppressions WHERE `+where, f.TenantID, f.Type, f.ApplicationID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query(ctx, `SELECT `+suppressionCols+` FROM suppressions WHERE `+where+`
		ORDER BY created_at DESC LIMIT $4 OFFSET $5`, f.TenantID, f.Type, f.ApplicationID, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.Suppression
	for rows.Next() {
		s, err := scanSuppression(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}
