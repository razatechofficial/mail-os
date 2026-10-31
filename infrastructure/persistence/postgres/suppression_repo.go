package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/suppression"
	domain "github.com/razatechofficial/mail-os/domain/suppression"
)

// SuppressionRepository stores the suppression list (one row per tenant
// and lowercased address).
type SuppressionRepository struct {
	db *Pool
}

var _ app.Repository = (*SuppressionRepository)(nil)

// NewSuppressionRepository returns the repository.
func NewSuppressionRepository(db *Pool) *SuppressionRepository { return &SuppressionRepository{db: db} }

const suppressionCols = `id, org_id, email, type, COALESCE(reason, ''), COALESCE(source, ''), COALESCE(created_by, ''), created_at`

func scanSuppression(row pgx.Row) (domain.Suppression, error) {
	var s domain.Suppression
	var typ string
	err := row.Scan(&s.ID, &s.OrgID, &s.Email, &typ, &s.Reason, &s.Source, &s.CreatedBy, &s.CreatedAt)
	s.Type = domain.Type(typ)
	return s, err
}

// Upsert adds s unless the address is listed, and returns the stored row.
func (r *SuppressionRepository) Upsert(ctx context.Context, s domain.Suppression) (domain.Suppression, error) {
	q := QuerierFromContext(ctx, r.db)
	_, err := q.Exec(ctx, `INSERT INTO suppressions (id, org_id, email, type, reason, source, created_by, created_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8) ON CONFLICT (org_id, email) DO NOTHING`,
		s.ID, s.OrgID, s.Email, string(s.Type), s.Reason, s.Source, s.CreatedBy, s.CreatedAt)
	if err != nil {
		return domain.Suppression{}, err
	}
	return scanSuppression(q.QueryRow(ctx, `SELECT `+suppressionCols+` FROM suppressions WHERE org_id = $1 AND email = $2`, s.OrgID, s.Email))
}

// Delete removes the address.
func (r *SuppressionRepository) Delete(ctx context.Context, tenantID, email string) (bool, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `DELETE FROM suppressions WHERE org_id = $1 AND email = $2`, tenantID, email)
	return err == nil && tag.RowsAffected() > 0, err
}

// Find returns the address's suppression, or nil.
func (r *SuppressionRepository) Find(ctx context.Context, tenantID, email string) (*domain.Suppression, error) {
	s, err := scanSuppression(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+suppressionCols+` FROM suppressions WHERE org_id = $1 AND email = $2`, tenantID, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// List returns a page, newest first, optionally of one type.
func (r *SuppressionRepository) List(ctx context.Context, tenantID, typ string, limit, offset int) ([]domain.Suppression, int, error) {
	q := QuerierFromContext(ctx, r.db)
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM suppressions WHERE org_id = $1 AND ($2 = '' OR type = $2)`, tenantID, typ).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query(ctx, `SELECT `+suppressionCols+` FROM suppressions WHERE org_id = $1 AND ($2 = '' OR type = $2)
		ORDER BY created_at DESC LIMIT $3 OFFSET $4`, tenantID, typ, limit, offset)
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
