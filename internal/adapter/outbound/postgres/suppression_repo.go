package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/razatechofficial/mail-os/internal/core/suppression"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type suppressionRepo struct {
	pool *pgxpool.Pool
}

var _ suppression.Repository = (*suppressionRepo)(nil)

func NewSuppressionRepo(pool *pgxpool.Pool) suppression.Repository {
	return &suppressionRepo{pool: pool}
}

func (r *suppressionRepo) Create(ctx context.Context, s *domain.Suppression) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO suppressions (id, org_id, email, type, reason, source, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, s.ID, string(s.OrgID), s.Email, string(s.Type), nullStr(s.Reason), nullStr(s.Source), s.CreatedAt)
	return err
}

func (r *suppressionRepo) Delete(ctx context.Context, orgID domain.OrganizationID, email string) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `DELETE FROM suppressions WHERE org_id = $1 AND email = $2`, string(orgID), email)
	return err
}

func (r *suppressionRepo) ExistsByEmail(ctx context.Context, orgID domain.OrganizationID, email string) (bool, error) {
	q := QuerierFromContext(ctx, r.pool)
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM suppressions WHERE org_id = $1 AND email = $2)`, string(orgID), email).Scan(&exists)
	return exists, err
}

func (r *suppressionRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params suppression.ListParams) ([]*domain.Suppression, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "email", "type"}, "created_at")
	sortOrder := "ASC"
	if params.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset()

	base := `FROM suppressions WHERE org_id = $1`
	args := []interface{}{string(orgID)}
	argIdx := 2
	if params.Type != "" {
		base += fmt.Sprintf(` AND type = $%d`, argIdx)
		args = append(args, params.Type)
		argIdx++
	}

	var total int
	err := q.QueryRow(ctx, `SELECT COUNT(*) `+base, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := q.Query(ctx, fmt.Sprintf(`
		SELECT id, org_id, email, type, reason, source, created_at
		%s ORDER BY %s %s LIMIT $%d OFFSET $%d
	`, base, sortBy, sortOrder, argIdx, argIdx+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var suppressions []*domain.Suppression
	for rows.Next() {
		s, err := scanSuppression(rows)
		if err != nil {
			return nil, 0, err
		}
		suppressions = append(suppressions, s)
	}
	return suppressions, total, rows.Err()
}

func scanSuppression(row pgx.Row) (*domain.Suppression, error) {
	var id, orgID, email, supType, reason, source string
	var createdAt time.Time
	err := row.Scan(&id, &orgID, &email, &supType, &reason, &source, &createdAt)
	if err != nil {
		return nil, err
	}
	return &domain.Suppression{
		ID:        id,
		OrgID:     domain.OrganizationID(orgID),
		Email:     email,
		Type:      domain.SuppressionType(supType),
		Reason:    reason,
		Source:    source,
		CreatedAt: createdAt,
	}, nil
}
