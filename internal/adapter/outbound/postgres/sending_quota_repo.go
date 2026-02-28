package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type sendingQuotaRepo struct {
	pool *pgxpool.Pool
}

func NewSendingQuotaRepo(pool *pgxpool.Pool) *sendingQuotaRepo {
	return &sendingQuotaRepo{pool: pool}
}

func (r *sendingQuotaRepo) FindByOrgID(ctx context.Context, orgID domain.OrganizationID) (*domain.SendingQuota, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, daily_limit, daily_used, monthly_limit, monthly_used, reset_at, created_at, updated_at
		FROM sending_quotas WHERE org_id = $1
	`, string(orgID))
	quota, err := scanSendingQuota(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return quota, nil
}

func (r *sendingQuotaRepo) IncrementDaily(ctx context.Context, orgID domain.OrganizationID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE sending_quotas SET daily_used = daily_used + 1, updated_at = NOW() WHERE org_id = $1
	`, string(orgID))
	return err
}

func (r *sendingQuotaRepo) Upsert(ctx context.Context, quota *domain.SendingQuota) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO sending_quotas (id, org_id, daily_limit, daily_used, monthly_limit, monthly_used, reset_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (org_id) DO UPDATE SET
			daily_limit = EXCLUDED.daily_limit,
			daily_used = EXCLUDED.daily_used,
			monthly_limit = EXCLUDED.monthly_limit,
			monthly_used = EXCLUDED.monthly_used,
			reset_at = EXCLUDED.reset_at,
			updated_at = EXCLUDED.updated_at
	`, quota.ID, string(quota.OrgID), quota.DailyLimit, quota.DailyUsed, quota.MonthlyLimit, quota.MonthlyUsed,
		quota.ResetAt, quota.CreatedAt, quota.UpdatedAt)
	return err
}

func scanSendingQuota(row pgx.Row) (*domain.SendingQuota, error) {
	var id, orgID string
	var dailyLimit, dailyUsed, monthlyLimit, monthlyUsed int
	var resetAt, createdAt, updatedAt time.Time
	err := row.Scan(&id, &orgID, &dailyLimit, &dailyUsed, &monthlyLimit, &monthlyUsed, &resetAt, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	return &domain.SendingQuota{
		ID:           id,
		OrgID:        domain.OrganizationID(orgID),
		DailyLimit:   dailyLimit,
		DailyUsed:    dailyUsed,
		MonthlyLimit: monthlyLimit,
		MonthlyUsed:  monthlyUsed,
		ResetAt:      resetAt,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}, nil
}
