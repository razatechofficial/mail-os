package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/razatechofficial/mail-os/internal/core/analytics"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type sendingStatsRepo struct {
	pool *pgxpool.Pool
}

var _ analytics.StatsRepository = (*sendingStatsRepo)(nil)

func NewSendingStatsRepo(pool *pgxpool.Pool) analytics.StatsRepository {
	return &sendingStatsRepo{pool: pool}
}

func (r *sendingStatsRepo) Upsert(ctx context.Context, stats *domain.SendingStats) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO sending_stats (id, org_id, period_type, period_start, sent, delivered, bounced, complained, opened, clicked, failed, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (org_id, period_type, period_start) DO UPDATE SET
			sent = sending_stats.sent + EXCLUDED.sent,
			delivered = sending_stats.delivered + EXCLUDED.delivered,
			bounced = sending_stats.bounced + EXCLUDED.bounced,
			complained = sending_stats.complained + EXCLUDED.complained,
			opened = sending_stats.opened + EXCLUDED.opened,
			clicked = sending_stats.clicked + EXCLUDED.clicked,
			failed = sending_stats.failed + EXCLUDED.failed,
			updated_at = EXCLUDED.updated_at
	`, stats.ID, string(stats.OrgID), string(stats.PeriodType), stats.PeriodStart, stats.Sent, stats.Delivered, stats.Bounced,
		stats.Complained, stats.Opened, stats.Clicked, stats.Failed, stats.CreatedAt, stats.UpdatedAt)
	return err
}

func (r *sendingStatsRepo) FindByOrgAndPeriod(ctx context.Context, orgID domain.OrganizationID, params analytics.StatsParams) ([]*domain.SendingStats, error) {
	q := QuerierFromContext(ctx, r.pool)
	rows, err := q.Query(ctx, `
		SELECT id, org_id, period_type, period_start, sent, delivered, bounced, complained, opened, clicked, failed, created_at, updated_at
		FROM sending_stats
		WHERE org_id = $1 AND period_type = $2 AND period_start >= $3 AND period_start < $4
		ORDER BY period_start ASC
	`, string(orgID), string(params.PeriodType), params.From, params.To)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*domain.SendingStats
	for rows.Next() {
		s, err := scanSendingStats(rows)
		if err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func (r *sendingStatsRepo) BatchUpsert(ctx context.Context, stats []*domain.SendingStats) error {
	for _, s := range stats {
		if err := r.Upsert(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func scanSendingStats(row pgx.Row) (*domain.SendingStats, error) {
	var id, orgID, periodType string
	var periodStart, createdAt, updatedAt time.Time
	var sent, delivered, bounced, complained, opened, clicked, failed int
	err := row.Scan(&id, &orgID, &periodType, &periodStart, &sent, &delivered, &bounced, &complained, &opened, &clicked, &failed, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	return &domain.SendingStats{
		ID:          id,
		OrgID:       domain.OrganizationID(orgID),
		PeriodType:  domain.PeriodType(periodType),
		PeriodStart: periodStart,
		Sent:        sent,
		Delivered:   delivered,
		Bounced:     bounced,
		Complained:  complained,
		Opened:      opened,
		Clicked:     clicked,
		Failed:      failed,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}, nil
}
