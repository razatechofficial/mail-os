package postgres

import (
	"context"
	"fmt"
	"time"

	app "github.com/razatechofficial/mail-os/application/analytics"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// StatsRepository keeps the daily counters in sending_stats.
type StatsRepository struct {
	db *Pool
}

var _ app.Repository = (*StatsRepository)(nil)

// NewStatsRepository returns the repository.
func NewStatsRepository(db *Pool) *StatsRepository { return &StatsRepository{db: db} }

// counters are the columns Increment may touch (never input).
var counters = map[string]bool{app.Sent: true, app.Delivered: true, app.Bounced: true, app.Complained: true,
	app.Opened: true, app.Clicked: true, app.Failed: true}

// Increment adds one to counter on at's UTC day.
func (r *StatsRepository) Increment(ctx context.Context, tenantID, counter string, at time.Time) error {
	if !counters[counter] {
		return fmt.Errorf("unknown counter %q", counter)
	}
	day := at.UTC().Truncate(24 * time.Hour)
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO sending_stats (id, org_id, period_type, period_start, `+counter+`, created_at, updated_at)
		VALUES ($1, $2, 'daily', $3, 1, now(), now())
		ON CONFLICT (org_id, period_type, period_start)
		DO UPDATE SET `+counter+` = sending_stats.`+counter+` + 1, updated_at = now()`, id.New(), tenantID, day)
	return err
}

// Stats sums daily rows per day or month.
func (r *StatsRepository) Stats(ctx context.Context, tenantID, period string, from, to time.Time) ([]app.Row, error) {
	bucket := "period_start"
	if period == app.PeriodMonthly {
		bucket = "date_trunc('month', period_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'"
	}
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `
		SELECT `+bucket+` AS start, sum(sent), sum(delivered), sum(bounced), sum(complained), sum(opened), sum(clicked), sum(failed)
		FROM sending_stats WHERE org_id = $1 AND period_type = 'daily' AND period_start >= $2 AND period_start < $3
		GROUP BY start ORDER BY start`, tenantID, from.UTC().Truncate(24*time.Hour), to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []app.Row{}
	for rows.Next() {
		row := app.Row{PeriodType: period}
		if err := rows.Scan(&row.PeriodStart, &row.Sent, &row.Delivered, &row.Bounced, &row.Complained, &row.Opened, &row.Clicked, &row.Failed); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
