// Package analytics is the sending statistics use case: daily counters
// per tenant, kept by the send path and read by the console.
package analytics

import (
	"context"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Counter names (the console's StatsRow fields).
const (
	Sent       = "sent"
	Delivered  = "delivered"
	Bounced    = "bounced"
	Complained = "complained"
	Opened     = "opened"
	Clicked    = "clicked"
	Failed     = "failed"
)

// Periods.
const (
	PeriodDaily   = "daily"
	PeriodMonthly = "monthly"
)

// Row is one period's counters.
type Row struct {
	PeriodType  string    `json:"period_type"`
	PeriodStart time.Time `json:"period_start"`
	Sent        int       `json:"sent"`
	Delivered   int       `json:"delivered"`
	Bounced     int       `json:"bounced"`
	Complained  int       `json:"complained"`
	Opened      int       `json:"opened"`
	Clicked     int       `json:"clicked"`
	Failed      int       `json:"failed"`
}

// Repository stores the daily counters.
type Repository interface {
	// Increment adds one to counter for the UTC day of at.
	Increment(ctx context.Context, tenantID, counter string, at time.Time) error
	// Stats sums the daily rows in [from, to) per period ("daily" or
	// "monthly").
	Stats(ctx context.Context, tenantID, period string, from, to time.Time) ([]Row, error)
}

// Service is the analytics use case.
type Service struct {
	repo Repository
}

// NewService builds the service.
func NewService(repo Repository) *Service { return &Service{repo: repo} }

// MaxRange bounds one query.
const MaxRange = 400 * 24 * time.Hour

// Stats returns the tenant's counters. from defaults to 30 days ago and to
// to now.
func (s *Service) Stats(ctx context.Context, tenantID, period string, from, to *time.Time) ([]Row, error) {
	if period == "" {
		period = PeriodDaily
	}
	if period != PeriodDaily && period != PeriodMonthly {
		return nil, apperrors.Invalid("period_type", "invalid", "period_type must be daily or monthly")
	}
	end := time.Now().UTC().Add(time.Second)
	if to != nil {
		end = *to
	}
	start := end.AddDate(0, 0, -30)
	if from != nil {
		start = *from
	}
	if !start.Before(end) || end.Sub(start) > MaxRange {
		return nil, apperrors.Invalid("from", "invalid", "from must be before to, at most 400 days apart")
	}
	return s.repo.Stats(ctx, tenantID, period, start, end)
}

// Count adds one to a counter.
func (s *Service) Count(ctx context.Context, tenantID, counter string, at time.Time) error {
	return s.repo.Increment(ctx, tenantID, counter, at)
}
