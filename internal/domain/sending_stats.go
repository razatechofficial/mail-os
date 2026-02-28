package domain

import "time"

type PeriodType string

const (
	PeriodTypeHourly  PeriodType = "hourly"
	PeriodTypeDaily   PeriodType = "daily"
	PeriodTypeMonthly PeriodType = "monthly"
)

type SendingStats struct {
	ID          string
	OrgID       OrganizationID
	PeriodType  PeriodType
	PeriodStart time.Time
	Sent        int
	Delivered   int
	Bounced     int
	Complained  int
	Opened      int
	Clicked     int
	Failed      int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
