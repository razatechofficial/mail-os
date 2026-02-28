package domain

import "time"

type SendingQuota struct {
	ID           string
	OrgID        OrganizationID
	DailyLimit   int
	DailyUsed    int
	MonthlyLimit int
	MonthlyUsed  int
	ResetAt      time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
