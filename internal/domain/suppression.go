package domain

import "time"

type SuppressionType string

const (
	SuppressionTypeHardBounce   SuppressionType = "hard_bounce"
	SuppressionTypeSoftBounce   SuppressionType = "soft_bounce"
	SuppressionTypeComplaint    SuppressionType = "complaint"
	SuppressionTypeUnsubscribe  SuppressionType = "unsubscribe"
	SuppressionTypeManual       SuppressionType = "manual"
)

type Suppression struct {
	ID        string
	OrgID     OrganizationID
	Email     string
	Type      SuppressionType
	Reason    string
	Source    string
	CreatedAt time.Time
}
