package domain

import "time"

type ProviderID string

type ProviderType string

const (
	ProviderTypeSMTP     ProviderType = "smtp"
	ProviderTypeSES      ProviderType = "ses"
	ProviderTypeSendGrid ProviderType = "sendgrid"
	ProviderTypeMailgun  ProviderType = "mailgun"
	ProviderTypePostmark ProviderType = "postmark"
)

type Provider struct {
	ID            ProviderID
	OrgID         OrganizationID
	Name          string
	Type          ProviderType
	Configuration map[string]any
	Priority      int
	Weight        int
	DailyLimit    int
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}
