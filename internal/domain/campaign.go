package domain

import "time"

type CampaignID string

type CampaignStatus string

const (
	CampaignStatusDraft      CampaignStatus = "draft"
	CampaignStatusScheduled  CampaignStatus = "scheduled"
	CampaignStatusSending    CampaignStatus = "sending"
	CampaignStatusPaused     CampaignStatus = "paused"
	CampaignStatusCompleted  CampaignStatus = "completed"
	CampaignStatusCancelled  CampaignStatus = "cancelled"
)

type CampaignType string

const (
	CampaignTypeRegular   CampaignType = "regular"
	CampaignTypeABTest    CampaignType = "ab_test"
	CampaignTypeAutomated CampaignType = "automated"
)

type Campaign struct {
	ID               CampaignID
	OrgID            OrganizationID
	Name             string
	Subject          string
	FromName         string
	FromEmail        string
	TemplateID       TemplateID
	ContactListID    ContactListID
	Type             CampaignType
	Status           CampaignStatus
	ScheduledAt      *time.Time
	StartedAt        *time.Time
	CompletedAt      *time.Time
	TotalRecipients  int
	SentCount        int
	FailedCount      int
	Metadata         map[string]any
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        *time.Time
}

type CampaignRecipient struct {
	CampaignID CampaignID
	ContactID  ContactID
	Status     string
	SentAt     *time.Time
	Error      string
}
