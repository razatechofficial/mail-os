package domain

import "time"

type MessageID string

type MessageStatus string

const (
	MessageStatusQueued    MessageStatus = "queued"
	MessageStatusSending   MessageStatus = "sending"
	MessageStatusSent      MessageStatus = "sent"
	MessageStatusDelivered MessageStatus = "delivered"
	MessageStatusFailed    MessageStatus = "failed"
	MessageStatusBounced   MessageStatus = "bounced"
	MessageStatusRejected  MessageStatus = "rejected"
	MessageStatusScheduled MessageStatus = "scheduled"
)

type MessageType string

const (
	MessageTypeTransactional MessageType = "transactional"
	MessageTypeCampaign      MessageType = "campaign"
	MessageTypeNotification  MessageType = "notification"
)

type MessagePriority int

const (
	MessagePriorityLow    MessagePriority = 1
	MessagePriorityNormal MessagePriority = 5
	MessagePriorityHigh   MessagePriority = 10
)

type Message struct {
	ID             MessageID
	OrgID          OrganizationID
	CampaignID     CampaignID
	ProviderID     ProviderID
	FromName       string
	FromEmail      string
	ToEmail        string
	ToName         string
	Subject        string
	HTMLBody       string
	TextBody       string
	Type           MessageType
	Status         MessageStatus
	Priority       MessagePriority
	Tags           []string
	Metadata       map[string]any
	IdempotencyKey string
	ProviderMsgID  string
	Attempts       int
	LastAttemptAt  *time.Time
	SentAt         *time.Time
	DeliveredAt    *time.Time
	OpenedAt       *time.Time
	ClickedAt      *time.Time
	BouncedAt      *time.Time
	ScheduledAt    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
