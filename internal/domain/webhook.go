package domain

import "time"

type WebhookID string

type Webhook struct {
	ID        WebhookID
	OrgID     OrganizationID
	URL       string
	Secret    string
	Events    []string
	IsActive  bool
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type DeliveryStatus string

const (
	DeliveryStatusPending DeliveryStatus = "pending"
	DeliveryStatusSuccess DeliveryStatus = "success"
	DeliveryStatusFailed  DeliveryStatus = "failed"
)

type WebhookDelivery struct {
	ID          string
	WebhookID   WebhookID
	EventType   string
	Payload     string
	Status      DeliveryStatus
	StatusCode  int
	Attempts    int
	LastError   string
	NextRetryAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
