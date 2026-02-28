package domain

import "time"

type EventType string

const (
	EventTypeQueued       EventType = "queued"
	EventTypeSent         EventType = "sent"
	EventTypeDelivered    EventType = "delivered"
	EventTypeOpened       EventType = "opened"
	EventTypeClicked      EventType = "clicked"
	EventTypeBounced      EventType = "bounced"
	EventTypeComplained   EventType = "complained"
	EventTypeUnsubscribed EventType = "unsubscribed"
)

type MessageEvent struct {
	ID        string
	MessageID MessageID
	OrgID     OrganizationID
	Type      EventType
	Provider  string
	Metadata  map[string]any
	CreatedAt time.Time
}
