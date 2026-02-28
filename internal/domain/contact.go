package domain

import "time"

type ContactID string

type ContactStatus string

const (
	ContactStatusActive       ContactStatus = "active"
	ContactStatusUnsubscribed ContactStatus = "unsubscribed"
	ContactStatusBounced      ContactStatus = "bounced"
	ContactStatusComplained   ContactStatus = "complained"
)

type Contact struct {
	ID        ContactID
	OrgID     OrganizationID
	Email     string
	FirstName string
	LastName  string
	Metadata  map[string]any
	Status    ContactStatus
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}
