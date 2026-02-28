package domain

import "time"

type ContactListID string

type ListType string

const (
	ListTypeStatic  ListType = "static"
	ListTypeDynamic ListType = "dynamic"
)

type ContactList struct {
	ID          ContactListID
	OrgID       OrganizationID
	Name        string
	Description string
	Type        ListType
	Query       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

type ListMember struct {
	ContactListID ContactListID
	ContactID     ContactID
	AddedAt       time.Time
}
