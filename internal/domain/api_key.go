package domain

import "time"

type APIKeyID string

type APIKey struct {
	ID         APIKeyID
	OrgID      OrganizationID
	Name       string
	KeyHash    string
	Prefix     string
	Scopes     []string
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	IsActive   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time
}
