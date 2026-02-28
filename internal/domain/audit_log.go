package domain

import "time"

type ActorType string

const (
	ActorTypeAPIKey ActorType = "api_key"
	ActorTypeSystem ActorType = "system"
	ActorTypeAdmin  ActorType = "admin"
)

type AuditLog struct {
	ID         string
	OrgID      OrganizationID
	ActorType  ActorType
	ActorID    string
	Action     string
	Resource   string
	ResourceID string
	Changes    map[string]any
	IPAddress  string
	UserAgent  string
	CreatedAt  time.Time
}
