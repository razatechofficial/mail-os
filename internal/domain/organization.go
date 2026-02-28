package domain

import "time"

type OrganizationID string

type Organization struct {
	ID            OrganizationID
	Name          string
	Slug          string
	WebhookURL    string
	WebhookSecret string
	Settings      map[string]any
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}
