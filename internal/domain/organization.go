// Package domain contains pure value types and entity structs that
// represent the mail-service business model. Domain types have no
// infrastructure dependencies.
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
