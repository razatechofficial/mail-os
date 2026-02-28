package domain

import "time"

type TemplateVersionID string

type TemplateVersion struct {
	ID         TemplateVersionID
	TemplateID TemplateID
	Version    int
	Subject    string
	HTMLBody   string
	TextBody   string
	Variables  []string
	IsActive   bool
	CreatedAt  time.Time
}
