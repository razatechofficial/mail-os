package domain

import "time"

type TemplateID string

type TemplateCategory string

const (
	TemplateCategoryTransactional TemplateCategory = "transactional"
	TemplateCategoryMarketing     TemplateCategory = "marketing"
	TemplateCategoryNotification  TemplateCategory = "notification"
)

type Template struct {
	ID          TemplateID
	OrgID       OrganizationID
	Name        string
	Slug        string
	Category    TemplateCategory
	Description string
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}
