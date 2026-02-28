package template

import (
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type CreateInput struct {
	OrgID       string
	Name        string
	Slug        string
	Description string
	Category    domain.TemplateCategory
}

type UpdateInput struct {
	Name        *string
	Slug        *string
	Description *string
	Category    *domain.TemplateCategory
	IsActive    *bool
}

type CreateVersionInput struct {
	TemplateID string
	Subject    string
	HTMLBody   string
	TextBody   string
	Variables  []string
}

type ListParams struct {
	pagination.Params
}
