package template

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.Template, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID) (*domain.Template, error)
	GetBySlug(ctx context.Context, orgID domain.OrganizationID, slug string) (*domain.Template, error)
	Update(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID, input UpdateInput) (*domain.Template, error)
	Delete(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Template, int, error)
	CreateVersion(ctx context.Context, input CreateVersionInput) (*domain.TemplateVersion, error)
	GetActiveVersion(ctx context.Context, templateID domain.TemplateID) (*domain.TemplateVersion, error)
	ListVersions(ctx context.Context, templateID domain.TemplateID) ([]*domain.TemplateVersion, error)
}

type Repository interface {
	Create(ctx context.Context, t *domain.Template) error
	FindByID(ctx context.Context, id domain.TemplateID) (*domain.Template, error)
	FindBySlug(ctx context.Context, orgID domain.OrganizationID, slug string) (*domain.Template, error)
	Update(ctx context.Context, t *domain.Template) error
	SoftDelete(ctx context.Context, id domain.TemplateID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Template, int, error)
	CreateVersion(ctx context.Context, v *domain.TemplateVersion) error
	FindActiveVersion(ctx context.Context, templateID domain.TemplateID) (*domain.TemplateVersion, error)
	FindVersions(ctx context.Context, templateID domain.TemplateID) ([]*domain.TemplateVersion, error)
	FindLatestVersionNumber(ctx context.Context, templateID domain.TemplateID) (int, error)
}
