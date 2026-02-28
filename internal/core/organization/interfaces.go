package organization

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.Organization, error)
	GetByID(ctx context.Context, id domain.OrganizationID) (*domain.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	Update(ctx context.Context, id domain.OrganizationID, input UpdateInput) (*domain.Organization, error)
	Delete(ctx context.Context, id domain.OrganizationID) error
	List(ctx context.Context, params ListParams) ([]*domain.Organization, int, error)
	CheckQuota(ctx context.Context, orgID string) error
}

type Repository interface {
	Create(ctx context.Context, org *domain.Organization) error
	FindByID(ctx context.Context, id domain.OrganizationID) (*domain.Organization, error)
	FindBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	Update(ctx context.Context, org *domain.Organization) error
	SoftDelete(ctx context.Context, id domain.OrganizationID) error
	FindAll(ctx context.Context, params ListParams) ([]*domain.Organization, int, error)
}
