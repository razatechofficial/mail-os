package provider

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.Provider, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.ProviderID) (*domain.Provider, error)
	Update(ctx context.Context, orgID domain.OrganizationID, id domain.ProviderID, input UpdateInput) (*domain.Provider, error)
	Delete(ctx context.Context, orgID domain.OrganizationID, id domain.ProviderID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Provider, int, error)
	ListActive(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Provider, error)
}

type Repository interface {
	Create(ctx context.Context, p *domain.Provider) error
	FindByID(ctx context.Context, id domain.ProviderID) (*domain.Provider, error)
	Update(ctx context.Context, p *domain.Provider) error
	SoftDelete(ctx context.Context, id domain.ProviderID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Provider, int, error)
	FindActive(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Provider, error)
}
