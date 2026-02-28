package sendingdomain

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.SendingDomain, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.SendingDomainID) (*domain.SendingDomain, error)
	Verify(ctx context.Context, orgID domain.OrganizationID, id domain.SendingDomainID) (*domain.SendingDomain, error)
	Delete(ctx context.Context, orgID domain.OrganizationID, id domain.SendingDomainID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.SendingDomain, int, error)
}

type Repository interface {
	Create(ctx context.Context, sd *domain.SendingDomain) error
	FindByID(ctx context.Context, id domain.SendingDomainID) (*domain.SendingDomain, error)
	Update(ctx context.Context, sd *domain.SendingDomain) error
	SoftDelete(ctx context.Context, id domain.SendingDomainID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.SendingDomain, int, error)
}
