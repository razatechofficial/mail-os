package contact

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.Contact, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID) (*domain.Contact, error)
	GetByEmail(ctx context.Context, orgID domain.OrganizationID, email string) (*domain.Contact, error)
	Update(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID, input UpdateInput) (*domain.Contact, error)
	Delete(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Contact, int, error)
	BatchCreate(ctx context.Context, orgID domain.OrganizationID, inputs []CreateInput) (int, error)
	UpdateStatus(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID, status domain.ContactStatus) error
}

type Repository interface {
	Create(ctx context.Context, c *domain.Contact) error
	FindByID(ctx context.Context, id domain.ContactID) (*domain.Contact, error)
	FindByEmail(ctx context.Context, orgID domain.OrganizationID, email string) (*domain.Contact, error)
	Update(ctx context.Context, c *domain.Contact) error
	SoftDelete(ctx context.Context, id domain.ContactID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Contact, int, error)
	BatchCreate(ctx context.Context, contacts []*domain.Contact) (int, error)
	UpdateStatus(ctx context.Context, id domain.ContactID, status domain.ContactStatus) error
}
