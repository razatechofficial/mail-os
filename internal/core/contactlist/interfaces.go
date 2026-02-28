package contactlist

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.ContactList, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.ContactListID) (*domain.ContactList, error)
	Update(ctx context.Context, orgID domain.OrganizationID, id domain.ContactListID, input UpdateInput) (*domain.ContactList, error)
	Delete(ctx context.Context, orgID domain.OrganizationID, id domain.ContactListID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.ContactList, int, error)
	AddMembers(ctx context.Context, orgID domain.OrganizationID, listID domain.ContactListID, contactIDs []domain.ContactID) error
	RemoveMembers(ctx context.Context, orgID domain.OrganizationID, listID domain.ContactListID, contactIDs []domain.ContactID) error
	ListMembers(ctx context.Context, listID domain.ContactListID, params ListParams) ([]*domain.Contact, int, error)
}

type Repository interface {
	Create(ctx context.Context, cl *domain.ContactList) error
	FindByID(ctx context.Context, id domain.ContactListID) (*domain.ContactList, error)
	Update(ctx context.Context, cl *domain.ContactList) error
	SoftDelete(ctx context.Context, id domain.ContactListID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.ContactList, int, error)
	AddMembers(ctx context.Context, listID domain.ContactListID, contactIDs []domain.ContactID) error
	RemoveMembers(ctx context.Context, listID domain.ContactListID, contactIDs []domain.ContactID) error
	FindMembers(ctx context.Context, listID domain.ContactListID, params ListParams) ([]*domain.Contact, int, error)
}
