package apikey

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.APIKey, string, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.APIKeyID) (*domain.APIKey, error)
	ValidateKey(ctx context.Context, plaintext string) (*domain.APIKey, error)
	Revoke(ctx context.Context, orgID domain.OrganizationID, id domain.APIKeyID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.APIKey, int, error)
}

type Repository interface {
	Create(ctx context.Context, key *domain.APIKey) error
	FindByID(ctx context.Context, id domain.APIKeyID) (*domain.APIKey, error)
	FindByPrefix(ctx context.Context, prefix string) ([]*domain.APIKey, error)
	Update(ctx context.Context, key *domain.APIKey) error
	SoftDelete(ctx context.Context, id domain.APIKeyID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.APIKey, int, error)
}
