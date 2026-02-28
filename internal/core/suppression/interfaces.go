package suppression

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Add(ctx context.Context, input AddInput) (*domain.Suppression, error)
	Remove(ctx context.Context, orgID domain.OrganizationID, email string) error
	IsSuppressed(ctx context.Context, orgID string, email string) (bool, error)
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Suppression, int, error)
}

type Repository interface {
	Create(ctx context.Context, s *domain.Suppression) error
	Delete(ctx context.Context, orgID domain.OrganizationID, email string) error
	ExistsByEmail(ctx context.Context, orgID domain.OrganizationID, email string) (bool, error)
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Suppression, int, error)
}
