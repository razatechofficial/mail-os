package webhook

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.Webhook, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.WebhookID) (*domain.Webhook, error)
	GetByIDForDelivery(ctx context.Context, id domain.WebhookID) (*domain.Webhook, error)
	Update(ctx context.Context, orgID domain.OrganizationID, id domain.WebhookID, input UpdateInput) (*domain.Webhook, error)
	Delete(ctx context.Context, orgID domain.OrganizationID, id domain.WebhookID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Webhook, int, error)
	ListActiveByOrg(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Webhook, error)
	CreateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) error
	UpdateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) error
	ListPendingDeliveries(ctx context.Context, limit int) ([]*domain.WebhookDelivery, error)
}

type Repository interface {
	Create(ctx context.Context, w *domain.Webhook) error
	FindByID(ctx context.Context, id domain.WebhookID) (*domain.Webhook, error)
	Update(ctx context.Context, w *domain.Webhook) error
	SoftDelete(ctx context.Context, id domain.WebhookID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Webhook, int, error)
	FindActiveByOrg(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Webhook, error)
	CreateDelivery(ctx context.Context, d *domain.WebhookDelivery) error
	UpdateDelivery(ctx context.Context, d *domain.WebhookDelivery) error
	FindPendingDeliveries(ctx context.Context, limit int) ([]*domain.WebhookDelivery, error)
}
