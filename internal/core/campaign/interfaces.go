package campaign

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/port"
)

type Service interface {
	Create(ctx context.Context, input CreateInput) (*domain.Campaign, error)
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) (*domain.Campaign, error)
	Update(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID, input UpdateInput) (*domain.Campaign, error)
	Delete(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error
	List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Campaign, int, error)
	Launch(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error
	Pause(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error
	Resume(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error
	Cancel(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error
}

type MessageEnqueuerSetter interface {
	SetMessageEnqueuer(port.MessageEnqueuer)
}

type Repository interface {
	Create(ctx context.Context, c *domain.Campaign) error
	FindByID(ctx context.Context, id domain.CampaignID) (*domain.Campaign, error)
	Update(ctx context.Context, c *domain.Campaign) error
	SoftDelete(ctx context.Context, id domain.CampaignID) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Campaign, int, error)
	UpdateStatus(ctx context.Context, id domain.CampaignID, status domain.CampaignStatus) error
	UpdateCounts(ctx context.Context, id domain.CampaignID, sent, failed int) error
}
