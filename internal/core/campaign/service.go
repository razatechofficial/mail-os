package campaign

import (
	"context"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

type service struct {
	repo           Repository
	publisher      port.Publisher
	messageEnqueuer port.MessageEnqueuer
}

func NewService(repo Repository, publisher port.Publisher) Service {
	return &service{repo: repo, publisher: publisher}
}

func (s *service) SetMessageEnqueuer(e port.MessageEnqueuer) {
	s.messageEnqueuer = e
}

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.Campaign, error) {
	c := &domain.Campaign{
		ID:             domain.CampaignID(id.New()),
		OrgID:          domain.OrganizationID(input.OrgID),
		Name:           input.Name,
		Subject:        input.Subject,
		FromName:       input.FromName,
		FromEmail:      input.FromEmail,
		TemplateID:     domain.TemplateID(input.TemplateID),
		ContactListID:  domain.ContactListID(input.ContactListID),
		Type:           input.Type,
		Status:         domain.CampaignStatusDraft,
		ScheduledAt:    input.ScheduledAt,
		TotalRecipients: 0,
		SentCount:      0,
		FailedCount:    0,
		Metadata:       input.Metadata,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("campaign.Create: %w", err)
	}
	return c, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) (*domain.Campaign, error) {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("campaign.GetByID: %w", err)
	}
	if c.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	return c, nil
}

func (s *service) Update(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID, input UpdateInput) (*domain.Campaign, error) {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("campaign.Update: %w", err)
	}
	if c.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	if input.Name != nil {
		c.Name = *input.Name
	}
	if input.Subject != nil {
		c.Subject = *input.Subject
	}
	if input.FromName != nil {
		c.FromName = *input.FromName
	}
	if input.FromEmail != nil {
		c.FromEmail = *input.FromEmail
	}
	if input.TemplateID != nil {
		c.TemplateID = domain.TemplateID(*input.TemplateID)
	}
	if input.ContactListID != nil {
		c.ContactListID = domain.ContactListID(*input.ContactListID)
	}
	if input.Type != nil {
		c.Type = *input.Type
	}
	if input.ScheduledAt != nil {
		c.ScheduledAt = input.ScheduledAt
	}
	if input.Metadata != nil {
		c.Metadata = *input.Metadata
	}
	c.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, c); err != nil {
		return nil, fmt.Errorf("campaign.Update: %w", err)
	}
	return c, nil
}

func (s *service) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("campaign.Delete: %w", err)
	}
	if c.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("campaign.Delete: %w", err)
	}
	return nil
}

func (s *service) ListScheduledDue(ctx context.Context, limit int) ([]*domain.Campaign, error) {
	return s.repo.FindScheduledDue(ctx, limit)
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Campaign, int, error) {
	campaigns, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("campaign.List: %w", err)
	}
	return campaigns, total, nil
}

func (s *service) Launch(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("campaign.Launch: %w", err)
	}
	if c.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.UpdateStatus(ctx, id, domain.CampaignStatusSending); err != nil {
		return fmt.Errorf("campaign.Launch: %w", err)
	}
	return nil
}

func (s *service) Pause(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("campaign.Pause: %w", err)
	}
	if c.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.UpdateStatus(ctx, id, domain.CampaignStatusPaused); err != nil {
		return fmt.Errorf("campaign.Pause: %w", err)
	}
	return nil
}

func (s *service) Resume(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("campaign.Resume: %w", err)
	}
	if c.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.UpdateStatus(ctx, id, domain.CampaignStatusSending); err != nil {
		return fmt.Errorf("campaign.Resume: %w", err)
	}
	return nil
}

func (s *service) Cancel(ctx context.Context, orgID domain.OrganizationID, id domain.CampaignID) error {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("campaign.Cancel: %w", err)
	}
	if c.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.UpdateStatus(ctx, id, domain.CampaignStatusCancelled); err != nil {
		return fmt.Errorf("campaign.Cancel: %w", err)
	}
	return nil
}
