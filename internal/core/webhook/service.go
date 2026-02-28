package webhook

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
	repo   Repository
	signer port.Signer
}

func NewService(repo Repository, signer port.Signer) Service {
	return &service{repo: repo, signer: signer}
}

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.Webhook, error) {
	w := &domain.Webhook{
		ID:        domain.WebhookID(id.New()),
		OrgID:     domain.OrganizationID(input.OrgID),
		URL:       input.URL,
		Secret:    input.Secret,
		Events:    input.Events,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, w); err != nil {
		return nil, fmt.Errorf("webhook.Create: %w", err)
	}
	return w, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.WebhookID) (*domain.Webhook, error) {
	w, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("webhook.GetByID: %w", err)
	}
	if w.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	return w, nil
}

func (s *service) GetByIDForDelivery(ctx context.Context, id domain.WebhookID) (*domain.Webhook, error) {
	return s.repo.FindByID(ctx, id)
}

func (s *service) Update(ctx context.Context, orgID domain.OrganizationID, id domain.WebhookID, input UpdateInput) (*domain.Webhook, error) {
	w, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("webhook.Update: %w", err)
	}
	if w.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	if input.URL != nil {
		w.URL = *input.URL
	}
	if input.Secret != nil {
		w.Secret = *input.Secret
	}
	if input.Events != nil {
		w.Events = *input.Events
	}
	if input.IsActive != nil {
		w.IsActive = *input.IsActive
	}
	w.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, w); err != nil {
		return nil, fmt.Errorf("webhook.Update: %w", err)
	}
	return w, nil
}

func (s *service) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.WebhookID) error {
	w, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("webhook.Delete: %w", err)
	}
	if w.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("webhook.Delete: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Webhook, int, error) {
	list, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("webhook.List: %w", err)
	}
	return list, total, nil
}

func (s *service) ListActiveByOrg(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Webhook, error) {
	list, err := s.repo.FindActiveByOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("webhook.ListActiveByOrg: %w", err)
	}
	return list, nil
}

func (s *service) CreateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) error {
	if err := s.repo.CreateDelivery(ctx, delivery); err != nil {
		return fmt.Errorf("webhook.CreateDelivery: %w", err)
	}
	return nil
}

func (s *service) UpdateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) error {
	if err := s.repo.UpdateDelivery(ctx, delivery); err != nil {
		return fmt.Errorf("webhook.UpdateDelivery: %w", err)
	}
	return nil
}

func (s *service) ListPendingDeliveries(ctx context.Context, limit int) ([]*domain.WebhookDelivery, error) {
	list, err := s.repo.FindPendingDeliveries(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("webhook.ListPendingDeliveries: %w", err)
	}
	return list, nil
}
