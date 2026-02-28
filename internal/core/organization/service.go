package organization

import (
	"context"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/id"
)

type service struct {
	repo Repository
}

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.Organization, error) {
	org := &domain.Organization{
		ID:            domain.OrganizationID(id.New()),
		Name:          input.Name,
		Slug:          input.Slug,
		WebhookURL:    input.WebhookURL,
		WebhookSecret: input.WebhookSecret,
		Settings:      input.Settings,
		IsActive:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := s.repo.Create(ctx, org); err != nil {
		return nil, fmt.Errorf("organization.Create: %w", err)
	}
	return org, nil
}

func (s *service) GetByID(ctx context.Context, id domain.OrganizationID) (*domain.Organization, error) {
	org, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("organization.GetByID: %w", err)
	}
	return org, nil
}

func (s *service) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	org, err := s.repo.FindBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("organization.GetBySlug: %w", err)
	}
	return org, nil
}

func (s *service) Update(ctx context.Context, id domain.OrganizationID, input UpdateInput) (*domain.Organization, error) {
	org, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("organization.Update: %w", err)
	}
	if input.Name != nil {
		org.Name = *input.Name
	}
	if input.WebhookURL != nil {
		org.WebhookURL = *input.WebhookURL
	}
	if input.WebhookSecret != nil {
		org.WebhookSecret = *input.WebhookSecret
	}
	if input.Settings != nil {
		org.Settings = input.Settings
	}
	if input.IsActive != nil {
		org.IsActive = *input.IsActive
	}
	org.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, org); err != nil {
		return nil, fmt.Errorf("organization.Update: %w", err)
	}
	return org, nil
}

func (s *service) Delete(ctx context.Context, id domain.OrganizationID) error {
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("organization.Delete: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, params ListParams) ([]*domain.Organization, int, error) {
	orgs, total, err := s.repo.FindAll(ctx, params)
	if err != nil {
		return nil, 0, fmt.Errorf("organization.List: %w", err)
	}
	return orgs, total, nil
}

func (s *service) CheckQuota(ctx context.Context, orgID string) error {
	return nil
}
