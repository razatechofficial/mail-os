package template

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
	repo      Repository
	renderer  port.TemplateRenderer
	cache     port.Cache
	publisher port.EventPublisher
}

type Option func(*service)

func WithCache(c port.Cache) Option {
	return func(s *service) { s.cache = c }
}

func WithEventPublisher(p port.EventPublisher) Option {
	return func(s *service) { s.publisher = p }
}

func NewService(repo Repository, renderer port.TemplateRenderer, opts ...Option) Service {
	s := &service{repo: repo, renderer: renderer}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.Template, error) {
	t := &domain.Template{
		ID:          domain.TemplateID(id.New()),
		OrgID:       domain.OrganizationID(input.OrgID),
		Name:        input.Name,
		Slug:        input.Slug,
		Category:    input.Category,
		Description: input.Description,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, fmt.Errorf("template.Create: %w", err)
	}
	return t, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID) (*domain.Template, error) {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("template.GetByID: %w", err)
	}
	if t.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	return t, nil
}

func (s *service) GetBySlug(ctx context.Context, orgID domain.OrganizationID, slug string) (*domain.Template, error) {
	t, err := s.repo.FindBySlug(ctx, orgID, slug)
	if err != nil {
		return nil, fmt.Errorf("template.GetBySlug: %w", err)
	}
	return t, nil
}

func (s *service) Update(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID, input UpdateInput) (*domain.Template, error) {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("template.Update: %w", err)
	}
	if t.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	if input.Name != nil {
		t.Name = *input.Name
	}
	if input.Slug != nil {
		t.Slug = *input.Slug
	}
	if input.Description != nil {
		t.Description = *input.Description
	}
	if input.Category != nil {
		t.Category = *input.Category
	}
	if input.IsActive != nil {
		t.IsActive = *input.IsActive
	}
	t.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("template.Update: %w", err)
	}
	return t, nil
}

func (s *service) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID) error {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("template.Delete: %w", err)
	}
	if t.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("template.Delete: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Template, int, error) {
	templates, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("template.List: %w", err)
	}
	return templates, total, nil
}

func (s *service) CreateVersion(ctx context.Context, input CreateVersionInput) (*domain.TemplateVersion, error) {
	version, err := s.repo.FindLatestVersionNumber(ctx, domain.TemplateID(input.TemplateID))
	if err != nil {
		return nil, fmt.Errorf("template.CreateVersion: %w", err)
	}
	version++
	v := &domain.TemplateVersion{
		ID:         domain.TemplateVersionID(id.New()),
		TemplateID: domain.TemplateID(input.TemplateID),
		Version:    version,
		Subject:    input.Subject,
		HTMLBody:   input.HTMLBody,
		TextBody:   input.TextBody,
		Variables:  input.Variables,
		IsActive:   true,
		CreatedAt:  time.Now(),
	}
	if err := s.repo.CreateVersion(ctx, v); err != nil {
		return nil, fmt.Errorf("template.CreateVersion: %w", err)
	}
	return v, nil
}

func (s *service) GetActiveVersion(ctx context.Context, templateID domain.TemplateID) (*domain.TemplateVersion, error) {
	v, err := s.repo.FindActiveVersion(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("template.GetActiveVersion: %w", err)
	}
	return v, nil
}

func (s *service) ListVersions(ctx context.Context, templateID domain.TemplateID) ([]*domain.TemplateVersion, error) {
	versions, err := s.repo.FindVersions(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("template.ListVersions: %w", err)
	}
	return versions, nil
}
