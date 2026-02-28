package contact

import (
	"context"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

type service struct {
	repo Repository
}

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.Contact, error) {
	c := &domain.Contact{
		ID:        domain.ContactID(id.New()),
		OrgID:     domain.OrganizationID(input.OrgID),
		Email:     input.Email,
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Metadata:  input.Metadata,
		Status:    domain.ContactStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("contact.Create: %w", err)
	}
	return c, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID) (*domain.Contact, error) {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("contact.GetByID: %w", err)
	}
	if c.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	return c, nil
}

func (s *service) GetByEmail(ctx context.Context, orgID domain.OrganizationID, email string) (*domain.Contact, error) {
	c, err := s.repo.FindByEmail(ctx, orgID, email)
	if err != nil {
		return nil, fmt.Errorf("contact.GetByEmail: %w", err)
	}
	return c, nil
}

func (s *service) Update(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID, input UpdateInput) (*domain.Contact, error) {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("contact.Update: %w", err)
	}
	if c.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	if input.Email != nil {
		c.Email = *input.Email
	}
	if input.FirstName != nil {
		c.FirstName = *input.FirstName
	}
	if input.LastName != nil {
		c.LastName = *input.LastName
	}
	if input.Metadata != nil {
		c.Metadata = *input.Metadata
	}
	c.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, c); err != nil {
		return nil, fmt.Errorf("contact.Update: %w", err)
	}
	return c, nil
}

func (s *service) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID) error {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("contact.Delete: %w", err)
	}
	if c.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("contact.Delete: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Contact, int, error) {
	contacts, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("contact.List: %w", err)
	}
	return contacts, total, nil
}

func (s *service) BatchCreate(ctx context.Context, orgID domain.OrganizationID, inputs []CreateInput) (int, error) {
	contacts := make([]*domain.Contact, len(inputs))
	now := time.Now()
	for i, input := range inputs {
		contacts[i] = &domain.Contact{
			ID:        domain.ContactID(id.New()),
			OrgID:     domain.OrganizationID(orgID),
			Email:     input.Email,
			FirstName: input.FirstName,
			LastName:  input.LastName,
			Metadata:  input.Metadata,
			Status:    domain.ContactStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}
	count, err := s.repo.BatchCreate(ctx, contacts)
	if err != nil {
		return 0, fmt.Errorf("contact.BatchCreate: %w", err)
	}
	return count, nil
}

func (s *service) UpdateStatus(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID, status domain.ContactStatus) error {
	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("contact.UpdateStatus: %w", err)
	}
	if c.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.UpdateStatus(ctx, id, status); err != nil {
		return fmt.Errorf("contact.UpdateStatus: %w", err)
	}
	return nil
}
