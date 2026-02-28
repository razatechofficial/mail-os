package sendingdomain

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

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.SendingDomain, error) {
	sd := &domain.SendingDomain{
		ID:        domain.SendingDomainID(id.New()),
		OrgID:     domain.OrganizationID(input.OrgID),
		Domain:    input.Domain,
		Status:    domain.DomainStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, sd); err != nil {
		return nil, fmt.Errorf("sendingdomain.Create: %w", err)
	}
	return sd, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.SendingDomainID) (*domain.SendingDomain, error) {
	sd, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("sendingdomain.GetByID: %w", err)
	}
	if sd.OrgID != orgID {
		return nil, fmt.Errorf("sendingdomain.GetByID: %w", errors.ErrNotFound)
	}
	return sd, nil
}

func (s *service) Verify(ctx context.Context, orgID domain.OrganizationID, id domain.SendingDomainID) (*domain.SendingDomain, error) {
	sd, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("sendingdomain.Verify: %w", err)
	}
	if sd.OrgID != orgID {
		return nil, fmt.Errorf("sendingdomain.Verify: %w", errors.ErrNotFound)
	}
	now := time.Now()
	sd.Status = domain.DomainStatusVerified
	sd.VerifiedAt = &now
	sd.UpdatedAt = now
	if err := s.repo.Update(ctx, sd); err != nil {
		return nil, fmt.Errorf("sendingdomain.Verify: %w", err)
	}
	return sd, nil
}

func (s *service) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.SendingDomainID) error {
	sd, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("sendingdomain.Delete: %w", err)
	}
	if sd.OrgID != orgID {
		return fmt.Errorf("sendingdomain.Delete: %w", errors.ErrNotFound)
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("sendingdomain.Delete: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.SendingDomain, int, error) {
	sds, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("sendingdomain.List: %w", err)
	}
	return sds, total, nil
}
