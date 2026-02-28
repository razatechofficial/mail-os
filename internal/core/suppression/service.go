package suppression

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

func (s *service) Add(ctx context.Context, input AddInput) (*domain.Suppression, error) {
	sup := &domain.Suppression{
		ID:        id.New(),
		OrgID:     domain.OrganizationID(input.OrgID),
		Email:     input.Email,
		Type:      input.Type,
		Reason:    input.Reason,
		Source:    input.Source,
		CreatedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, sup); err != nil {
		return nil, fmt.Errorf("suppression.Add: %w", err)
	}
	return sup, nil
}

func (s *service) Remove(ctx context.Context, orgID domain.OrganizationID, email string) error {
	if err := s.repo.Delete(ctx, orgID, email); err != nil {
		return fmt.Errorf("suppression.Remove: %w", err)
	}
	return nil
}

func (s *service) IsSuppressed(ctx context.Context, orgID string, email string) (bool, error) {
	exists, err := s.repo.ExistsByEmail(ctx, domain.OrganizationID(orgID), email)
	if err != nil {
		return false, fmt.Errorf("suppression.IsSuppressed: %w", err)
	}
	return exists, nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Suppression, int, error) {
	list, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("suppression.List: %w", err)
	}
	return list, total, nil
}
