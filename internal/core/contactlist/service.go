package contactlist

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

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.ContactList, error) {
	cl := &domain.ContactList{
		ID:          domain.ContactListID(id.New()),
		OrgID:       domain.OrganizationID(input.OrgID),
		Name:        input.Name,
		Description: input.Description,
		Type:        input.Type,
		Query:       input.Query,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := s.repo.Create(ctx, cl); err != nil {
		return nil, fmt.Errorf("contactlist.Create: %w", err)
	}
	return cl, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.ContactListID) (*domain.ContactList, error) {
	cl, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("contactlist.GetByID: %w", err)
	}
	if cl.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	return cl, nil
}

func (s *service) Update(ctx context.Context, orgID domain.OrganizationID, id domain.ContactListID, input UpdateInput) (*domain.ContactList, error) {
	cl, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("contactlist.Update: %w", err)
	}
	if cl.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	if input.Name != nil {
		cl.Name = *input.Name
	}
	if input.Description != nil {
		cl.Description = *input.Description
	}
	if input.Type != nil {
		cl.Type = *input.Type
	}
	if input.Query != nil {
		cl.Query = *input.Query
	}
	cl.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, cl); err != nil {
		return nil, fmt.Errorf("contactlist.Update: %w", err)
	}
	return cl, nil
}

func (s *service) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.ContactListID) error {
	cl, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("contactlist.Delete: %w", err)
	}
	if cl.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("contactlist.Delete: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.ContactList, int, error) {
	lists, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("contactlist.List: %w", err)
	}
	return lists, total, nil
}

func (s *service) AddMembers(ctx context.Context, orgID domain.OrganizationID, listID domain.ContactListID, contactIDs []domain.ContactID) error {
	cl, err := s.repo.FindByID(ctx, listID)
	if err != nil {
		return fmt.Errorf("contactlist.AddMembers: %w", err)
	}
	if cl.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.AddMembers(ctx, listID, contactIDs); err != nil {
		return fmt.Errorf("contactlist.AddMembers: %w", err)
	}
	return nil
}

func (s *service) RemoveMembers(ctx context.Context, orgID domain.OrganizationID, listID domain.ContactListID, contactIDs []domain.ContactID) error {
	cl, err := s.repo.FindByID(ctx, listID)
	if err != nil {
		return fmt.Errorf("contactlist.RemoveMembers: %w", err)
	}
	if cl.OrgID != orgID {
		return errors.ErrNotFound
	}
	if err := s.repo.RemoveMembers(ctx, listID, contactIDs); err != nil {
		return fmt.Errorf("contactlist.RemoveMembers: %w", err)
	}
	return nil
}

func (s *service) ListMembers(ctx context.Context, listID domain.ContactListID, params ListParams) ([]*domain.Contact, int, error) {
	contacts, total, err := s.repo.FindMembers(ctx, listID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("contactlist.ListMembers: %w", err)
	}
	return contacts, total, nil
}
