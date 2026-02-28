package handler

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/core/contact"
	"github.com/razatechofficial/mail-os/internal/domain"
)

// ContactService wraps contact.Service for gRPC. Stub implementations will be
// connected to generated proto code when available.
type ContactService struct {
	svc contact.Service
}

func NewContactService(svc contact.Service) *ContactService {
	return &ContactService{svc: svc}
}

// Create will be connected to generated proto when available.
func (h *ContactService) Create(ctx context.Context, orgID domain.OrganizationID, req any) (any, error) {
	_ = orgID
	_ = req
	// Stub: to be wired to contact.Service.Create via proto-generated types
	return nil, nil
}

// GetByID will be connected to generated proto when available.
func (h *ContactService) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID) (any, error) {
	_, err := h.svc.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}

// GetByEmail will be connected to generated proto when available.
func (h *ContactService) GetByEmail(ctx context.Context, orgID domain.OrganizationID, email string) (any, error) {
	_, err := h.svc.GetByEmail(ctx, orgID, email)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}

// Update will be connected to generated proto when available.
func (h *ContactService) Update(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID, req any) (any, error) {
	_ = req
	// Stub: to be wired to contact.Service.Update via proto-generated types
	_ = id
	return nil, nil
}

// Delete will be connected to generated proto when available.
func (h *ContactService) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.ContactID) error {
	return h.svc.Delete(ctx, orgID, id)
}

// List will be connected to generated proto when available.
func (h *ContactService) List(ctx context.Context, orgID domain.OrganizationID, params contact.ListParams) (any, error) {
	_, _, err := h.svc.List(ctx, orgID, params)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}
