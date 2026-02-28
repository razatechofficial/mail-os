package handler

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/core/template"
	"github.com/razatechofficial/mail-os/internal/domain"
)

// TemplateService wraps template.Service for gRPC. Stub implementations will be
// connected to generated proto code when available.
type TemplateService struct {
	svc template.Service
}

func NewTemplateService(svc template.Service) *TemplateService {
	return &TemplateService{svc: svc}
}

// Create will be connected to generated proto when available.
func (h *TemplateService) Create(ctx context.Context, orgID domain.OrganizationID, req any) (any, error) {
	_ = orgID
	_ = req
	// Stub: to be wired to template.Service.Create via proto-generated types
	return nil, nil
}

// GetByID will be connected to generated proto when available.
func (h *TemplateService) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID) (any, error) {
	_, err := h.svc.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}

// GetBySlug will be connected to generated proto when available.
func (h *TemplateService) GetBySlug(ctx context.Context, orgID domain.OrganizationID, slug string) (any, error) {
	_, err := h.svc.GetBySlug(ctx, orgID, slug)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}

// Update will be connected to generated proto when available.
func (h *TemplateService) Update(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID, req any) (any, error) {
	_ = req
	// Stub: to be wired to template.Service.Update via proto-generated types
	_ = id
	return nil, nil
}

// Delete will be connected to generated proto when available.
func (h *TemplateService) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.TemplateID) error {
	return h.svc.Delete(ctx, orgID, id)
}

// List will be connected to generated proto when available.
func (h *TemplateService) List(ctx context.Context, orgID domain.OrganizationID, params template.ListParams) (any, error) {
	_, _, err := h.svc.List(ctx, orgID, params)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}
