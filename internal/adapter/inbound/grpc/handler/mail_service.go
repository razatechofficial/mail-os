package handler

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/core/message"
	"github.com/razatechofficial/mail-os/internal/domain"
)

// MailService wraps message.Service for gRPC. Stub implementations will be
// connected to generated proto code when available.
type MailService struct {
	svc message.Service
}

func NewMailService(svc message.Service) *MailService {
	return &MailService{svc: svc}
}

// Send will be connected to generated proto when available.
func (h *MailService) Send(ctx context.Context, orgID string, req any) (any, error) {
	_ = orgID
	_ = req
	// Stub: to be wired to message.Service.Send via proto-generated types
	return nil, nil
}

// BatchSend will be connected to generated proto when available.
func (h *MailService) BatchSend(ctx context.Context, orgID string, req any) (any, error) {
	_ = orgID
	_ = req
	// Stub: to be wired to message.Service.BatchSend via proto-generated types
	return nil, nil
}

// Schedule will be connected to generated proto when available.
func (h *MailService) Schedule(ctx context.Context, orgID string, req any) (any, error) {
	_ = orgID
	_ = req
	// Stub: to be wired to message.Service.Schedule via proto-generated types
	return nil, nil
}

// GetByID will be connected to generated proto when available.
func (h *MailService) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.MessageID) (any, error) {
	_, err := h.svc.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}

// List will be connected to generated proto when available.
func (h *MailService) List(ctx context.Context, params message.MessageListParams) (any, error) {
	_, _, err := h.svc.List(ctx, params)
	if err != nil {
		return nil, err
	}
	// Stub: to be wired to proto-generated response
	return nil, nil
}
