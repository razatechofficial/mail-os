// Package handler holds the gRPC service implementations. Each delegates to
// an application use case and maps its errors with grpctransport.Status.
package handler

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/razatechofficial/mail-os/api/proto/v1"
	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/event"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
)

// EventHandler serves MailService.DispatchEvent: a service publishing an
// event with its service token in the authorization metadata. The request
// carries no event id or tenant: MailOS assigns the id, and the tenant is
// the token's (or the client's configured one).
type EventHandler struct {
	svc *inbound.Service
}

// NewEventHandler builds the handler; the MailService server delegates
// DispatchEvent to it.
func NewEventHandler(svc *inbound.Service) *EventHandler { return &EventHandler{svc: svc} }

// DispatchEvent accepts one event. Invalid data is InvalidArgument, a
// refused sender or tenant PermissionDenied (audited).
func (h *EventHandler) DispatchEvent(ctx context.Context, req *v1.DispatchEventRequest) (*v1.DispatchEventResponse, error) {
	data := req.GetData()
	if len(data) > event.MaxSize {
		return nil, status.Error(codes.InvalidArgument, "the event data is over 256 KiB")
	}
	if !json.Valid(data) {
		return nil, status.Error(codes.InvalidArgument, "data must be a JSON object")
	}
	ev := event.Event{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Type:      req.GetType(),
		Source:    req.GetSource(),
		Data:      json.RawMessage(data),
		Timestamp: time.Now().UTC(),
	}
	res, err := h.svc.Dispatch(ctx, inbound.In{Transport: inbound.TransportGRPC, Event: ev})
	if err != nil {
		return nil, grpctransport.Status(err)
	}
	return &v1.DispatchEventResponse{Accepted: res.Accepted, DeliveryId: res.DeliveryID}, nil
}
