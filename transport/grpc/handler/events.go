// Package handler holds the gRPC service implementations. Each delegates to
// an application use case and maps its errors with grpctransport.Status.
package handler

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	v1 "github.com/razatechofficial/mail-os/api/proto/v1"
	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/event"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
)

// EventHandler serves MailService.DispatchEvent: a service publishing an
// event with its service token in the authorization metadata. The request
// carries no event id or tenant: the id is the x-event-id metadata when it
// holds a UUID (so a retried dispatch is the same event and the sender can
// look its delivery up by its own id), otherwise MailOS assigns one; the
// tenant is the token's (or the client's configured one).
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
		ID:        eventID(ctx),
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

// MetadataEventID is the metadata key a sender names its event id with.
const MetadataEventID = "x-event-id"

// eventID is the sender's event id from the metadata when it is a UUID,
// otherwise a new one.
func eventID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(MetadataEventID); len(v) == 1 {
			if u, err := uuid.Parse(v[0]); err == nil {
				return u.String()
			}
		}
	}
	return uuid.Must(uuid.NewV7()).String()
}
