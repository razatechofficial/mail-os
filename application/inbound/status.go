package inbound

import (
	"context"
	"slices"
	"time"

	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// ServiceResolver resolves a service token to the application it is and
// the principal acting for it (applications.Service.ResolveService).
type ServiceResolver interface {
	ResolveService(ctx context.Context, p access.Principal) (domainapp.Application, access.Principal, error)
}

// Deliveries reads a message and its providers' delivery events
// (message.Service.Delivery).
type Deliveries interface {
	Delivery(ctx context.Context, tenantID, id string) (domainmsg.Message, []domainmsg.DeliveryEvent, error)
}

// RecordReader reads a received event's record.
type RecordReader interface {
	// Record returns the tenant's event, apperrors.NotFound otherwise.
	Record(ctx context.Context, tenantID, eventID string) (Record, error)
}

// Delivery statuses the status API reports (contract with IAM).
const (
	DeliveryQueued     = "queued"
	DeliverySending    = "sending"
	DeliverySent       = "sent"
	DeliveryDelivered  = "delivered"
	DeliveryBounced    = "bounced"
	DeliveryComplained = "complained"
	DeliveryFailed     = "failed"
	DeliveryCancelled  = "cancelled"
	DeliverySuppressed = "suppressed"
)

// StatusEvent is one step of a delivery.
type StatusEvent struct {
	Type       string
	OccurredAt time.Time
}

// DeliveryStatus is where a sender's message is.
type DeliveryStatus struct {
	DeliveryID string
	EventID    string
	Status     string
	LastError  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	// Events are the steps so far, oldest first: queued, sent, failed or
	// cancelled from the message, and the providers' delivery events.
	Events []StatusEvent
}

// StatusService answers a sending service where its messages are. A
// service sees only messages its own application sent for its tenant;
// anything else is not found.
type StatusService struct {
	apps       ServiceResolver
	deliveries Deliveries
	records    RecordReader
}

// NewStatusService builds the use case.
func NewStatusService(apps ServiceResolver, deliveries Deliveries, records RecordReader) *StatusService {
	return &StatusService{apps: apps, deliveries: deliveries, records: records}
}

// caller is the calling service's tenant and application.
func (s *StatusService) caller(ctx context.Context) (access.Principal, error) {
	p, ok := access.FromContext(ctx)
	if !ok || !p.IsService() {
		return p, apperrors.Forbidden("only a service may read its deliveries")
	}
	_, p, err := s.apps.ResolveService(ctx, p)
	return p, err
}

// ByDelivery is the status of the message POST /events returned as
// delivery_id.
func (s *StatusService) ByDelivery(ctx context.Context, deliveryID string) (DeliveryStatus, error) {
	p, err := s.caller(ctx)
	if err != nil {
		return DeliveryStatus{}, err
	}
	return s.status(ctx, p, deliveryID, "")
}

// ByEvent is the status of the message the caller's event became.
func (s *StatusService) ByEvent(ctx context.Context, eventID string) (DeliveryStatus, error) {
	p, err := s.caller(ctx)
	if err != nil {
		return DeliveryStatus{}, err
	}
	rec, err := s.records.Record(ctx, p.TenantID, eventID)
	if err != nil {
		return DeliveryStatus{}, err
	}
	if rec.ApplicationID != p.ApplicationID || rec.MessageID == "" {
		return DeliveryStatus{}, notFound()
	}
	return s.status(ctx, p, rec.MessageID, rec.EventID)
}

func notFound() error { return apperrors.NotFound("delivery not found") }

func (s *StatusService) status(ctx context.Context, p access.Principal, id, eventID string) (DeliveryStatus, error) {
	m, events, err := s.deliveries.Delivery(ctx, p.TenantID, id)
	if apperrors.IsNotFound(err) || err == nil && (m.ApplicationID == "" || m.ApplicationID != p.ApplicationID) {
		return DeliveryStatus{}, notFound()
	}
	if err != nil {
		return DeliveryStatus{}, err
	}
	if eventID == "" {
		eventID = m.EventID
	}
	return DeliveryStatus{DeliveryID: m.ID, EventID: eventID, Status: deliveryStatus(m.Status), LastError: m.LastError,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt, Events: steps(m, events)}, nil
}

// deliveryStatus maps a message status to the API's: a scheduled message
// is queued, and a sandbox application's captured message counts as sent
// (it was handled and will never go further).
func deliveryStatus(s domainmsg.Status) string {
	switch s {
	case domainmsg.StatusScheduled:
		return DeliveryQueued
	case domainmsg.StatusCaptured:
		return DeliverySent
	}
	return string(s)
}

// steps merges the message's own timestamps with the providers' events.
func steps(m domainmsg.Message, events []domainmsg.DeliveryEvent) []StatusEvent {
	out := []StatusEvent{{Type: DeliveryQueued, OccurredAt: m.CreatedAt}}
	has := map[string]bool{}
	for _, e := range events {
		has[string(e.Type)] = true
	}
	add := func(typ string, at *time.Time) {
		if at != nil && !has[typ] {
			out = append(out, StatusEvent{Type: typ, OccurredAt: *at})
		}
	}
	add(DeliverySent, m.SentAt)
	add(DeliveryDelivered, m.DeliveredAt)
	add(DeliveryBounced, m.BouncedAt)
	add(DeliveryFailed, m.FailedAt)
	add(DeliveryCancelled, m.CancelledAt)
	for _, e := range events {
		out = append(out, StatusEvent{Type: string(e.Type), OccurredAt: e.OccurredAt})
	}
	slices.SortStableFunc(out, func(a, b StatusEvent) int { return a.OccurredAt.Compare(b.OccurredAt) })
	return out
}
