package message

import (
	"context"
	"errors"
	"strings"
	"time"

	analytics "github.com/razatechofficial/mail-os/application/analytics"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/suppression"
	"github.com/razatechofficial/mail-os/domain/webhook"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// DeliveryEvents stores the providers' delivery events of messages and
// finds the message a provider names by its own id.
type DeliveryEvents interface {
	// ByProviderMessageID returns the tenant's message the provider sent
	// under providerMessageID, apperrors.NotFound otherwise.
	ByProviderMessageID(ctx context.Context, tenantID, providerID, providerMessageID string) (domainmsg.Message, error)
	// Add records e once per (message, type, key); false when it was
	// already recorded (a redelivered webhook).
	Add(ctx context.Context, e domainmsg.DeliveryEvent) (bool, error)
	// List returns a message's events, oldest first.
	List(ctx context.Context, tenantID, messageID string) ([]domainmsg.DeliveryEvent, error)
}

// Feedback suppresses addresses providers reported (suppression.Service).
type Feedback interface {
	RecordFeedback(ctx context.Context, tenantID, email string, t suppression.Type, reason string) error
}

// EventOutcome is what recording one provider event did.
type EventOutcome string

// Outcomes.
const (
	OutcomeRecorded       EventOutcome = "recorded"
	OutcomeDuplicate      EventOutcome = "duplicate"
	OutcomeUnknownMessage EventOutcome = "unknown_message"
)

// ErrStillSending is an event for a message whose send has not been
// recorded yet: the provider should deliver the event again later.
var ErrStillSending = errors.New("the message is still being sent")

// RecordProviderEvent records one delivery event that an authenticated
// webhook of the tenant's provider reported. The message is the one MailOS
// sent through that provider: by MailOS's id when the provider echoes it,
// otherwise by the provider's id; any other provider's or tenant's message
// is unknown. A delivered, hard-bounced or complained event moves the
// message's status when the move is legal, counts it, and tells the
// tenant's webhooks; a hard bounce or complaint of the recipient also
// suppresses the address. Every event is kept for the message's history.
func (s *Service) RecordProviderEvent(ctx context.Context, tenantID, providerID string, e domainmsg.ProviderEvent) (EventOutcome, error) {
	if s.d.Events == nil {
		return "", errors.New("delivery events are not available")
	}
	if !e.Type.Valid() || tenantID == "" || providerID == "" {
		return "", apperrors.Invalid("event", "invalid", "unknown event")
	}
	ctx = audit.WithTenant(ctx, tenantID)
	m, err := s.eventMessage(ctx, tenantID, providerID, e)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return OutcomeUnknownMessage, nil
		}
		return "", err
	}
	at := e.OccurredAt
	if at.IsZero() {
		at = s.now()
	}
	fresh, err := s.d.Events.Add(ctx, domainmsg.DeliveryEvent{ID: id.New(), MessageID: m.ID, TenantID: tenantID, Type: e.Type,
		ProviderID: providerID, Key: e.Key(), Reason: e.Reason, OccurredAt: at.UTC(), CreatedAt: s.now()})
	if err != nil {
		return "", err
	}
	if !fresh {
		return OutcomeDuplicate, nil
	}
	sameRecipient := e.Recipient == "" || strings.EqualFold(e.Recipient, m.ToEmail)
	moved, err := s.applyEvent(ctx, &m, e, at)
	if err != nil {
		return "", err
	}
	switch e.Type {
	case domainmsg.EventBounced, domainmsg.EventComplained:
		if sameRecipient {
			s.suppress(ctx, m, e)
		}
	}
	if moved {
		switch m.Status {
		case domainmsg.StatusDelivered:
			s.after(ctx, m, analytics.Delivered, webhook.EventDelivered)
		case domainmsg.StatusBounced:
			s.after(ctx, m, analytics.Bounced, webhook.EventBounced)
		case domainmsg.StatusComplained:
			s.after(ctx, m, analytics.Complained, webhook.EventComplained)
		}
	}
	return OutcomeRecorded, nil
}

// eventMessage finds the provider's message. A message still being sent
// has no provider yet; ErrStillSending asks for the event again.
func (s *Service) eventMessage(ctx context.Context, tenantID, providerID string, e domainmsg.ProviderEvent) (domainmsg.Message, error) {
	if e.MessageID != "" {
		m, err := s.d.Repo.Get(ctx, tenantID, e.MessageID)
		switch {
		case err == nil && m.Status == domainmsg.StatusSending:
			return m, ErrStillSending
		case err == nil && m.ProviderID == providerID:
			return m, nil
		case err != nil && !apperrors.IsNotFound(err):
			return m, err
		}
	}
	if e.ProviderMessageID == "" {
		return domainmsg.Message{}, apperrors.NotFound("message")
	}
	return s.d.Events.ByProviderMessageID(ctx, tenantID, providerID, e.ProviderMessageID)
}

// applyEvent moves the message to the event's status when that is a
// legal change, retrying once if a concurrent update moved it first.
func (s *Service) applyEvent(ctx context.Context, m *domainmsg.Message, e domainmsg.ProviderEvent, at time.Time) (bool, error) {
	to := e.Type.Status()
	for attempt := 0; attempt < 2 && to != ""; attempt++ {
		if !domainmsg.CanTransition(m.Status, to) {
			return false, nil
		}
		from := m.Status
		next := *m
		if err := next.Transition(to, at.UTC()); err != nil {
			return false, err
		}
		next.UpdatedAt = s.now()
		if to == domainmsg.StatusBounced || to == domainmsg.StatusComplained {
			next.LastError = e.Reason
		}
		ok, err := s.d.Repo.Update(ctx, next, from)
		if err != nil {
			return false, err
		}
		if ok {
			*m = next
			s.auditEvent(ctx, *m, e)
			return true, nil
		}
		fresh, err := s.d.Repo.Get(ctx, m.OrgID, m.ID)
		if err != nil {
			return false, err
		}
		*m = fresh
	}
	return false, nil
}

// auditEvent records bounces and complaints (deliveries are counted, not
// audited: there is one per message).
func (s *Service) auditEvent(ctx context.Context, m domainmsg.Message, e domainmsg.ProviderEvent) {
	if s.d.Audit == nil || e.Type == domainmsg.EventDelivered {
		return
	}
	if err := s.d.Audit.Append(ctx, "message", m.ID, "message."+string(m.Status), map[string]any{
		"provider_id": m.ProviderID, "to": logger.MaskEmail(m.ToEmail), "reason": e.Reason, "source": "provider_webhook",
	}); err != nil {
		logger.FromContext(ctx).Warn("audit delivery event", logger.Err(err))
	}
}

// suppress lists a hard-bounced or complaining recipient.
func (s *Service) suppress(ctx context.Context, m domainmsg.Message, e domainmsg.ProviderEvent) {
	if s.d.Feedback == nil {
		return
	}
	t := suppression.TypeBounce
	if e.Type == domainmsg.EventComplained {
		t = suppression.TypeComplaint
	}
	if err := s.d.Feedback.RecordFeedback(ctx, m.OrgID, m.ToEmail, t, e.Reason); err != nil {
		logger.FromContext(ctx).Warn("suppress from delivery event", logger.String("message_id", m.ID), logger.Err(err))
	}
}

// Events returns a message's recorded delivery events (nil without an
// event store).
func (s *Service) Events(ctx context.Context, tenantID, messageID string) ([]domainmsg.DeliveryEvent, error) {
	if s.d.Events == nil {
		return nil, nil
	}
	return s.d.Events.List(ctx, tenantID, messageID)
}
