// Package pubsub is the Kafka transport for events IAM publishes (contract
// §2): each record's iam-msg-sig is verified, its envelope parsed and
// matched to the signature, its sender authorised for the topic and tenant,
// and the event handed to the inbound use case. Every rejection is audited
// as mailos.message_rejected with the reason, never the body.
//
// MailOS consumes Kafka only. IAM can also publish over NATS and RabbitMQ;
// MailOS's configuration offers neither.
package pubsub

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/kafka"
	"github.com/razatechofficial/mail-os/infrastructure/msgsig"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Verifier checks message signatures (msgsig.Verifier).
type Verifier interface {
	Verify(ctx context.Context, header, topic string, value []byte, opts ...msgsig.Option) (msgsig.Claims, error)
}

// Dispatcher is the inbound use case.
type Dispatcher interface {
	Dispatch(ctx context.Context, in inbound.In) (inbound.Result, error)
}

// Auditor records rejections.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Handler handles one Kafka record. It is the kafka.Handler of the event
// consumer: nil or a permanent rejection commits the record, any other
// error redelivers it.
type Handler struct {
	verifier Verifier
	grants   access.ServiceGrants
	events   Dispatcher
	audit    Auditor

	mu sync.Mutex
	// lastTransient is the delivery whose transient rejection was audited,
	// so a record retried in place is audited once, not on every retry.
	lastTransient string
}

// NewHandler builds the handler.
func NewHandler(verifier Verifier, grants access.ServiceGrants, events Dispatcher, audit Auditor) *Handler {
	return &Handler{verifier: verifier, grants: grants, events: events, audit: audit}
}

// Handle implements kafka.Handler.
func (h *Handler) Handle(ctx context.Context, rec kafka.Record) error {
	claims, err := h.verifier.Verify(ctx, string(rec.Headers[msgsig.Header]), rec.Topic, rec.Value, msgsig.Delivery(rec.DeliveryID()))
	if err != nil {
		if reason, ok := event.ReasonOf(err); ok {
			// A replay passed checks 1 to 4: its body is IAM's, so the
			// rejection is recorded under the event's tenant.
			if reason == event.ReasonReplay || reason == event.ReasonReplayGuardUnavailable {
				if ev, perr := event.Parse(rec.Value); perr == nil {
					return h.reject(audit.WithTenant(ctx, ev.TenantUUID), rec, reason, err, nil, ev.ID)
				}
			}
			return h.reject(ctx, rec, reason, err, nil)
		}
		// IAM's JWKS is unreachable: nothing was checked, retry.
		return err
	}
	ev, err := event.Parse(rec.Value)
	if err != nil {
		return h.reject(ctx, rec, event.ReasonMalformed, err, &claims)
	}
	if ev.Type != rec.Topic {
		return h.reject(ctx, rec, event.ReasonTopic, fmt.Errorf("event type %q on topic %q", ev.Type, rec.Topic), &claims)
	}
	if ev.ID != claims.JTI {
		return h.reject(ctx, rec, event.ReasonMalformed, fmt.Errorf("jti %q is not the event id %q", claims.JTI, ev.ID), &claims)
	}

	// The signed body is now trusted: act as the signing client, for the
	// tenant the event names (or the one configured for the client).
	p := access.Principal{
		Kind: access.KindService, Subject: "client:" + claims.ClientID, ClientID: claims.ClientID,
		TenantID: ev.TenantUUID, OrgID: ev.OrganizationUUID, TokenID: claims.JTI,
	}
	ctx = access.WithPrincipal(ctx, p)
	// 6. The sender may publish the topic for the tenant (contract §4).
	if _, err := h.grants.Authorize(p, ev.Type, ev.TenantUUID); err != nil {
		return h.reject(ctx, rec, stepSixReason(err), err, &claims, ev.ID)
	}
	res, err := h.events.Dispatch(ctx, inbound.In{Transport: inbound.TransportKafka, Event: ev, TopicHint: rec.Topic})
	if err != nil {
		if refusal, ok := inbound.IsRefusal(err); ok {
			return h.reject(ctx, rec, stepSixReason(refusal), err, &claims, ev.ID)
		}
		switch apperrors.KindOf(err) {
		case apperrors.KindInvalidInput, apperrors.KindBadRequest, apperrors.KindConflict:
			return h.reject(ctx, rec, event.ReasonMalformed, err, &claims, ev.ID)
		case apperrors.KindForbidden, apperrors.KindInactive:
			// MailOS is switched off for the tenant.
			return h.reject(ctx, rec, event.ReasonUnauthorisedTopic, err, &claims, ev.ID)
		}
		return err
	}
	logger.FromContext(ctx).Info("event accepted",
		logger.String("topic", rec.Topic), logger.String("event_id", res.EventID),
		logger.String("message_id", res.DeliveryID), logger.Bool("duplicate", res.Duplicate))
	return nil
}

// stepSixReason names an allow-list refusal for mailos.message_rejected:
// unknown_client, or unauthorised_topic for a topic or tenant the client
// may not publish (the access reason is audited beside it as refusal).
func stepSixReason(err error) event.Reason {
	if errors.Is(err, access.ErrUnknownClient) {
		return event.ReasonUnknownClient
	}
	return event.ReasonUnauthorisedTopic
}

// reject audits a rejected record and returns the error the consumer acts
// on: the rejection (committed) when it is permanent, the transient error
// otherwise, and a transient error when the audit row cannot be written,
// so no rejection is committed unaudited. claims is nil before the
// signature verified; then the client and tenant are unknown.
func (h *Handler) reject(ctx context.Context, rec kafka.Record, reason event.Reason, cause error, claims *msgsig.Claims, eventID ...string) error {
	var rej *event.Rejection
	if !errors.As(cause, &rej) || rej.Reason != reason {
		rej = event.Reject(reason, cause)
	}
	meta := map[string]any{
		"reason": string(reason), "topic": rec.Topic, "partition": int(rec.Partition), "offset": rec.Offset,
	}
	if claims != nil {
		meta["client_id"] = claims.ClientID
	}
	resource := rec.DeliveryID()
	if len(eventID) > 0 && eventID[0] != "" {
		meta["event_id"] = eventID[0]
		resource = eventID[0]
	}
	if access.Reason(cause) != "refused" {
		meta["refusal"] = access.Reason(cause)
	}
	logger.SecurityWarn("message rejected", logger.String("reason", string(reason)), logger.String("topic", rec.Topic),
		logger.Int("partition", int(rec.Partition)), logger.Int64("offset", rec.Offset), logger.Err(cause))

	if rej.Transient {
		h.mu.Lock()
		seen := h.lastTransient == rec.DeliveryID()
		h.lastTransient = rec.DeliveryID()
		h.mu.Unlock()
		if !seen {
			if err := h.audit.Append(ctx, "event", resource, event.AuditMessageRejected, meta); err != nil {
				logger.Error("audit message rejection", logger.Err(err))
			}
		}
		return rej
	}
	if err := h.audit.Append(ctx, "event", resource, event.AuditMessageRejected, meta); err != nil {
		return fmt.Errorf("audit %s rejection: %w", reason, err)
	}
	return rej
}
