// Package inbound accepts the events services publish to MailOS (contract
// §2, §4): over HTTP and gRPC with a service token, or from Kafka with a
// message signature. Whatever the transport, an event is authorised for its
// sender and tenant, checked against the topic catalogue, recorded once per
// (tenant, event id) and handed to the Dispatcher, which turns it into a
// message. A redelivered event is accepted again without a second message.
//
// The sender is an application (application/applications): its IAM client
// must be a registered, active server application of the tenant, allowed
// to send the topic. There is no other allow-list.
package inbound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Transports an event arrives on.
const (
	TransportHTTP  = "http"
	TransportGRPC  = "grpc"
	TransportKafka = "kafka"
)

// Audit actions. A refusal over Kafka is audited by the consumer as
// event.AuditMessageRejected instead.
const (
	AuditAccepted = "event.accepted"
	AuditRefused  = "event.refused"
)

// Delivery is an accepted event for the Dispatcher.
type Delivery struct {
	TenantID      string
	OrgID         string
	ApplicationID string
	Topic         string
	EventID       string
	Source        string
	ClientID      string
	// Data is the event data, numbers as json.Number. The recipient is
	// data.email.
	Data map[string]any
}

// Dispatcher turns an accepted event into a message (the messaging use
// case's templated send). It runs in the transaction that records the
// event, so a failure records nothing and the event can be sent again.
type Dispatcher interface {
	Dispatch(ctx context.Context, d Delivery) (messageID string, err error)
}

// Record is a received event, kept for idempotency.
type Record struct {
	TenantID      string
	EventID       string
	Topic         string
	ClientID      string
	ApplicationID string
	Transport     string
	// DataSHA256 is the hash of the type and data, to tell a redelivery
	// from another event reusing the id.
	DataSHA256 string
	MessageID  string
	ReceivedAt time.Time
}

// Store records events once per (tenant, event id).
type Store interface {
	// Claim records r unless the event was already received; then it
	// returns the earlier record and false.
	Claim(ctx context.Context, r Record) (prior Record, fresh bool, err error)
	// Complete stores the message the event became.
	Complete(ctx context.Context, tenantID, eventID, messageID string) error
}

// Transactor runs fn in one database transaction.
type Transactor interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// TenantEnsurer provisions the tenant on its first event and refuses a
// tenant MailOS is disabled for.
type TenantEnsurer interface {
	Ensure(ctx context.Context, tenantID string) error
}

// Authorizer decides whether the caller's application may publish a
// topic for a tenant (applications.Service.AuthorizeEvent), and returns
// the principal acting for the application's tenant.
type Authorizer interface {
	AuthorizeEvent(ctx context.Context, p access.Principal, topic, tenant string) (domainapp.Application, access.Principal, error)
}

// Auditor records acceptances and refusals.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// In is one received event.
type In struct {
	Transport string
	Event     event.Event
	// TopicHint is the topic the event arrived on (the Kafka record's);
	// when set, the event type must equal it.
	TopicHint string
}

// Result is what the caller is told.
type Result struct {
	Accepted bool
	// DeliveryID is the id of the message the event became.
	DeliveryID string
	EventID    string
	Duplicate  bool
}

// RefusedMessage is the client-facing message of a refused event; the
// reason is audited, not returned.
const RefusedMessage = "this service may not publish the event for this tenant"

// Service is the inbound event use case.
type Service struct {
	apps       Authorizer
	tenants    TenantEnsurer
	store      Store
	tx         Transactor
	dispatcher Dispatcher
	audit      Auditor
	now        func() time.Time
}

// NewService builds the use case.
func NewService(apps Authorizer, tenants TenantEnsurer, store Store, tx Transactor, dispatcher Dispatcher, audit Auditor) *Service {
	return &Service{apps: apps, tenants: tenants, store: store, tx: tx, dispatcher: dispatcher, audit: audit, now: time.Now}
}

// Dispatch authorises, validates, records and dispatches one event. A
// refusal is a 403 (its error wraps the access refusal), invalid data a 422
// with the failing fields, an event id reused for other data a 409.
func (s *Service) Dispatch(ctx context.Context, in In) (Result, error) {
	ev := in.Event
	p, ok := access.FromContext(ctx)
	if !ok || !p.IsService() {
		return Result{}, s.refuse(ctx, in, domainapp.ErrNotService)
	}
	if err := ev.Validate(); err != nil {
		return Result{}, apperrors.Invalid("type", "invalid_event", err.Error())
	}
	if in.TopicHint != "" && in.TopicHint != ev.Type {
		return Result{}, s.refuse(ctx, in, domainapp.ErrTypeNotAllowed)
	}
	_, p, err := s.apps.AuthorizeEvent(ctx, p, ev.Type, ev.TenantUUID)
	if err != nil {
		if domainapp.Reason(err) != "" {
			return Result{}, s.refuse(ctx, in, err)
		}
		return Result{}, err
	}
	// Audit rows and the dispatch act for the application's tenant.
	tenant := p.TenantID
	if ev.OrganizationUUID != "" {
		p.OrgID = ev.OrganizationUUID
	}
	ctx = access.WithPrincipal(ctx, p)
	if err := s.tenants.Ensure(ctx, tenant); err != nil {
		return Result{}, err
	}

	data, err := decodeData(ev.Data)
	if err != nil {
		return Result{}, apperrors.Invalid("data", "invalid_type", "data must be a JSON object")
	}
	if errs := template.ValidateData(ev.Type, data); len(errs) > 0 {
		return Result{}, apperrors.Validation(errs...)
	}
	if email, _ := data["email"].(string); strings.TrimSpace(email) == "" {
		return Result{}, apperrors.Invalid("data.email", "required", "data.email is required")
	}

	eventID := ev.ID
	if eventID == "" {
		eventID = uuid.Must(uuid.NewV7()).String()
	}
	rec := Record{
		TenantID: tenant, EventID: eventID, Topic: ev.Type, ClientID: p.ClientID, ApplicationID: p.ApplicationID, Transport: in.Transport,
		DataSHA256: dataHash(ev), ReceivedAt: s.now().UTC(),
	}
	var res Result
	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		prior, fresh, err := s.store.Claim(ctx, rec)
		if err != nil {
			return err
		}
		if !fresh {
			if prior.DataSHA256 != rec.DataSHA256 {
				return apperrors.Conflict("the event id was already used for another event")
			}
			res = Result{Accepted: true, DeliveryID: prior.MessageID, EventID: eventID, Duplicate: true}
			return s.accepted(ctx, in, res)
		}
		messageID, err := s.dispatcher.Dispatch(ctx, Delivery{
			TenantID: tenant, OrgID: p.OrgID, ApplicationID: p.ApplicationID, Topic: ev.Type, EventID: eventID, Source: ev.Source,
			ClientID: p.ClientID, Data: data,
		})
		if err != nil {
			return err
		}
		if err := s.store.Complete(ctx, tenant, eventID, messageID); err != nil {
			return err
		}
		res = Result{Accepted: true, DeliveryID: messageID, EventID: eventID}
		return s.accepted(ctx, in, res)
	})
	if err != nil {
		// The send was refused inside the transaction (sender, limits):
		// its audit row rolled back with it, so the event's refusal is
		// recorded now.
		if domainapp.Reason(err) != "" {
			return Result{}, s.refused(ctx, in, err)
		}
		return Result{}, err
	}
	return res, nil
}

// accepted audits an accepted event: who, which topic and event, which
// message. Never the data.
func (s *Service) accepted(ctx context.Context, in In, r Result) error {
	return s.audit.Append(ctx, "event", r.EventID, AuditAccepted, map[string]any{
		"topic": in.Event.Type, "event_id": r.EventID, "message_id": r.DeliveryID,
		"transport": in.Transport, "duplicate": r.Duplicate, "application_id": applicationOf(ctx),
	})
}

func applicationOf(ctx context.Context) string {
	p, _ := access.FromContext(ctx)
	return p.ApplicationID
}

// refuse audits a refusal (except over Kafka, whose consumer audits it as a
// rejected message) and returns the 403 wrapping reason.
func (s *Service) refuse(ctx context.Context, in In, reason error) error {
	if err := s.auditRefusal(ctx, in, reason); err != nil {
		return err
	}
	return apperrors.Wrap(reason, apperrors.KindForbidden, apperrors.CodeForbidden, RefusedMessage)
}

// refused audits a send the application refused while dispatching, and
// returns that refusal (a 403 or a 429) unchanged.
func (s *Service) refused(ctx context.Context, in In, err error) error {
	if aerr := s.auditRefusal(ctx, in, err); aerr != nil {
		return aerr
	}
	return err
}

func (s *Service) auditRefusal(ctx context.Context, in In, reason error) error {
	if in.Transport != TransportKafka {
		meta := map[string]any{"reason": domainapp.Reason(reason), "topic": in.Event.Type, "transport": in.Transport}
		if id := applicationOf(ctx); id != "" {
			meta["application_id"] = id
		}
		if in.Event.ID != "" {
			meta["event_id"] = in.Event.ID
		}
		if in.Event.TenantUUID != "" {
			meta["requested_tenant"] = in.Event.TenantUUID
		}
		return s.audit.Append(ctx, "event", in.Event.ID, AuditRefused, meta)
	}
	return nil
}

// IsRefusal reports whether err is a refused event, and its stable reason.
func IsRefusal(err error) (reason string, ok bool) {
	r := domainapp.Reason(err)
	return r, r != ""
}

func decodeData(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, errors.New("data is not a JSON object")
	}
	return m, nil
}

// dataHash is the SHA-256 of the type and the compacted data: the same
// event sent again (even with new trace metadata) hashes the same.
func dataHash(ev event.Event) string {
	var buf bytes.Buffer
	buf.WriteString(ev.Type)
	buf.WriteByte('\n')
	if err := json.Compact(&buf, ev.Data); err != nil {
		buf.Write(ev.Data)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// Unconfigured is the Dispatcher until messaging is wired: every event is
// answered 503 (and redelivered over Kafka), never dropped.
type Unconfigured struct{}

// Dispatch implements Dispatcher.
func (Unconfigured) Dispatch(context.Context, Delivery) (string, error) {
	return "", apperrors.Unavailable("event dispatch is not configured")
}
