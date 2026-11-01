package message

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/infrastructure/render"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// ErrDuplicateKey is returned by Repository.Create for a reused
// idempotency key.
var ErrDuplicateKey = errors.New("duplicate idempotency key")

// ErrBodyGone is the 404 for a body erased under the retention policy.
var ErrBodyGone = apperrors.NotFound("the message body is no longer stored")

// MaxBatch bounds one batch send.
const MaxBatch = 100

// MaxSchedule is how far ahead a message may be scheduled.
const MaxSchedule = 30 * 24 * time.Hour

// Service is the message use case.
type Service struct {
	d   Deps
	cfg Config
	now func() time.Time
}

// NewService builds the service.
func NewService(d Deps, cfg Config) *Service {
	return &Service{d: d, cfg: cfg.withDefaults(), now: func() time.Time { return time.Now().UTC() }}
}

var _ apptemplate.TestSender = (*Service)(nil)

// SendInput is a direct send, or a templated one when TemplateSlug or
// TemplateID is set (then Subject and the bodies come from the template).
type SendInput struct {
	TenantID       string
	FromName       string
	FromEmail      string
	ToEmail        string
	ToName         string
	ReplyTo        string
	Subject        string
	HTML           string
	Text           string
	TemplateSlug   string
	TemplateID     string
	Locale         string
	TemplateData   map[string]any
	Tags           []string
	Metadata       map[string]any
	Priority       int
	IdempotencyKey string
	ScheduleAt     *time.Time
	Type           domainmsg.Type
}

// Result is a queued message's id and status.
type Result struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
}

// actorOf names who asks, from the request's principal.
func actorOf(ctx context.Context) domainmsg.Actor {
	p, ok := access.FromContext(ctx)
	switch {
	case !ok:
		return domainmsg.Actor{Type: domainmsg.ActorSystem}
	case p.IsService():
		return domainmsg.Actor{Type: domainmsg.ActorService, ID: p.ClientID}
	}
	return domainmsg.Actor{Type: domainmsg.ActorUser, ID: p.Subject}
}

// Send queues one message.
func (s *Service) Send(ctx context.Context, in SendInput) (Result, error) {
	if in.TemplateSlug != "" || in.TemplateID != "" {
		m, err := s.SendTemplated(ctx, TemplatedSend{TenantID: in.TenantID, TemplateSlug: in.TemplateSlug, TemplateID: in.TemplateID,
			Locale: in.Locale, To: in.ToEmail, ToName: in.ToName, FromName: in.FromName, FromEmail: in.FromEmail,
			IdempotencyKey: in.IdempotencyKey, Data: in.TemplateData, Tags: in.Tags, Type: in.Type,
			replyTo: in.ReplyTo, metadata: in.Metadata, priority: in.Priority, scheduleAt: in.ScheduleAt})
		return Result{MessageID: m.ID, Status: string(m.Status)}, err
	}
	// Written HTML is sanitised like a template's, so a direct send cannot
	// carry script into the mail or the console's body view.
	if in.HTML != "" {
		clean, err := render.SanitizeHTML(in.HTML)
		if err != nil {
			return Result{}, apperrors.Invalid("html_body", "invalid", "the HTML body cannot be read")
		}
		in.HTML = clean
	}
	now := s.now()
	m := domainmsg.Message{
		ID: id.New(), OrgID: in.TenantID, FromName: in.FromName, FromEmail: in.FromEmail, ToEmail: in.ToEmail,
		ToName: in.ToName, ReplyTo: in.ReplyTo, Subject: in.Subject, HTMLBody: in.HTML, TextBody: in.Text,
		Type: in.Type, Priority: domainmsg.Priority(in.Priority), Tags: in.Tags, Metadata: in.Metadata,
		IdempotencyKey: in.IdempotencyKey, Actor: actorOf(ctx), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.schedule(&m, in.ScheduleAt, now); err != nil {
		return Result{}, err
	}
	m, err := s.queue(ctx, m)
	return Result{MessageID: m.ID, Status: string(m.Status)}, err
}

// schedule makes m scheduled when at is in the future.
func (s *Service) schedule(m *domainmsg.Message, at *time.Time, now time.Time) error {
	if at == nil || !at.After(now) {
		return nil
	}
	if at.Sub(now) > MaxSchedule {
		return apperrors.Invalid("schedule_at", "out_of_range", "a message can be scheduled at most 30 days ahead")
	}
	t := at.UTC()
	m.ScheduledAt, m.Status = &t, domainmsg.StatusScheduled
	return nil
}

// queue validates m, applies the idempotency key and the suppression
// list, stores it and hands it to the queue.
func (s *Service) queue(ctx context.Context, m domainmsg.Message) (domainmsg.Message, error) {
	if err := s.d.Tenants.Ensure(ctx, m.OrgID); err != nil {
		return domainmsg.Message{}, err
	}
	m.Normalize()
	if err := m.Validate(); err != nil {
		return domainmsg.Message{}, err
	}
	if m.IdempotencyKey != "" {
		if prior, err := s.d.Repo.ByIdempotencyKey(ctx, m.OrgID, m.IdempotencyKey); err != nil || prior != nil {
			if prior != nil {
				return *prior, nil
			}
			return domainmsg.Message{}, err
		}
	}
	sup, err := s.d.Suppressions.Blocks(ctx, m.OrgID, m.ToEmail, m.Type)
	if err != nil {
		return domainmsg.Message{}, err
	}
	if sup != nil {
		m.Status = domainmsg.StatusSuppressed
		m.LastError = "the recipient is on the suppression list (" + string(sup.Type) + ")"
	}
	if err := s.d.Repo.Create(ctx, m); err != nil {
		if errors.Is(err, ErrDuplicateKey) {
			if prior, err := s.d.Repo.ByIdempotencyKey(ctx, m.OrgID, m.IdempotencyKey); err == nil && prior != nil {
				return *prior, nil
			}
		}
		return domainmsg.Message{}, err
	}
	if m.Status == domainmsg.StatusQueued {
		if err := s.d.Queue.EnqueueSend(ctx, m); err != nil {
			// The row is stored: the sweep queues it again.
			logger.FromContext(ctx).Warn("enqueue send failed; the sweep will retry", logger.String("message_id", m.ID), logger.Err(err))
		}
	}
	if err := s.d.Audit.Append(ctx, "message", m.ID, "message.queued", map[string]any{
		"to": logger.MaskEmail(m.ToEmail), "status": string(m.Status), "type": string(m.Type),
		"topic": m.Topic, "template_id": m.TemplateID, "template_version_id": m.TemplateVersionID,
	}); err != nil {
		return domainmsg.Message{}, err
	}
	return m, nil
}

// BatchItem is one batch entry's outcome.
type BatchItem struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// BatchResult is a batch send's outcome.
type BatchResult struct {
	Results      []BatchItem `json:"results"`
	SuccessCount int         `json:"success_count"`
	FailCount    int         `json:"fail_count"`
}

// Batch queues up to MaxBatch messages; one failing does not stop the
// rest.
func (s *Service) Batch(ctx context.Context, tenantID string, in []SendInput) (BatchResult, error) {
	if len(in) == 0 || len(in) > MaxBatch {
		return BatchResult{}, apperrors.Invalid("messages", "out_of_range", fmt.Sprintf("a batch holds 1 to %d messages", MaxBatch))
	}
	out := BatchResult{Results: make([]BatchItem, 0, len(in))}
	for _, m := range in {
		m.TenantID = tenantID
		r, err := s.Send(ctx, m)
		if err != nil {
			out.FailCount++
			out.Results = append(out.Results, BatchItem{Status: "failed", Error: apperrors.UserMessage(err)})
			continue
		}
		out.SuccessCount++
		out.Results = append(out.Results, BatchItem{MessageID: r.MessageID, Status: r.Status})
	}
	return out, nil
}

// TemplatedSend is a send from a published template, by an event or the
// API. Topic, TemplateSlug or TemplateID names the template.
type TemplatedSend struct {
	TenantID       string
	Topic          string
	TemplateSlug   string
	TemplateID     string
	Locale         string
	To             string
	ToName         string
	FromName       string
	FromEmail      string
	EventID        string
	Source         string
	IdempotencyKey string
	Data           map[string]any
	Tags           []string
	Type           domainmsg.Type
	// CampaignID links a campaign's message to its campaign.
	CampaignID string

	actor      *domainmsg.Actor
	replyTo    string
	metadata   map[string]any
	priority   int
	scheduleAt *time.Time
}

func typeOf(c domaintemplate.Category) domainmsg.Type {
	switch c {
	case domaintemplate.CategoryMarketing:
		return domainmsg.TypeMarketing
	case domaintemplate.CategoryNotification:
		return domainmsg.TypeNotification
	}
	return domainmsg.TypeTransactional
}

// SendTemplated resolves the template's published version, pins it, and
// queues the message with the data and the topic's secret keys. The
// worker renders it.
func (s *Service) SendTemplated(ctx context.Context, in TemplatedSend) (domainmsg.Message, error) {
	if s.d.Templates == nil {
		return domainmsg.Message{}, apperrors.Unavailable("templates are not available")
	}
	if err := s.d.Tenants.Ensure(ctx, in.TenantID); err != nil {
		return domainmsg.Message{}, err
	}
	tpl, ver, err := s.d.Templates.ResolvePublished(ctx, in.TenantID, apptemplate.Ref{TemplateID: in.TemplateID, Slug: in.TemplateSlug, Topic: in.Topic}, in.Locale)
	if err != nil {
		return domainmsg.Message{}, err
	}
	topic := in.Topic
	if topic == "" {
		topic = tpl.Topic
	}
	data := in.Data
	if data == nil {
		data = map[string]any{}
	}
	if topic != "" {
		if errs := domaintemplate.ValidateData(topic, data); len(errs) > 0 {
			return domainmsg.Message{}, apperrors.Validation(errs...)
		}
	}
	typ := in.Type
	if typ == "" {
		typ = typeOf(tpl.Category)
	}
	secretKeys := domaintemplate.SecretKeys(topic)
	now := s.now()
	m := domainmsg.Message{
		ID: id.New(), OrgID: in.TenantID, FromName: in.FromName, FromEmail: in.FromEmail, ToEmail: in.To, ToName: in.ToName,
		ReplyTo: in.replyTo, Type: typ, Priority: domainmsg.Priority(in.priority), Tags: in.Tags, Metadata: in.metadata,
		Topic: topic, TemplateID: tpl.ID, TemplateVersionID: ver.ID, Locale: string(ver.Locale), TemplateData: data,
		SecretKeys: secretKeys, EventID: in.EventID, IdempotencyKey: in.IdempotencyKey, Actor: actorOf(ctx),
		CampaignID: in.CampaignID, CreatedAt: now, UpdatedAt: now,
	}
	if in.actor != nil {
		m.Actor = *in.actor
	}
	if in.Source != "" {
		m.Metadata = maps.Clone(m.Metadata)
		if m.Metadata == nil {
			m.Metadata = map[string]any{}
		}
		m.Metadata["source"] = in.Source
	}
	// The subject is rendered now so lists show it; views mask its secrets.
	if s.d.Render != nil {
		if c, err := s.d.Render(Content{Subject: ver.Subject}, s.withBrand(ctx, in.TenantID, data)); err == nil {
			m.Subject = c.Subject
		}
	}
	if err := s.schedule(&m, in.scheduleAt, now); err != nil {
		return domainmsg.Message{}, err
	}
	return s.queue(ctx, m)
}

// TestMessage is a template test send, rendered by the templates slice.
type TestMessage = apptemplate.TestMessage

// SendTest queues a test send, tagged "test" (apptemplate.TestSender).
func (s *Service) SendTest(ctx context.Context, t TestMessage) (messageID, status string, err error) {
	tags := t.Tags
	if !slices.Contains(tags, "test") {
		tags = append(slices.Clone(tags), "test")
	}
	r, err := s.Send(ctx, SendInput{TenantID: t.TenantID, FromName: t.FromName, FromEmail: t.FromEmail, ToEmail: t.To,
		Subject: t.Subject, HTML: t.HTML, Text: t.Text, Tags: tags, Type: domainmsg.TypeTransactional,
		Metadata: map[string]any{"test": true}})
	return r.MessageID, r.Status, err
}

// View is a message as the console and API show it: no bodies, the
// subject and template data with secret values masked.
type View struct {
	domainmsg.Message
	MaskedSubject      string
	MaskedTemplateData map[string]any
}

func viewOf(m domainmsg.Message) View {
	return View{Message: m, MaskedSubject: m.Redact(m.Subject), MaskedTemplateData: m.MaskedTemplateData()}
}

// Get returns one message.
func (s *Service) Get(ctx context.Context, tenantID, id string) (View, error) {
	m, err := s.d.Repo.Get(ctx, tenantID, id)
	if err != nil {
		return View{}, err
	}
	return viewOf(m), nil
}

// List returns a page of messages.
func (s *Service) List(ctx context.Context, f Filter) ([]View, int, error) {
	list, total, err := s.d.Repo.List(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	out := make([]View, len(list))
	for i, m := range list {
		out[i] = viewOf(m)
	}
	return out, total, nil
}

// Body is a stored body.
type Body struct {
	HTML string `json:"html_body"`
	Text string `json:"text_body"`
}

// Body returns a message's body, audited (message.body_viewed). Secret
// values stay masked; a purged body is 404.
func (s *Service) Body(ctx context.Context, tenantID, id string) (Body, error) {
	m, err := s.d.Repo.Get(ctx, tenantID, id)
	if err != nil {
		return Body{}, err
	}
	if m.BodyPurgedAt != nil {
		return Body{}, ErrBodyGone
	}
	if err := s.d.Audit.Append(ctx, "message", m.ID, "message.body_viewed", map[string]any{"to": logger.MaskEmail(m.ToEmail)}); err != nil {
		return Body{}, err
	}
	return Body{HTML: m.Redact(m.HTMLBody), Text: m.Redact(m.TextBody)}, nil
}

// Cancel stops a queued or scheduled message.
func (s *Service) Cancel(ctx context.Context, tenantID, id string) (domainmsg.Message, error) {
	m, err := s.d.Repo.Get(ctx, tenantID, id)
	if err != nil {
		return domainmsg.Message{}, err
	}
	from := m.Status
	if from != domainmsg.StatusQueued && from != domainmsg.StatusScheduled {
		return domainmsg.Message{}, apperrors.Conflict("only a queued or scheduled message can be cancelled")
	}
	if err := m.Transition(domainmsg.StatusCancelled, s.now()); err != nil {
		return domainmsg.Message{}, err
	}
	ok, err := s.d.Repo.Update(ctx, m, from)
	if err != nil {
		return domainmsg.Message{}, err
	}
	if !ok {
		return domainmsg.Message{}, apperrors.Conflict("the message is already being sent")
	}
	if err := s.d.Audit.Append(ctx, "message", m.ID, "message.cancelled", map[string]any{"from_status": string(from)}); err != nil {
		return domainmsg.Message{}, err
	}
	return m, nil
}

// Resend queues a copy of a finished message as a new message.
func (s *Service) Resend(ctx context.Context, tenantID, messageID string) (domainmsg.Message, error) {
	orig, err := s.d.Repo.Get(ctx, tenantID, messageID)
	if err != nil {
		return domainmsg.Message{}, err
	}
	if !orig.Status.Final() {
		return domainmsg.Message{}, apperrors.Conflict("the message is still being sent")
	}
	if orig.BodyPurgedAt != nil {
		return domainmsg.Message{}, apperrors.Conflict("the message body was erased under the retention policy; it cannot be resent")
	}
	now := s.now()
	m := orig
	m.ID, m.Status, m.Attempts, m.LastError, m.IdempotencyKey = id.New(), domainmsg.StatusQueued, 0, "", ""
	m.ProviderID, m.ProviderMessageID = "", ""
	m.ScheduledAt, m.LastAttemptAt, m.SentAt, m.DeliveredAt, m.BouncedAt, m.FailedAt, m.CancelledAt, m.OpenedAt, m.ClickedAt = nil, nil, nil, nil, nil, nil, nil, nil, nil
	m.Actor, m.CreatedAt, m.UpdatedAt = actorOf(ctx), now, now
	m.Tags = slices.Clone(orig.Tags)
	m.Metadata = maps.Clone(orig.Metadata)
	if m.Metadata == nil {
		m.Metadata = map[string]any{}
	}
	m.Metadata["resent_from"] = orig.ID
	if m.TemplateVersionID != "" {
		// Rendered again from the pinned version and the stored data.
		m.HTMLBody, m.TextBody = "", ""
	}
	out, err := s.queue(ctx, m)
	if err != nil {
		return domainmsg.Message{}, err
	}
	if err := s.d.Audit.Append(ctx, "message", orig.ID, "message.resent", map[string]any{"new_message_id": out.ID}); err != nil {
		return domainmsg.Message{}, err
	}
	return out, nil
}

// withBrand adds brand.company_name from the tenant's branding when the
// data has none (IAM sends it with its events; API sends do not).
func (s *Service) withBrand(ctx context.Context, tenantID string, data map[string]any) map[string]any {
	if s.d.Branding == nil {
		return data
	}
	if v, ok := domaintemplate.Lookup(data, "brand.company_name"); ok && v != "" {
		return data
	}
	b, err := s.d.Branding.Branding(ctx, tenantID)
	if err != nil || strings.TrimSpace(b.CompanyName) == "" {
		return data
	}
	out := maps.Clone(data)
	brand, _ := out["brand"].(map[string]any)
	brand = maps.Clone(brand)
	if brand == nil {
		brand = map[string]any{}
	}
	brand["company_name"] = b.CompanyName
	out["brand"] = brand
	return out
}
