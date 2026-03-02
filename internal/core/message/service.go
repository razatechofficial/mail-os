package message

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
	"golang.org/x/sync/errgroup"

	tmpl "github.com/razatechofficial/mail-os/internal/core/template"
)

const (
	messageProcessTopic  = "messages.process"
	defaultBatchConcur   = 20 // max concurrent Send() calls per batch when not configured
)

type service struct {
	repo                Repository
	suppressions        port.SuppressionChecker
	quotas              port.QuotaChecker
	renderer            port.TemplateRenderer
	templateSvc         tmpl.Service
	publisher           port.Publisher
	txManager           port.TxManager
	events              port.EventPublisher
	batchSendConcur     int
}

func NewService(
	repo Repository,
	suppressions port.SuppressionChecker,
	quotas port.QuotaChecker,
	renderer port.TemplateRenderer,
	templateSvc tmpl.Service,
	publisher port.Publisher,
	txManager port.TxManager,
	events port.EventPublisher,
	batchSendConcurrency int,
) Service {
	concur := batchSendConcurrency
	if concur < 1 {
		concur = defaultBatchConcur
	}
	return &service{
		repo:            repo,
		suppressions:    suppressions,
		quotas:          quotas,
		renderer:        renderer,
		templateSvc:     templateSvc,
		publisher:       publisher,
		txManager:      txManager,
		events:         events,
		batchSendConcur: concur,
	}
}

type messageCreatedEvent struct {
	msg *domain.Message
}

func (e *messageCreatedEvent) EventType() string   { return "message.created" }
func (e *messageCreatedEvent) OccurredAt() time.Time { return e.msg.CreatedAt }
func (e *messageCreatedEvent) OrgID() string       { return string(e.msg.OrgID) }

func (s *service) Send(ctx context.Context, input SendEmailInput) (*SendEmailOutput, error) {
	if input.IdempotencyKey != "" {
		existing, err := s.repo.FindByIdempotencyKey(ctx, domain.OrganizationID(input.OrgID), input.IdempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("message.Send: %w", err)
		}
		if existing != nil {
			return &SendEmailOutput{MessageID: string(existing.ID), Status: string(existing.Status)}, nil
		}
	}

	suppressed, err := s.suppressions.IsEmailSuppressed(ctx, input.OrgID, input.ToEmail)
	if err != nil {
		return nil, fmt.Errorf("message.Send: %w", err)
	}
	if suppressed {
		return nil, errors.NewBadRequest("email is suppressed")
	}

	htmlBody, textBody := input.HTMLBody, input.TextBody
	subject := input.Subject

	if input.TemplateSlug == "" {
		if subject == "" {
			return nil, errors.NewBadRequest("subject is required when not using a template")
		}
		if htmlBody == "" && textBody == "" {
			return nil, errors.NewBadRequest("html_body, text_body, or template_slug is required")
		}
	}

	if input.TemplateSlug != "" {
		tpl, err := s.templateSvc.GetBySlug(ctx, domain.OrganizationID(input.OrgID), input.TemplateSlug)
		if err != nil {
			return nil, fmt.Errorf("message.Send: template not found: %w", err)
		}
		version, err := s.templateSvc.GetActiveVersion(ctx, tpl.ID)
		if err != nil {
			return nil, fmt.Errorf("message.Send: no active template version: %w", err)
		}
		vars := input.TemplateVars
		if vars == nil {
			vars = map[string]any{}
		}
		htmlRendered, textRendered, err := s.renderer.Render(ctx, version.HTMLBody, vars)
		if err != nil {
			return nil, fmt.Errorf("message.Send: template render failed: %w", err)
		}
		htmlBody = htmlRendered
		if version.TextBody != "" {
			_, textRendered, err = s.renderer.Render(ctx, version.TextBody, vars)
			if err == nil {
				textBody = textRendered
			}
		} else {
			textBody = textRendered
		}
		if subject == "" {
			subject = version.Subject
		}
	}

	priority := domain.MessagePriority(input.Priority)
	if priority == 0 {
		priority = domain.MessagePriorityNormal
	}

	msg := &domain.Message{
		ID:             domain.MessageID(id.New()),
		OrgID:          domain.OrganizationID(input.OrgID),
		CampaignID:     "",
		ProviderID:     "",
		FromName:       input.FromName,
		FromEmail:      input.FromEmail,
		ToEmail:        input.ToEmail,
		ToName:         input.ToName,
		Subject:        subject,
		HTMLBody:       htmlBody,
		TextBody:       textBody,
		Type:           domain.MessageTypeTransactional,
		Status:         domain.MessageStatusQueued,
		Priority:       priority,
		Tags:           input.Tags,
		Metadata:       input.Metadata,
		IdempotencyKey: input.IdempotencyKey,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	err = s.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		if err := s.repo.Create(txCtx, msg); err != nil {
			return err
		}
		return s.quotas.CheckAndIncrement(txCtx, input.OrgID)
	})
	if err != nil {
		return nil, fmt.Errorf("message.Send: %w", err)
	}

	payload, _ := json.Marshal(ProcessEmailInput{MessageID: string(msg.ID)})
	if err := s.publisher.Publish(ctx, messageProcessTopic, payload, port.WithPriority(int(priority))); err != nil {
		return nil, fmt.Errorf("message.Send: %w", err)
	}

	if s.events != nil {
		_ = s.events.Publish(ctx, &messageCreatedEvent{msg: msg})
	}

	return &SendEmailOutput{MessageID: string(msg.ID), Status: string(msg.Status)}, nil
}

func (s *service) BatchSend(ctx context.Context, input BatchSendInput) (*BatchSendOutput, error) {
	n := len(input.Messages)
	if n == 0 {
		return &BatchSendOutput{Results: []SendEmailOutput{}, SuccessCount: 0, FailCount: 0}, nil
	}
	results := make([]SendEmailOutput, n)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.batchSendConcur)
	for i, m := range input.Messages {
		i, m := i, m
		m.OrgID = input.OrgID
		g.Go(func() error {
			out, err := s.Send(gctx, m)
			if err != nil {
				results[i] = SendEmailOutput{}
				return nil // collect all; don't cancel on first error
			}
			results[i] = *out
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("message.BatchSend: %w", err)
	}
	success := 0
	for _, r := range results {
		if r.MessageID != "" {
			success++
		}
	}
	return &BatchSendOutput{Results: results, SuccessCount: success, FailCount: n - success}, nil
}

func (s *service) Schedule(ctx context.Context, input ScheduleEmailInput) (*SendEmailOutput, error) {
	priority := domain.MessagePriority(input.Priority)
	if priority == 0 {
		priority = domain.MessagePriorityNormal
	}

	msg := &domain.Message{
		ID:         domain.MessageID(id.New()),
		OrgID:      domain.OrganizationID(input.OrgID),
		CampaignID: "",
		ProviderID: "",
		FromName:    input.FromName,
		FromEmail:   input.FromEmail,
		ToEmail:     input.ToEmail,
		ToName:      input.ToName,
		Subject:     input.Subject,
		HTMLBody:    input.HTMLBody,
		TextBody:    input.TextBody,
		Type:        domain.MessageTypeTransactional,
		Status:      domain.MessageStatusScheduled,
		Priority:    priority,
		Tags:        input.Tags,
		Metadata:    input.Metadata,
		ScheduledAt: &input.ScheduleAt,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.Create(ctx, msg); err != nil {
		return nil, fmt.Errorf("message.Schedule: %w", err)
	}

	payload, _ := json.Marshal(ProcessEmailInput{MessageID: string(msg.ID)})
	delay := time.Until(input.ScheduleAt)
	if delay < 0 {
		delay = 0
	}
	if err := s.publisher.Publish(ctx, messageProcessTopic, payload, port.WithDelay(delay), port.WithPriority(int(priority))); err != nil {
		return nil, fmt.Errorf("message.Schedule: %w", err)
	}

	return &SendEmailOutput{MessageID: string(msg.ID), Status: string(msg.Status)}, nil
}

func (s *service) Process(ctx context.Context, input ProcessEmailInput) error {
	return nil
}

func (s *service) GetByIDForProcessing(ctx context.Context, id domain.MessageID) (*domain.Message, error) {
	return s.repo.FindByID(ctx, id)
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.MessageID) (*domain.Message, error) {
	msg, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("message.GetByID: %w", err)
	}
	if msg.OrgID != orgID {
		return nil, errors.ErrNotFound
	}
	return msg, nil
}

func (s *service) ListScheduledDue(ctx context.Context, limit int) ([]*domain.Message, error) {
	return s.repo.FindScheduledDue(ctx, limit)
}

func (s *service) List(ctx context.Context, params MessageListParams) ([]*domain.Message, int, error) {
	msgs, total, err := s.repo.FindAll(ctx, params)
	if err != nil {
		return nil, 0, fmt.Errorf("message.List: %w", err)
	}
	return msgs, total, nil
}

func (s *service) Cancel(ctx context.Context, orgID domain.OrganizationID, id domain.MessageID) error {
	msg, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("message.Cancel: %w", err)
	}
	if msg.OrgID != orgID {
		return errors.ErrNotFound
	}
	if msg.Status != domain.MessageStatusScheduled && msg.Status != domain.MessageStatusQueued {
		return errors.NewBadRequest("can only cancel scheduled or queued messages")
	}
	return s.repo.UpdateStatus(ctx, id, domain.MessageStatusRejected, map[string]any{"updated_at": time.Now()})
}

func (s *service) UpdateStatus(ctx context.Context, id domain.MessageID, status domain.MessageStatus) error {
	return s.repo.UpdateStatus(ctx, id, status, map[string]any{"updated_at": time.Now()})
}

func (s *service) EnqueueCampaignEmail(ctx context.Context, orgID string, campaignID string, contactEmail string) error {
	payload, _ := json.Marshal(map[string]string{
		"org_id":        orgID,
		"campaign_id":   campaignID,
		"contact_email": contactEmail,
	})
	return s.publisher.Publish(ctx, "campaign.send", payload)
}
