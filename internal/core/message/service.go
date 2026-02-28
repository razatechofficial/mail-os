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
)

const messageProcessTopic = "messages.process"

type service struct {
	repo        Repository
	suppressions port.SuppressionChecker
	quotas      port.QuotaChecker
	renderer    port.TemplateRenderer
	publisher   port.Publisher
	txManager   port.TxManager
	events      port.EventPublisher
}

func NewService(
	repo Repository,
	suppressions port.SuppressionChecker,
	quotas port.QuotaChecker,
	renderer port.TemplateRenderer,
	publisher port.Publisher,
	txManager port.TxManager,
	events port.EventPublisher,
) Service {
	return &service{
		repo:        repo,
		suppressions: suppressions,
		quotas:      quotas,
		renderer:    renderer,
		publisher:   publisher,
		txManager:   txManager,
		events:      events,
	}
}

type messageCreatedEvent struct {
	msg *domain.Message
}

func (e *messageCreatedEvent) EventType() string { return "message.created" }
func (e *messageCreatedEvent) OccurredAt() time.Time { return e.msg.CreatedAt }

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
		Subject:        input.Subject,
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
	results := make([]SendEmailOutput, 0, len(input.Messages))
	for _, m := range input.Messages {
		m.OrgID = input.OrgID
		out, err := s.Send(ctx, m)
		if err != nil {
			results = append(results, SendEmailOutput{})
			continue
		}
		results = append(results, *out)
	}
	success := 0
	for _, r := range results {
		if r.MessageID != "" {
			success++
		}
	}
	return &BatchSendOutput{Results: results, SuccessCount: success, FailCount: len(results) - success}, nil
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
