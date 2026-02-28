package message

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	Send(ctx context.Context, input SendEmailInput) (*SendEmailOutput, error)
	BatchSend(ctx context.Context, input BatchSendInput) (*BatchSendOutput, error)
	Schedule(ctx context.Context, input ScheduleEmailInput) (*SendEmailOutput, error)
	Process(ctx context.Context, input ProcessEmailInput) error
	GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.MessageID) (*domain.Message, error)
	List(ctx context.Context, params MessageListParams) ([]*domain.Message, int, error)
	Cancel(ctx context.Context, orgID domain.OrganizationID, id domain.MessageID) error
	UpdateStatus(ctx context.Context, id domain.MessageID, status domain.MessageStatus) error
	EnqueueCampaignEmail(ctx context.Context, orgID string, campaignID string, contactEmail string) error
}

type Repository interface {
	Create(ctx context.Context, msg *domain.Message) error
	FindByID(ctx context.Context, id domain.MessageID) (*domain.Message, error)
	FindAll(ctx context.Context, params MessageListParams) ([]*domain.Message, int, error)
	UpdateStatus(ctx context.Context, id domain.MessageID, status domain.MessageStatus, fields map[string]any) error
	FindByIdempotencyKey(ctx context.Context, orgID domain.OrganizationID, key string) (*domain.Message, error)
}
