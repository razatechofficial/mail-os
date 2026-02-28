package analytics

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/domain"
)

type Service interface {
	RecordEvent(ctx context.Context, input RecordEventInput) error
	GetStats(ctx context.Context, orgID domain.OrganizationID, params StatsParams) ([]*domain.SendingStats, error)
	IncrementStats(ctx context.Context, orgID string, eventType domain.EventType) error
	FlushStats(ctx context.Context, stats []*domain.SendingStats) error
	GetAuditLogs(ctx context.Context, orgID domain.OrganizationID, params AuditLogParams) ([]*domain.AuditLog, int, error)
	CreateAuditLog(ctx context.Context, input AuditLogInput) error
}

type StatsRepository interface {
	Upsert(ctx context.Context, stats *domain.SendingStats) error
	FindByOrgAndPeriod(ctx context.Context, orgID domain.OrganizationID, params StatsParams) ([]*domain.SendingStats, error)
	BatchUpsert(ctx context.Context, stats []*domain.SendingStats) error
}

type AuditLogRepository interface {
	Create(ctx context.Context, log *domain.AuditLog) error
	FindAll(ctx context.Context, orgID domain.OrganizationID, params AuditLogParams) ([]*domain.AuditLog, int, error)
}

type MessageEventRepository interface {
	Create(ctx context.Context, event *domain.MessageEvent) error
	FindByMessageID(ctx context.Context, messageID domain.MessageID) ([]*domain.MessageEvent, error)
}
