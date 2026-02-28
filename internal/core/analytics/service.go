package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/id"
)

type service struct {
	stats       StatsRepository
	auditLogs   AuditLogRepository
	msgEvents   MessageEventRepository
}

func NewService(stats StatsRepository, auditLogs AuditLogRepository, events MessageEventRepository) Service {
	return &service{
		stats:     stats,
		auditLogs: auditLogs,
		msgEvents: events,
	}
}

func (s *service) RecordEvent(ctx context.Context, input RecordEventInput) error {
	event := &domain.MessageEvent{
		ID:        id.New(),
		MessageID: domain.MessageID(input.MessageID),
		OrgID:     domain.OrganizationID(input.OrgID),
		Type:      input.Type,
		Provider:  input.Provider,
		Metadata:  input.Metadata,
		CreatedAt: time.Now(),
	}
	if err := s.msgEvents.Create(ctx, event); err != nil {
		return fmt.Errorf("analytics.RecordEvent: %w", err)
	}
	return nil
}

func (s *service) GetStats(ctx context.Context, orgID domain.OrganizationID, params StatsParams) ([]*domain.SendingStats, error) {
	stats, err := s.stats.FindByOrgAndPeriod(ctx, orgID, params)
	if err != nil {
		return nil, fmt.Errorf("analytics.GetStats: %w", err)
	}
	return stats, nil
}

func (s *service) IncrementStats(ctx context.Context, orgID string, eventType domain.EventType) error {
	stats := &domain.SendingStats{
		OrgID:       domain.OrganizationID(orgID),
		PeriodType:  domain.PeriodTypeDaily,
		PeriodStart: time.Now().Truncate(24 * time.Hour),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	switch eventType {
	case domain.EventTypeSent:
		stats.Sent = 1
	case domain.EventTypeDelivered:
		stats.Delivered = 1
	case domain.EventTypeBounced:
		stats.Bounced = 1
	case domain.EventTypeComplained:
		stats.Complained = 1
	case domain.EventTypeOpened:
		stats.Opened = 1
	case domain.EventTypeClicked:
		stats.Clicked = 1
	default:
		stats.Failed = 1
	}
	if err := s.stats.Upsert(ctx, stats); err != nil {
		return fmt.Errorf("analytics.IncrementStats: %w", err)
	}
	return nil
}

func (s *service) FlushStats(ctx context.Context, stats []*domain.SendingStats) error {
	if err := s.stats.BatchUpsert(ctx, stats); err != nil {
		return fmt.Errorf("analytics.FlushStats: %w", err)
	}
	return nil
}

func (s *service) GetAuditLogs(ctx context.Context, orgID domain.OrganizationID, params AuditLogParams) ([]*domain.AuditLog, int, error) {
	logs, total, err := s.auditLogs.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("analytics.GetAuditLogs: %w", err)
	}
	return logs, total, nil
}

func (s *service) CreateAuditLog(ctx context.Context, input AuditLogInput) error {
	log := &domain.AuditLog{
		ID:         id.New(),
		OrgID:      domain.OrganizationID(input.OrgID),
		ActorType:  input.ActorType,
		ActorID:    input.ActorID,
		Action:     input.Action,
		Resource:   input.Resource,
		ResourceID: input.ResourceID,
		Changes:    input.Changes,
		IPAddress:  input.IPAddress,
		UserAgent:  input.UserAgent,
		CreatedAt:  time.Now(),
	}
	if err := s.auditLogs.Create(ctx, log); err != nil {
		return fmt.Errorf("analytics.CreateAuditLog: %w", err)
	}
	return nil
}
