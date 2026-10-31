// Package auditlog reads a tenant's audit log for the console. Each read
// and export is itself audited (PCI DSS 10.2.1.3).
package auditlog

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Store lists events.
type Store interface {
	List(ctx context.Context, f postgres.AuditFilter) ([]audit.Event, int, error)
}

// Auditor records the read.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Service is the audit log reader.
type Service struct {
	store Store
	audit Auditor
}

// NewService builds the service.
func NewService(store Store, audit Auditor) *Service { return &Service{store: store, audit: audit} }

// Query is a console filter.
type Query struct {
	Tenant       string
	ResourceType string
	ResourceID   string
	Action       string
	From, To     *time.Time
}

// MaxExport caps one export.
const MaxExport = 10000

// List returns one page and records audit_log.viewed.
func (s *Service) List(ctx context.Context, q Query, limit, offset int) ([]audit.Event, int, error) {
	f, err := filter(q)
	if err != nil {
		return nil, 0, err
	}
	f.Limit, f.Offset = limit, offset
	events, total, err := s.store.List(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	if err := s.audit.Append(ctx, "audit_log", q.Tenant, "audit_log.viewed", meta(q, len(events))); err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

// Export returns every matching event (up to MaxExport) and records
// audit_log.exported before handing them out.
func (s *Service) Export(ctx context.Context, q Query) ([]audit.Event, error) {
	f, err := filter(q)
	if err != nil {
		return nil, err
	}
	f.Limit = MaxExport
	events, _, err := s.store.List(ctx, f)
	if err != nil {
		return nil, err
	}
	if err := s.audit.Append(ctx, "audit_log", q.Tenant, "audit_log.exported", meta(q, len(events))); err != nil {
		return nil, err
	}
	return events, nil
}

func filter(q Query) (postgres.AuditFilter, error) {
	id, err := uuid.Parse(q.Tenant)
	if err != nil {
		return postgres.AuditFilter{}, apperrors.ErrForbidden
	}
	if q.From != nil && q.To != nil && q.To.Before(*q.From) {
		return postgres.AuditFilter{}, apperrors.Invalid("to", "invalid", "to must not be before from")
	}
	return postgres.AuditFilter{TenantUUID: id, ResourceType: q.ResourceType, ResourceID: q.ResourceID, Action: q.Action, From: q.From, To: q.To}, nil
}

func meta(q Query, rows int) map[string]any {
	m := map[string]any{"rows": rows}
	if q.ResourceType != "" {
		m["resource"] = q.ResourceType
	}
	if q.Action != "" {
		m["action_filter"] = q.Action
	}
	if q.From != nil {
		m["from"] = q.From.Format(time.RFC3339)
	}
	if q.To != nil {
		m["to"] = q.To.Format(time.RFC3339)
	}
	return m
}
