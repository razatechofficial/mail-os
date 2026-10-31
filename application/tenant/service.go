// Package tenant provisions MailOS tenants on their first verified request
// and manages their security settings.
//
// IAM decides who may use MailOS (assignment to the MailOS application,
// access rules, a MailOS role in the token); a verified token for a tenant
// therefore means MailOS is enabled for it, and the local record is created
// just in time. An operator can still switch a tenant off locally.
package tenant

import (
	"context"
	"errors"
	"sync"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/tenant"
)

// Repository stores tenants and settings.
type Repository interface {
	Get(ctx context.Context, id string) (domain.Tenant, error)
	// Create inserts the tenant, doing nothing when it exists.
	Create(ctx context.Context, t domain.Tenant) error
	Settings(ctx context.Context, id string) (domain.Settings, error)
	SaveSettings(ctx context.Context, s domain.Settings) error
}

// Auditor records setting changes.
type Auditor interface {
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Service is the tenant use case.
type Service struct {
	repo  Repository
	audit Auditor
	ttl   time.Duration

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewService builds the service; ensured tenants are remembered for ttl.
func NewService(repo Repository, audit Auditor, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &Service{repo: repo, audit: audit, ttl: ttl, seen: map[string]time.Time{}}
}

// Ensure makes sure the tenant exists and is active.
func (s *Service) Ensure(ctx context.Context, id string) error {
	s.mu.Lock()
	at, ok := s.seen[id]
	s.mu.Unlock()
	if ok && time.Since(at) < s.ttl {
		return nil
	}
	t, err := s.repo.Get(ctx, id)
	if errors.Is(err, domain.ErrNotFound) {
		if err := s.repo.Create(ctx, domain.Tenant{ID: id, Name: id, Active: true, CreatedAt: time.Now().UTC()}); err != nil {
			return err
		}
		t, err = s.repo.Get(ctx, id)
	}
	if err != nil {
		return err
	}
	if !t.Active {
		return domain.ErrDisabled
	}
	s.mu.Lock()
	s.seen[id] = time.Now()
	s.mu.Unlock()
	return nil
}

// Settings returns the tenant's settings (defaults when none were saved).
func (s *Service) Settings(ctx context.Context, id string) (domain.Settings, error) {
	return s.repo.Settings(ctx, id)
}

// UpdateSettings validates, saves and audits a change.
func (s *Service) UpdateSettings(ctx context.Context, next domain.Settings, by string) (domain.Settings, error) {
	if err := next.Validate(); err != nil {
		return domain.Settings{}, err
	}
	before, err := s.repo.Settings(ctx, next.TenantID)
	if err != nil {
		return domain.Settings{}, err
	}
	next.UpdatedBy, next.UpdatedAt = by, time.Now().UTC()
	if err := s.repo.SaveSettings(ctx, next); err != nil {
		return domain.Settings{}, err
	}
	if err := s.audit.Change(ctx, "tenant_settings", next.TenantID, "tenant_settings.updated", before, next, nil); err != nil {
		return domain.Settings{}, err
	}
	return next, nil
}
