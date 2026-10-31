// Package suppression is the suppression list use case: operators add and
// remove addresses, the send path records hard bounces, and every send
// checks the list first.
package suppression

import (
	"context"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	domain "github.com/razatechofficial/mail-os/domain/suppression"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Repository stores suppressions.
type Repository interface {
	// Upsert adds s, or keeps the existing row for the address in s's
	// scope (tenant-wide, or s.ApplicationID).
	Upsert(ctx context.Context, s domain.Suppression) (domain.Suppression, error)
	// Delete removes the address from one scope; false when it was not
	// listed there.
	Delete(ctx context.Context, tenantID, applicationID, email string) (bool, error)
	// Find returns the address's tenant-wide entry and, with an
	// application, that application's entry.
	Find(ctx context.Context, tenantID, applicationID, email string) ([]domain.Suppression, error)
	// List returns a page, of one type and one application's scope when
	// set.
	List(ctx context.Context, f Filter) ([]domain.Suppression, int, error)
}

// Filter selects suppressions. ApplicationID "" lists every scope.
type Filter struct {
	TenantID      string
	Type          string
	ApplicationID string
	Limit         int
	Offset        int
}

// Auditor records list changes.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Service is the suppression use case.
type Service struct {
	repo  Repository
	audit Auditor
}

// NewService builds the service.
func NewService(repo Repository, audit Auditor) *Service { return &Service{repo: repo, audit: audit} }

// Add suppresses an address.
func (s *Service) Add(ctx context.Context, in domain.Suppression) (domain.Suppression, error) {
	in.Email = domain.NormalizeEmail(in.Email)
	if in.Source == "" {
		in.Source = domain.SourceManual
	}
	if err := in.Validate(); err != nil {
		return domain.Suppression{}, err
	}
	in.ID, in.CreatedAt = id.New(), time.Now().UTC()
	out, err := s.repo.Upsert(ctx, in)
	if err != nil {
		return domain.Suppression{}, err
	}
	if err := s.audit.Append(ctx, "suppression", out.ID, "suppression.added",
		map[string]any{"email": logger.MaskEmail(out.Email), "type": string(out.Type), "source": out.Source,
			"application_id": out.ApplicationID}); err != nil {
		return domain.Suppression{}, err
	}
	return out, nil
}

// Remove lifts a suppression from one scope (applicationID "" is the
// tenant-wide entry); removing an unlisted address is not an error.
func (s *Service) Remove(ctx context.Context, tenantID, applicationID, email string) error {
	email = domain.NormalizeEmail(email)
	removed, err := s.repo.Delete(ctx, tenantID, applicationID, email)
	if err != nil || !removed {
		return err
	}
	return s.audit.Append(ctx, "suppression", email, "suppression.removed",
		map[string]any{"email": logger.MaskEmail(email), "application_id": applicationID})
}

// List returns a page of suppressions.
func (s *Service) List(ctx context.Context, f Filter) ([]domain.Suppression, int, error) {
	return s.repo.List(ctx, f)
}

// Blocks reports whether the list stops a message of type mt to email
// from applicationID (empty for the tenant's own mail): a tenant-wide
// entry always applies, an application's entry to its own mail only.
func (s *Service) Blocks(ctx context.Context, tenantID, applicationID, email string, mt message.Type) (*domain.Suppression, error) {
	list, err := s.repo.Find(ctx, tenantID, applicationID, domain.NormalizeEmail(email))
	if err != nil {
		return nil, err
	}
	for _, sup := range list {
		if sup.Type.Blocks(mt) {
			return &sup, nil
		}
	}
	return nil, nil
}

// RecordBounce suppresses a recipient a provider refused.
func (s *Service) RecordBounce(ctx context.Context, tenantID, email, reason string) error {
	_, err := s.repo.Upsert(ctx, domain.Suppression{ID: id.New(), OrgID: tenantID, Email: domain.NormalizeEmail(email),
		Type: domain.TypeBounce, Reason: reason, Source: domain.SourceSend, CreatedAt: time.Now().UTC()})
	return err
}
