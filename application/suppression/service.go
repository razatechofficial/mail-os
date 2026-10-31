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
	// Upsert adds s, or keeps the existing row for the address.
	Upsert(ctx context.Context, s domain.Suppression) (domain.Suppression, error)
	// Delete removes the address; false when it was not listed.
	Delete(ctx context.Context, tenantID, email string) (bool, error)
	Find(ctx context.Context, tenantID, email string) (*domain.Suppression, error)
	List(ctx context.Context, tenantID, typ string, limit, offset int) ([]domain.Suppression, int, error)
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
		map[string]any{"email": logger.MaskEmail(out.Email), "type": string(out.Type), "source": out.Source}); err != nil {
		return domain.Suppression{}, err
	}
	return out, nil
}

// Remove lifts a suppression; removing an unlisted address is not an error.
func (s *Service) Remove(ctx context.Context, tenantID, email string) error {
	email = domain.NormalizeEmail(email)
	removed, err := s.repo.Delete(ctx, tenantID, email)
	if err != nil || !removed {
		return err
	}
	return s.audit.Append(ctx, "suppression", email, "suppression.removed", map[string]any{"email": logger.MaskEmail(email)})
}

// List returns a page of suppressions, optionally of one type.
func (s *Service) List(ctx context.Context, tenantID, typ string, limit, offset int) ([]domain.Suppression, int, error) {
	return s.repo.List(ctx, tenantID, typ, limit, offset)
}

// Blocks reports whether the tenant's list stops a message of type mt to
// email, and the suppression that does.
func (s *Service) Blocks(ctx context.Context, tenantID, email string, mt message.Type) (*domain.Suppression, error) {
	sup, err := s.repo.Find(ctx, tenantID, domain.NormalizeEmail(email))
	if err != nil || sup == nil || !sup.Type.Blocks(mt) {
		return nil, err
	}
	return sup, nil
}

// RecordBounce suppresses a recipient a provider refused.
func (s *Service) RecordBounce(ctx context.Context, tenantID, email, reason string) error {
	_, err := s.repo.Upsert(ctx, domain.Suppression{ID: id.New(), OrgID: tenantID, Email: domain.NormalizeEmail(email),
		Type: domain.TypeBounce, Reason: reason, Source: domain.SourceSend, CreatedAt: time.Now().UTC()})
	return err
}
