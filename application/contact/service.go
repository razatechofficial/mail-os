// Package contact is the audience use case: a tenant's contacts, their
// import, and the static lists campaigns are sent to. Every change is
// audited in the same transaction as the change.
//
// Contacts are personal data: audit records and logs carry the masked
// address (logger.MaskEmail) and the names of the fields that changed,
// never their values.
package contact

import (
	"context"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/contact"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Filter narrows and pages a listing.
type Filter struct {
	// Status keeps one contact status ("" for all).
	Status domain.Status
	// Search matches the address or either name, case-insensitively.
	Search    string
	SortBy    string
	SortOrder string
	Limit     int
	Offset    int
}

// Repository stores contacts. Every method is scoped to the tenant: a
// contact of another tenant is domain.ErrNotFound.
type Repository interface {
	Get(ctx context.Context, tenant, id string) (domain.Contact, error)
	List(ctx context.Context, tenant string, f Filter) ([]domain.Contact, int, error)
	// Create fails with domain.ErrDuplicateEmail when the address exists.
	Create(ctx context.Context, c domain.Contact) error
	// CreateMany inserts the contacts, skipping addresses that exist, and
	// returns how many it created.
	CreateMany(ctx context.Context, cs []domain.Contact) (int, error)
	// Update fails with domain.ErrDuplicateEmail when the new address
	// belongs to another contact.
	Update(ctx context.Context, c domain.Contact) error
	// Delete removes the contact with its memberships and recipient rows.
	Delete(ctx context.Context, tenant, id string) error
}

// Auditor records changes.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Transactor runs fn in one database transaction.
type Transactor interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// Service is the audience use case.
type Service struct {
	contacts Repository
	lists    ListRepository
	tx       Transactor
	audit    Auditor
	now      func() time.Time
}

// NewService builds the service.
func NewService(contacts Repository, lists ListRepository, tx Transactor, audit Auditor) *Service {
	return &Service{contacts: contacts, lists: lists, tx: tx, audit: audit, now: func() time.Time { return time.Now().UTC() }}
}

// Get returns one of the tenant's contacts.
func (s *Service) Get(ctx context.Context, tenant, id string) (domain.Contact, error) {
	return s.contacts.Get(ctx, tenant, id)
}

// List returns one page of the tenant's contacts.
func (s *Service) List(ctx context.Context, tenant string, f Filter) ([]domain.Contact, int, error) {
	return s.contacts.List(ctx, tenant, f)
}

// Create validates, stores and audits a contact.
func (s *Service) Create(ctx context.Context, tenant string, c domain.Contact) (domain.Contact, error) {
	if err := c.Check(); err != nil {
		return domain.Contact{}, err
	}
	now := s.now()
	c.ID, c.OrgID, c.CreatedAt, c.UpdatedAt = id.New(), tenant, now, now
	err := s.tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.contacts.Create(ctx, c); err != nil {
			return err
		}
		return s.audit.Append(ctx, "contact", c.ID, "contact.created", map[string]any{"email": logger.MaskEmail(c.Email)})
	})
	if err != nil {
		return domain.Contact{}, err
	}
	return c, nil
}

// ImportResult is what an import did.
type ImportResult struct {
	Created int `json:"created_count"`
	// Skipped counts addresses that already exist or repeat in the batch.
	Skipped int `json:"skipped_count"`
}

// Import creates up to domain.MaxBatch contacts at once. The batch is
// validated whole (one invalid contact refuses it, with indexed field
// paths); addresses already in the audience are skipped, not updated.
// One contact.imported event records the counts.
func (s *Service) Import(ctx context.Context, tenant string, in []domain.Contact) (ImportResult, error) {
	cs, dup, err := domain.CheckBatch(in)
	if err != nil {
		return ImportResult{}, err
	}
	now := s.now()
	for i := range cs {
		cs[i].ID, cs[i].OrgID, cs[i].CreatedAt, cs[i].UpdatedAt = id.New(), tenant, now, now
	}
	var res ImportResult
	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		n, err := s.contacts.CreateMany(ctx, cs)
		if err != nil {
			return err
		}
		res = ImportResult{Created: n, Skipped: len(in) - n}
		return s.audit.Append(ctx, "contact", tenant, "contact.imported", map[string]any{
			"submitted": len(in), "created": res.Created, "skipped": res.Skipped, "duplicates_in_batch": dup})
	})
	return res, err
}

// Update is a partial update: nil fields keep their value.
type Update struct {
	Email     *string
	FirstName *string
	LastName  *string
	Status    *domain.Status
	Metadata  *map[string]any
}

// Update changes a contact and audits the names of the fields that changed.
func (s *Service) Update(ctx context.Context, tenant, contactID string, u Update) (domain.Contact, error) {
	var out domain.Contact
	err := s.tx.InTx(ctx, func(ctx context.Context) error {
		before, err := s.contacts.Get(ctx, tenant, contactID)
		if err != nil {
			return err
		}
		c := before
		if u.Email != nil {
			c.Email = *u.Email
		}
		if u.FirstName != nil {
			c.FirstName = *u.FirstName
		}
		if u.LastName != nil {
			c.LastName = *u.LastName
		}
		if u.Status != nil {
			c.Status = *u.Status
		}
		if u.Metadata != nil {
			c.Metadata = *u.Metadata
		}
		if err := c.Check(); err != nil {
			return err
		}
		changed := domain.Changes(before, c)
		if len(changed) == 0 {
			out = before
			return nil
		}
		c.UpdatedAt = s.now()
		if err := s.contacts.Update(ctx, c); err != nil {
			return err
		}
		out = c
		meta := map[string]any{"changed": changed, "email": logger.MaskEmail(c.Email)}
		if before.Status != c.Status {
			meta["status_before"], meta["status_after"] = string(before.Status), string(c.Status)
		}
		return s.audit.Append(ctx, "contact", c.ID, "contact.updated", meta)
	})
	return out, err
}

// Delete removes a contact (erasure: the row goes, not a tombstone).
func (s *Service) Delete(ctx context.Context, tenant, contactID string) error {
	return s.tx.InTx(ctx, func(ctx context.Context) error {
		c, err := s.contacts.Get(ctx, tenant, contactID)
		if err != nil {
			return err
		}
		if err := s.contacts.Delete(ctx, tenant, contactID); err != nil {
			return err
		}
		return s.audit.Append(ctx, "contact", contactID, "contact.deleted", map[string]any{"email": logger.MaskEmail(c.Email)})
	})
}
