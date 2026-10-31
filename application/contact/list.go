package contact

import (
	"context"
	"strings"

	domain "github.com/razatechofficial/mail-os/domain/contact"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// ListRepository stores contact lists and their members, scoped to the
// tenant: a list of another tenant is domain.ErrListNotFound.
type ListRepository interface {
	GetList(ctx context.Context, tenant, id string) (domain.List, error)
	Lists(ctx context.Context, tenant string, limit, offset int) ([]domain.List, int, error)
	CreateList(ctx context.Context, l domain.List) error
	UpdateList(ctx context.Context, l domain.List) error
	// DeleteList removes the list and its memberships; campaigns that
	// named it keep no list.
	DeleteList(ctx context.Context, tenant, id string) error
	// InUse reports whether a scheduled, sending or paused campaign sends
	// to the list.
	InUse(ctx context.Context, tenant, id string) (bool, error)
	// MissingContacts returns the ids that are not contacts of the tenant.
	MissingContacts(ctx context.Context, tenant string, ids []string) ([]string, error)
	// AddMembers adds the contacts (already members are left alone) and
	// returns how many were added.
	AddMembers(ctx context.Context, tenant, listID string, ids []string) (int, error)
	RemoveMembers(ctx context.Context, tenant, listID string, ids []string) (int, error)
	Members(ctx context.Context, tenant, listID string, f Filter) ([]domain.Contact, int, error)
}

// GetList returns one of the tenant's lists.
func (s *Service) GetList(ctx context.Context, tenant, id string) (domain.List, error) {
	return s.lists.GetList(ctx, tenant, id)
}

// Lists returns one page of the tenant's lists.
func (s *Service) Lists(ctx context.Context, tenant string, limit, offset int) ([]domain.List, int, error) {
	return s.lists.Lists(ctx, tenant, limit, offset)
}

// CreateList validates, stores and audits a list.
func (s *Service) CreateList(ctx context.Context, tenant string, l domain.List) (domain.List, error) {
	if err := l.Check(); err != nil {
		return domain.List{}, err
	}
	now := s.now()
	l.ID, l.OrgID, l.CreatedAt, l.UpdatedAt = id.New(), tenant, now, now
	err := s.tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.lists.CreateList(ctx, l); err != nil {
			return err
		}
		return s.audit.Change(ctx, "contact_list", l.ID, "contact_list.created", nil, l, nil)
	})
	if err != nil {
		return domain.List{}, err
	}
	return l, nil
}

// ListUpdate is a partial update: nil fields keep their value.
type ListUpdate struct {
	Name        *string
	Description *string
	Type        *domain.ListType
	Query       *string
}

// UpdateList changes a list and audits before and after.
func (s *Service) UpdateList(ctx context.Context, tenant, listID string, u ListUpdate) (domain.List, error) {
	var out domain.List
	err := s.tx.InTx(ctx, func(ctx context.Context) error {
		before, err := s.lists.GetList(ctx, tenant, listID)
		if err != nil {
			return err
		}
		l := before
		if u.Name != nil {
			l.Name = *u.Name
		}
		if u.Description != nil {
			l.Description = *u.Description
		}
		if u.Type != nil {
			l.Type = *u.Type
		}
		if u.Query != nil {
			l.Query = *u.Query
		}
		if err := l.Check(); err != nil {
			return err
		}
		l.UpdatedAt = s.now()
		if err := s.lists.UpdateList(ctx, l); err != nil {
			return err
		}
		out = l
		return s.audit.Change(ctx, "contact_list", l.ID, "contact_list.updated", before, l, nil)
	})
	return out, err
}

// DeleteList removes a list no live campaign sends to.
func (s *Service) DeleteList(ctx context.Context, tenant, listID string) error {
	return s.tx.InTx(ctx, func(ctx context.Context) error {
		l, err := s.lists.GetList(ctx, tenant, listID)
		if err != nil {
			return err
		}
		inUse, err := s.lists.InUse(ctx, tenant, listID)
		if err != nil {
			return err
		}
		if inUse {
			return apperrors.Conflict("a scheduled, sending or paused campaign sends to this list; cancel it first")
		}
		if err := s.lists.DeleteList(ctx, tenant, listID); err != nil {
			return err
		}
		return s.audit.Change(ctx, "contact_list", listID, "contact_list.deleted", l, nil, nil)
	})
}

// AddMembers adds contacts to a list. Every id must be one of the
// tenant's contacts, or nothing is added (422 naming the unknown ids).
func (s *Service) AddMembers(ctx context.Context, tenant, listID string, contactIDs []string) (int, error) {
	ids, err := domain.CheckMembers(contactIDs)
	if err != nil {
		return 0, err
	}
	var added int
	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.lists.GetList(ctx, tenant, listID); err != nil {
			return err
		}
		missing, err := s.lists.MissingContacts(ctx, tenant, ids)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			return apperrors.Invalid("contact_ids", "not_found", "unknown contacts: "+strings.Join(truncate(missing, 10), ", "))
		}
		if added, err = s.lists.AddMembers(ctx, tenant, listID, ids); err != nil {
			return err
		}
		return s.audit.Append(ctx, "contact_list", listID, "contact_list.members_added", map[string]any{"requested": len(ids), "added": added})
	})
	return added, err
}

// RemoveMembers removes contacts from a list; ids that are not members
// are ignored.
func (s *Service) RemoveMembers(ctx context.Context, tenant, listID string, contactIDs []string) (int, error) {
	ids, err := domain.CheckMembers(contactIDs)
	if err != nil {
		return 0, err
	}
	var removed int
	err = s.tx.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.lists.GetList(ctx, tenant, listID); err != nil {
			return err
		}
		if removed, err = s.lists.RemoveMembers(ctx, tenant, listID, ids); err != nil {
			return err
		}
		return s.audit.Append(ctx, "contact_list", listID, "contact_list.members_removed", map[string]any{"requested": len(ids), "removed": removed})
	})
	return removed, err
}

// Members returns one page of a list's contacts.
func (s *Service) Members(ctx context.Context, tenant, listID string, f Filter) ([]domain.Contact, int, error) {
	if _, err := s.lists.GetList(ctx, tenant, listID); err != nil {
		return nil, 0, err
	}
	return s.lists.Members(ctx, tenant, listID, f)
}

func truncate(xs []string, n int) []string {
	if len(xs) > n {
		return append(xs[:n:n], "…")
	}
	return xs
}
