package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/contact"
	domain "github.com/razatechofficial/mail-os/domain/contact"
)

// ContactListRepository maps contact lists onto contact_lists and
// contact_list_members. Every query names the tenant, so a list or contact
// of another tenant is never read or joined.
type ContactListRepository struct {
	contacts *ContactRepository
}

var _ app.ListRepository = (*ContactListRepository)(nil)

// NewContactListRepository returns the repository.
func NewContactListRepository(db *Pool) *ContactListRepository {
	return &ContactListRepository{contacts: NewContactRepository(db)}
}

func (r *ContactListRepository) q(ctx context.Context) Querier {
	return QuerierFromContext(ctx, r.contacts.db)
}

const listColumns = `id, org_id, name, COALESCE(description, ''), type, COALESCE(query, ''), created_at, updated_at`

func scanList(row pgx.Row) (domain.List, error) {
	var l domain.List
	err := row.Scan(&l.ID, &l.OrgID, &l.Name, &l.Description, &l.Type, &l.Query, &l.CreatedAt, &l.UpdatedAt)
	return l, err
}

// GetList reads one of the tenant's lists.
func (r *ContactListRepository) GetList(ctx context.Context, tenant, id string) (domain.List, error) {
	l, err := scanList(r.q(ctx).QueryRow(ctx,
		`SELECT `+listColumns+` FROM contact_lists WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenant))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.List{}, domain.ErrListNotFound
	}
	return l, err
}

// Lists returns a page of the tenant's lists, newest first.
func (r *ContactListRepository) Lists(ctx context.Context, tenant string, limit, offset int) ([]domain.List, int, error) {
	var total int
	if err := r.q(ctx).QueryRow(ctx, `SELECT count(*) FROM contact_lists WHERE org_id = $1 AND deleted_at IS NULL`, tenant).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.q(ctx).Query(ctx, `SELECT `+listColumns+` FROM contact_lists WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, tenant, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []domain.List{}
	for rows.Next() {
		l, err := scanList(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

// CreateList inserts a list.
func (r *ContactListRepository) CreateList(ctx context.Context, l domain.List) error {
	_, err := r.q(ctx).Exec(ctx, `
		INSERT INTO contact_lists (id, org_id, name, description, type, query, created_at, updated_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, NULLIF($6, ''), $7, $8)`,
		l.ID, l.OrgID, l.Name, l.Description, string(l.Type), l.Query, l.CreatedAt, l.UpdatedAt)
	return err
}

// UpdateList saves a list's fields.
func (r *ContactListRepository) UpdateList(ctx context.Context, l domain.List) error {
	tag, err := r.q(ctx).Exec(ctx, `
		UPDATE contact_lists SET name = $3, description = NULLIF($4, ''), type = $5, query = NULLIF($6, ''), updated_at = $7
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
		l.ID, l.OrgID, l.Name, l.Description, string(l.Type), l.Query, l.UpdatedAt)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrListNotFound
	}
	return err
}

// DeleteList removes the list; members go with it (ON DELETE CASCADE) and
// campaigns that named it keep no list (ON DELETE SET NULL).
func (r *ContactListRepository) DeleteList(ctx context.Context, tenant, id string) error {
	tag, err := r.q(ctx).Exec(ctx, `DELETE FROM contact_lists WHERE id = $1 AND org_id = $2`, id, tenant)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrListNotFound
	}
	return err
}

// InUse reports whether a scheduled, sending or paused campaign sends to
// the list.
func (r *ContactListRepository) InUse(ctx context.Context, tenant, id string) (bool, error) {
	var used bool
	err := r.q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM campaigns WHERE org_id = $1 AND contact_list_id = $2
		AND status IN ('scheduled', 'sending', 'paused') AND deleted_at IS NULL)`, tenant, id).Scan(&used)
	return used, err
}

// MissingContacts returns the ids that are not contacts of the tenant.
func (r *ContactListRepository) MissingContacts(ctx context.Context, tenant string, ids []string) ([]string, error) {
	rows, err := r.q(ctx).Query(ctx, `
		SELECT t.id FROM unnest($2::text[]) WITH ORDINALITY AS t(id, n)
		WHERE NOT EXISTS (SELECT 1 FROM contacts c WHERE c.id = t.id AND c.org_id = $1 AND c.deleted_at IS NULL)
		ORDER BY t.n`, tenant, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// AddMembers adds the tenant's contacts to the list; existing members and
// ids that are not the tenant's contacts are skipped.
func (r *ContactListRepository) AddMembers(ctx context.Context, tenant, listID string, ids []string) (int, error) {
	tag, err := r.q(ctx).Exec(ctx, `
		INSERT INTO contact_list_members (contact_list_id, contact_id, added_at)
		SELECT l.id, c.id, now() FROM contact_lists l
		JOIN contacts c ON c.org_id = l.org_id AND c.id = ANY($3::text[]) AND c.deleted_at IS NULL
		WHERE l.id = $1 AND l.org_id = $2 AND l.deleted_at IS NULL
		ON CONFLICT DO NOTHING`, listID, tenant, ids)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// RemoveMembers removes contacts from the tenant's list.
func (r *ContactListRepository) RemoveMembers(ctx context.Context, tenant, listID string, ids []string) (int, error) {
	tag, err := r.q(ctx).Exec(ctx, `
		DELETE FROM contact_list_members m USING contact_lists l
		WHERE m.contact_list_id = l.id AND l.id = $1 AND l.org_id = $2 AND m.contact_id = ANY($3::text[])`, listID, tenant, ids)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// memberSortColumns add the membership time to the contact sorts.
var memberSortColumns = map[string]string{
	"added_at": "m.added_at", "created_at": "c.created_at", "updated_at": "c.updated_at", "email": "c.email",
	"first_name": "c.first_name", "last_name": "c.last_name",
}

// Members returns a page of the list's contacts, most recently added first
// by default.
func (r *ContactListRepository) Members(ctx context.Context, tenant, listID string, f app.Filter) ([]domain.Contact, int, error) {
	where, args := contactFilter(f, "m.contact_list_id = $1 AND c.org_id = $2 AND c.deleted_at IS NULL", []any{listID, tenant})
	return r.contacts.page(ctx, "contact_list_members m JOIN contacts c ON c.id = m.contact_id", where, args, f, memberSortColumns, "m.added_at")
}
