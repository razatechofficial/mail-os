package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/contact"
	domain "github.com/razatechofficial/mail-os/domain/contact"
)

// ContactRepository maps contacts onto the contacts table. Contacts are
// deleted outright (personal data); the deleted_at predicate stays in the
// queries because the table's indexes are partial on it.
type ContactRepository struct {
	db *Pool
}

var _ app.Repository = (*ContactRepository)(nil)

// NewContactRepository returns the repository.
func NewContactRepository(db *Pool) *ContactRepository { return &ContactRepository{db: db} }

const contactColumns = `c.id, c.org_id, c.email, COALESCE(c.first_name, ''), COALESCE(c.last_name, ''),
	COALESCE(c.metadata, '{}'::jsonb), c.status, c.created_at, c.updated_at`

func scanContact(row pgx.Row) (domain.Contact, error) {
	var c domain.Contact
	err := row.Scan(&c.ID, &c.OrgID, &c.Email, &c.FirstName, &c.LastName, &c.Metadata, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func collectContacts(rows pgx.Rows) ([]domain.Contact, error) {
	defer rows.Close()
	out := []domain.Contact{}
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get reads one of the tenant's contacts.
func (r *ContactRepository) Get(ctx context.Context, tenant, id string) (domain.Contact, error) {
	c, err := scanContact(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+contactColumns+` FROM contacts c WHERE c.id = $1 AND c.org_id = $2 AND c.deleted_at IS NULL`, id, tenant))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Contact{}, domain.ErrNotFound
	}
	return c, err
}

// contactSortColumns are the sort_by values a listing accepts.
var contactSortColumns = map[string]string{
	"created_at": "c.created_at", "updated_at": "c.updated_at", "email": "c.email",
	"first_name": "c.first_name", "last_name": "c.last_name",
}

// contactOrder is an ORDER BY from an allow-listed column, with the id as
// tie-break so pages do not overlap.
func contactOrder(columns map[string]string, sortBy, sortOrder, def string) string {
	col, ok := columns[sortBy]
	if !ok {
		col = def
	}
	dir := "DESC"
	if strings.EqualFold(sortOrder, "asc") {
		dir = "ASC"
	}
	return " ORDER BY " + col + " " + dir + ", c.id " + dir
}

// contactFilter appends the status and search predicates to where.
func contactFilter(f app.Filter, where string, args []any) (string, []any) {
	if f.Status != "" {
		args = append(args, string(f.Status))
		where += " AND c.status = $" + strconv.Itoa(len(args))
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		args = append(args, "%"+strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)+"%")
		n := "$" + strconv.Itoa(len(args))
		where += " AND (c.email ILIKE " + n + " OR c.first_name ILIKE " + n + " OR c.last_name ILIKE " + n + ")"
	}
	return where, args
}

// page runs a count and a page of a contact query.
func (r *ContactRepository) page(ctx context.Context, from, where string, args []any, f app.Filter, sorts map[string]string, defaultSort string) ([]domain.Contact, int, error) {
	q := QuerierFromContext(ctx, r.db)
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM `+from+` WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := q.Query(ctx, `SELECT `+contactColumns+` FROM `+from+` WHERE `+where+
		contactOrder(sorts, f.SortBy, f.SortOrder, defaultSort)+
		` LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := collectContacts(rows)
	return out, total, err
}

// List returns a page of the tenant's contacts, newest first by default.
func (r *ContactRepository) List(ctx context.Context, tenant string, f app.Filter) ([]domain.Contact, int, error) {
	where, args := contactFilter(f, "c.org_id = $1 AND c.deleted_at IS NULL", []any{tenant})
	return r.page(ctx, "contacts c", where, args, f, contactSortColumns, "c.created_at")
}

// Create inserts a contact.
func (r *ContactRepository) Create(ctx context.Context, c domain.Contact) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO contacts (id, org_id, email, first_name, last_name, metadata, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.OrgID, c.Email, c.FirstName, c.LastName, c.Metadata, string(c.Status), c.CreatedAt, c.UpdatedAt)
	if IsUniqueViolation(err) {
		return domain.ErrDuplicateEmail
	}
	return err
}

// CreateMany inserts contacts in one statement, skipping addresses the
// tenant already has.
func (r *ContactRepository) CreateMany(ctx context.Context, cs []domain.Contact) (int, error) {
	if len(cs) == 0 {
		return 0, nil
	}
	ids, orgs, emails, firsts, lasts, statuses := make([]string, len(cs)), make([]string, len(cs)), make([]string, len(cs)),
		make([]string, len(cs)), make([]string, len(cs)), make([]string, len(cs))
	metas := make([]string, len(cs))
	for i, c := range cs {
		meta, err := json.Marshal(c.Metadata)
		if err != nil {
			return 0, err
		}
		ids[i], orgs[i], emails[i], firsts[i], lasts[i], statuses[i], metas[i] = c.ID, c.OrgID, c.Email, c.FirstName, c.LastName, string(c.Status), string(meta)
	}
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO contacts (id, org_id, email, first_name, last_name, metadata, status, created_at, updated_at)
		SELECT u.id, u.org_id, u.email, u.first_name, u.last_name, u.metadata::jsonb, u.status, $8, $8
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
			AS u(id, org_id, email, first_name, last_name, metadata, status)
		ON CONFLICT (org_id, email) WHERE deleted_at IS NULL DO NOTHING`,
		ids, orgs, emails, firsts, lasts, metas, statuses, cs[0].CreatedAt)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// Update saves a contact's fields.
func (r *ContactRepository) Update(ctx context.Context, c domain.Contact) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE contacts SET email = $3, first_name = $4, last_name = $5, metadata = $6, status = $7, updated_at = $8
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
		c.ID, c.OrgID, c.Email, c.FirstName, c.LastName, c.Metadata, string(c.Status), c.UpdatedAt)
	if IsUniqueViolation(err) {
		return domain.ErrDuplicateEmail
	}
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return err
}

// Delete removes the contact; its memberships and recipient rows go with
// it (ON DELETE CASCADE).
func (r *ContactRepository) Delete(ctx context.Context, tenant, id string) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `DELETE FROM contacts WHERE id = $1 AND org_id = $2`, id, tenant)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return err
}
