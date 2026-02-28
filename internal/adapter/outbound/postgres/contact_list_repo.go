package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/contactlist"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type contactListRepo struct {
	pool *pgxpool.Pool
}

var _ contactlist.Repository = (*contactListRepo)(nil)

func NewContactListRepo(pool *pgxpool.Pool) contactlist.Repository {
	return &contactListRepo{pool: pool}
}

func (r *contactListRepo) Create(ctx context.Context, cl *domain.ContactList) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO contact_lists (id, org_id, name, description, type, query, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, string(cl.ID), string(cl.OrgID), cl.Name, cl.Description, string(cl.Type), cl.Query, cl.CreatedAt, cl.UpdatedAt)
	return err
}

func (r *contactListRepo) FindByID(ctx context.Context, id domain.ContactListID) (*domain.ContactList, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, name, description, type, query, created_at, updated_at, deleted_at
		FROM contact_lists WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	cl, err := scanContactList(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return cl, nil
}

func (r *contactListRepo) Update(ctx context.Context, cl *domain.ContactList) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE contact_lists SET name = $2, description = $3, type = $4, query = $5, updated_at = $6
		WHERE id = $1 AND deleted_at IS NULL
	`, string(cl.ID), cl.Name, cl.Description, string(cl.Type), cl.Query, cl.UpdatedAt)
	return err
}

func (r *contactListRepo) SoftDelete(ctx context.Context, id domain.ContactListID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE contact_lists SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *contactListRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params contactlist.ListParams) ([]*domain.ContactList, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "name"}, "created_at")
	sortOrder := "ASC"
	if params.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset()

	var total int
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM contact_lists WHERE org_id = $1 AND deleted_at IS NULL`, string(orgID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `
		SELECT id, org_id, name, description, type, query, created_at, updated_at, deleted_at
		FROM contact_lists WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3
	`, string(orgID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var lists []*domain.ContactList
	for rows.Next() {
		cl, err := scanContactList(rows)
		if err != nil {
			return nil, 0, err
		}
		lists = append(lists, cl)
	}
	return lists, total, rows.Err()
}

func (r *contactListRepo) AddMembers(ctx context.Context, listID domain.ContactListID, contactIDs []domain.ContactID) error {
	if len(contactIDs) == 0 {
		return nil
	}
	q := QuerierFromContext(ctx, r.pool)
	now := time.Now()
	for _, cid := range contactIDs {
		_, err := q.Exec(ctx, `
			INSERT INTO contact_list_members (contact_list_id, contact_id, added_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (contact_list_id, contact_id) DO NOTHING
		`, string(listID), string(cid), now)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *contactListRepo) RemoveMembers(ctx context.Context, listID domain.ContactListID, contactIDs []domain.ContactID) error {
	if len(contactIDs) == 0 {
		return nil
	}
	q := QuerierFromContext(ctx, r.pool)
	for _, cid := range contactIDs {
		_, err := q.Exec(ctx, `DELETE FROM contact_list_members WHERE contact_list_id = $1 AND contact_id = $2`, string(listID), string(cid))
		if err != nil {
			return err
		}
	}
	return nil
}

var contactMemberSortColumns = map[string]string{
	"added_at":   "clm.added_at",
	"email":      "c.email",
	"first_name": "c.first_name",
	"last_name":  "c.last_name",
	"created_at": "c.created_at",
}

func (r *contactListRepo) FindMembers(ctx context.Context, listID domain.ContactListID, params contactlist.ListParams) ([]*domain.Contact, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := "clm.added_at"
	if col, ok := contactMemberSortColumns[params.SortBy]; ok {
		sortBy = col
	}
	sortOrder := "ASC"
	if params.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset()

	var total int
	err := q.QueryRow(ctx, `
		SELECT COUNT(*) FROM contact_list_members clm
		JOIN contacts c ON c.id = clm.contact_id AND c.deleted_at IS NULL
		WHERE clm.contact_list_id = $1
	`, string(listID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `
		SELECT c.id, c.org_id, c.email, c.first_name, c.last_name, c.metadata, c.status, c.created_at, c.updated_at, c.deleted_at
		FROM contact_list_members clm
		JOIN contacts c ON c.id = clm.contact_id AND c.deleted_at IS NULL
		WHERE clm.contact_list_id = $1
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3
	`, string(listID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var contacts []*domain.Contact
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, 0, err
		}
		contacts = append(contacts, c)
	}
	return contacts, total, rows.Err()
}

func scanContactList(row pgx.Row) (*domain.ContactList, error) {
	var id, orgID, name, description, listType, query string
	var createdAt, updatedAt time.Time
	var deletedAt *time.Time
	err := row.Scan(&id, &orgID, &name, &description, &listType, &query, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	return &domain.ContactList{
		ID:          domain.ContactListID(id),
		OrgID:       domain.OrganizationID(orgID),
		Name:        name,
		Description: description,
		Type:        domain.ListType(listType),
		Query:       query,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		DeletedAt:   deletedAt,
	}, nil
}

func scanContact(row pgx.Row) (*domain.Contact, error) {
	var id, orgID, email, firstName, lastName, status string
	var metadata []byte
	var createdAt, updatedAt time.Time
	var deletedAt *time.Time
	err := row.Scan(&id, &orgID, &email, &firstName, &lastName, &metadata, &status, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	var metadataMap map[string]any
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &metadataMap)
	}
	return &domain.Contact{
		ID:        domain.ContactID(id),
		OrgID:     domain.OrganizationID(orgID),
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Metadata:  metadataMap,
		Status:    domain.ContactStatus(status),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		DeletedAt: deletedAt,
	}, nil
}
