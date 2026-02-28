package postgres

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/contact"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type contactRepo struct {
	pool *pgxpool.Pool
}

var _ contact.Repository = (*contactRepo)(nil)

func NewContactRepo(pool *pgxpool.Pool) contact.Repository {
	return &contactRepo{pool: pool}
}

func (r *contactRepo) Create(ctx context.Context, c *domain.Contact) error {
	q := QuerierFromContext(ctx, r.pool)
	metadata, _ := json.Marshal(c.Metadata)
	_, err := q.Exec(ctx, `
		INSERT INTO contacts (id, org_id, email, first_name, last_name, metadata, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, string(c.ID), string(c.OrgID), c.Email, c.FirstName, c.LastName, metadata, string(c.Status), c.CreatedAt, c.UpdatedAt)
	return err
}

func (r *contactRepo) FindByID(ctx context.Context, id domain.ContactID) (*domain.Contact, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, email, first_name, last_name, metadata, status, created_at, updated_at, deleted_at
		FROM contacts WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	c, err := scanContact(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

func (r *contactRepo) FindByEmail(ctx context.Context, orgID domain.OrganizationID, email string) (*domain.Contact, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, email, first_name, last_name, metadata, status, created_at, updated_at, deleted_at
		FROM contacts WHERE org_id = $1 AND email = $2 AND deleted_at IS NULL
	`, string(orgID), email)
	c, err := scanContact(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

func (r *contactRepo) Update(ctx context.Context, c *domain.Contact) error {
	q := QuerierFromContext(ctx, r.pool)
	metadata, _ := json.Marshal(c.Metadata)
	_, err := q.Exec(ctx, `
		UPDATE contacts SET email = $2, first_name = $3, last_name = $4, metadata = $5, status = $6, updated_at = $7
		WHERE id = $1 AND deleted_at IS NULL
	`, string(c.ID), c.Email, c.FirstName, c.LastName, metadata, string(c.Status), c.UpdatedAt)
	return err
}

func (r *contactRepo) SoftDelete(ctx context.Context, id domain.ContactID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE contacts SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *contactRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params contact.ListParams) ([]*domain.Contact, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "email", "first_name", "last_name"}, "created_at")
	sortOrder := "ASC"
	if params.SortOrder == "desc" {
		sortOrder = "DESC"
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset()

	countQuery := `SELECT COUNT(*) FROM contacts WHERE org_id = $1 AND deleted_at IS NULL`
	listQuery := `SELECT id, org_id, email, first_name, last_name, metadata, status, created_at, updated_at, deleted_at
		FROM contacts WHERE org_id = $1 AND deleted_at IS NULL`

	args := []any{string(orgID)}
	argIdx := 2

	if params.Status != "" {
		countQuery += ` AND status = ` + placeholder(argIdx)
		listQuery += ` AND status = ` + placeholder(argIdx)
		args = append(args, params.Status)
		argIdx++
	}
	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		countQuery += ` AND (email ILIKE ` + placeholder(argIdx) + ` OR first_name ILIKE ` + placeholder(argIdx) + ` OR last_name ILIKE ` + placeholder(argIdx) + `)`
		listQuery += ` AND (email ILIKE ` + placeholder(argIdx) + ` OR first_name ILIKE ` + placeholder(argIdx) + ` OR last_name ILIKE ` + placeholder(argIdx) + `)`
		args = append(args, searchPattern)
		argIdx++
	}

	var total int
	err := q.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	listQuery += ` ORDER BY ` + sortBy + ` ` + sortOrder + ` LIMIT ` + placeholder(argIdx) + ` OFFSET ` + placeholder(argIdx+1)

	rows, err := q.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []*domain.Contact
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, 0, err
		}
		list = append(list, c)
	}
	return list, total, rows.Err()
}

func (r *contactRepo) BatchCreate(ctx context.Context, contacts []*domain.Contact) (int, error) {
	if len(contacts) == 0 {
		return 0, nil
	}
	q := QuerierFromContext(ctx, r.pool)
	var args []any
	var valPhrases []string
	for i, c := range contacts {
		metadata, _ := json.Marshal(c.Metadata)
		n := i*9 + 1
		valPhrases = append(valPhrases, "("+placeholder(n)+", "+placeholder(n+1)+", "+placeholder(n+2)+", "+placeholder(n+3)+", "+placeholder(n+4)+", "+placeholder(n+5)+", "+placeholder(n+6)+", "+placeholder(n+7)+", "+placeholder(n+8)+")")
		args = append(args, string(c.ID), string(c.OrgID), c.Email, c.FirstName, c.LastName, metadata, string(c.Status), c.CreatedAt, c.UpdatedAt)
	}
	query := `INSERT INTO contacts (id, org_id, email, first_name, last_name, metadata, status, created_at, updated_at) VALUES ` + strings.Join(valPhrases, ", ")
	_, err := q.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return len(contacts), nil
}

func (r *contactRepo) UpdateStatus(ctx context.Context, id domain.ContactID, status domain.ContactStatus) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE contacts SET status = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id), string(status))
	return err
}
