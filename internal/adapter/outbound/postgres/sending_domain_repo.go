package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/sendingdomain"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type sendingDomainRepo struct {
	pool *pgxpool.Pool
}

var _ sendingdomain.Repository = (*sendingDomainRepo)(nil)

func NewSendingDomainRepo(pool *pgxpool.Pool) sendingdomain.Repository {
	return &sendingDomainRepo{pool: pool}
}

func (r *sendingDomainRepo) Create(ctx context.Context, sd *domain.SendingDomain) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		INSERT INTO sending_domains (id, org_id, domain, dkim_public_key, dkim_private_key, spf_record, dmarc_record, status, verified_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, string(sd.ID), string(sd.OrgID), sd.Domain, sd.DKIMPublicKey, sd.DKIMPrivateKey, sd.SPFRecord, sd.DMARCRecord, string(sd.Status), sd.VerifiedAt, sd.CreatedAt, sd.UpdatedAt)
	return err
}

func (r *sendingDomainRepo) FindByID(ctx context.Context, id domain.SendingDomainID) (*domain.SendingDomain, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, domain, dkim_public_key, dkim_private_key, spf_record, dmarc_record, status, verified_at, created_at, updated_at, deleted_at
		FROM sending_domains WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	sd, err := scanSendingDomain(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return sd, nil
}

func (r *sendingDomainRepo) Update(ctx context.Context, sd *domain.SendingDomain) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE sending_domains SET domain = $2, dkim_public_key = $3, dkim_private_key = $4, spf_record = $5, dmarc_record = $6, status = $7, verified_at = $8, updated_at = $9
		WHERE id = $1 AND deleted_at IS NULL
	`, string(sd.ID), sd.Domain, sd.DKIMPublicKey, sd.DKIMPrivateKey, sd.SPFRecord, sd.DMARCRecord, string(sd.Status), sd.VerifiedAt, sd.UpdatedAt)
	return err
}

func (r *sendingDomainRepo) SoftDelete(ctx context.Context, id domain.SendingDomainID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE sending_domains SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *sendingDomainRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params sendingdomain.ListParams) ([]*domain.SendingDomain, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "domain"}, "created_at")
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
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM sending_domains WHERE org_id = $1 AND deleted_at IS NULL`, string(orgID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `SELECT id, org_id, domain, dkim_public_key, dkim_private_key, spf_record, dmarc_record, status, verified_at, created_at, updated_at, deleted_at
		FROM sending_domains WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3`, string(orgID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []*domain.SendingDomain
	for rows.Next() {
		sd, err := scanSendingDomain(rows)
		if err != nil {
			return nil, 0, err
		}
		list = append(list, sd)
	}
	return list, total, rows.Err()
}

func scanSendingDomain(row pgx.Row) (*domain.SendingDomain, error) {
	var id, orgID, domainVal, status string
	var dkimPub, dkimPriv, spf, dmarc *string
	var verifiedAt, deletedAt *time.Time
	var createdAt, updatedAt time.Time
	err := row.Scan(&id, &orgID, &domainVal, &dkimPub, &dkimPriv, &spf, &dmarc, &status, &verifiedAt, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	sd := &domain.SendingDomain{
		ID:         domain.SendingDomainID(id),
		OrgID:      domain.OrganizationID(orgID),
		Domain:     domainVal,
		Status:     domain.DomainStatus(status),
		VerifiedAt: verifiedAt,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
		DeletedAt:  deletedAt,
	}
	if dkimPub != nil {
		sd.DKIMPublicKey = *dkimPub
	}
	if dkimPriv != nil {
		sd.DKIMPrivateKey = *dkimPriv
	}
	if spf != nil {
		sd.SPFRecord = *spf
	}
	if dmarc != nil {
		sd.DMARCRecord = *dmarc
	}
	return sd, nil
}
