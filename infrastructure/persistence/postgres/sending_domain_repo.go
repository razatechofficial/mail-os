package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	app "github.com/razatechofficial/mail-os/application/sendingdomain"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domain "github.com/razatechofficial/mail-os/domain/sendingdomain"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// SendingDomainRepository stores sending domains; the DKIM private key is
// sealed in dkim_private_key_sealed and the plaintext column stays empty.
type SendingDomainRepository struct {
	db *Pool
}

var _ app.Repository = (*SendingDomainRepository)(nil)

// NewSendingDomainRepository returns the repository.
func NewSendingDomainRepository(db *Pool) *SendingDomainRepository {
	return &SendingDomainRepository{db: db}
}

// SealedColumn is dkim_private_key_sealed, for the key schedule.
func (r *SendingDomainRepository) SealedColumn() appkm.SealedColumn {
	return sealedColumn{db: r.db, purpose: domainkm.PurposeDKIM, table: "sending_domains", column: "dkim_private_key_sealed"}
}

const domainCols = `id, org_id, domain, COALESCE(dkim_selector, 'mailos'), COALESCE(dkim_public_key, ''), COALESCE(spf_record, ''),
	COALESCE(dmarc_record, ''), status, last_checked_at, COALESCE(failure_reason, ''), verified_at, COALESCE(created_by, ''),
	created_at, updated_at, COALESCE(dkim_private_key_sealed, '')`

func scanDomain(row pgx.Row) (app.Stored, error) {
	var s app.Stored
	d := &s.Domain
	var status string
	err := row.Scan(&d.ID, &d.OrgID, &d.Name, &d.DKIMSelector, &d.DKIMPublicKey, &d.SPFRecord, &d.DMARCRecord, &status,
		&d.LastCheckedAt, &d.FailureReason, &d.VerifiedAt, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &s.Sealed)
	d.Status = domain.Status(status)
	return s, err
}

// Create inserts a domain; the tenant's existing name is a conflict.
func (r *SendingDomainRepository) Create(ctx context.Context, s app.Stored) error {
	d := s.Domain
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO sending_domains (id, org_id, domain, dkim_selector, dkim_public_key, dkim_private_key_sealed, spf_record,
			dmarc_record, status, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), $11, $12)`,
		d.ID, d.OrgID, d.Name, d.DKIMSelector, d.DKIMPublicKey, s.Sealed, d.SPFRecord, d.DMARCRecord, string(d.Status),
		d.CreatedBy, d.CreatedAt, d.UpdatedAt)
	if IsUniqueViolation(err) {
		return apperrors.Conflict("the domain is already registered")
	}
	return err
}

// Update saves d, and the key when sealed is set.
func (r *SendingDomainRepository) Update(ctx context.Context, d domain.Domain, sealed *string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE sending_domains SET dkim_selector = $3, dkim_public_key = $4, spf_record = $5, dmarc_record = $6, status = $7,
			last_checked_at = $8, failure_reason = NULLIF($9, ''), verified_at = $10, updated_at = $11,
			dkim_private_key_sealed = CASE WHEN $12::boolean THEN $13 ELSE dkim_private_key_sealed END
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
		d.ID, d.OrgID, d.DKIMSelector, d.DKIMPublicKey, d.SPFRecord, d.DMARCRecord, string(d.Status), d.LastCheckedAt,
		d.FailureReason, d.VerifiedAt, d.UpdatedAt, sealed != nil, deref(sealed))
	return err
}

// Delete soft-deletes a domain and drops its key.
func (r *SendingDomainRepository) Delete(ctx context.Context, tenantID, id string, at time.Time) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE sending_domains SET deleted_at = $3, updated_at = $3,
		dkim_private_key_sealed = NULL, dkim_private_key = NULL WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenantID, at)
	return err
}

// Get reads one of the tenant's domains.
func (r *SendingDomainRepository) Get(ctx context.Context, tenantID, id string) (app.Stored, error) {
	s, err := scanDomain(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+domainCols+` FROM sending_domains WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenantID))
	return s, notFound(err, "sending domain")
}

func (r *SendingDomainRepository) scan(ctx context.Context, sql string, args ...any) ([]app.Stored, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.Stored
	for rows.Next() {
		s, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// List returns a page of domains.
func (r *SendingDomainRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Domain, int, error) {
	var total int
	if err := QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT count(*) FROM sending_domains WHERE org_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	list, err := r.scan(ctx, `SELECT `+domainCols+` FROM sending_domains WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY domain LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	out := make([]domain.Domain, len(list))
	for i, s := range list {
		out[i] = s.Domain
	}
	return out, total, err
}

// Verified lists the tenant's verified domains with their keys.
func (r *SendingDomainRepository) Verified(ctx context.Context, tenantID string) ([]app.Stored, error) {
	return r.scan(ctx, `SELECT `+domainCols+` FROM sending_domains WHERE org_id = $1 AND status = 'verified' AND deleted_at IS NULL`, tenantID)
}

// Legacy lists domains with a plaintext DKIM key.
func (r *SendingDomainRepository) Legacy(ctx context.Context) ([]app.LegacyRow, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx,
		`SELECT id, dkim_private_key FROM sending_domains WHERE dkim_private_key IS NOT NULL AND dkim_private_key <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.LegacyRow
	for rows.Next() {
		var lr app.LegacyRow
		if err := rows.Scan(&lr.ID, &lr.PrivateKeyPEM); err != nil {
			return nil, err
		}
		out = append(out, lr)
	}
	return out, rows.Err()
}

// ReplaceLegacy stores the sealed key and empties the plaintext column.
func (r *SendingDomainRepository) ReplaceLegacy(ctx context.Context, id, sealed string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `UPDATE sending_domains SET dkim_private_key_sealed = $2,
		dkim_private_key = NULL, dkim_selector = COALESCE(dkim_selector, 'mailos') WHERE id = $1`, id, sealed)
	return err
}

// WithLock runs fn under the DKIM conversion's advisory lock.
func (r *SendingDomainRepository) WithLock(ctx context.Context, fn func(ctx context.Context) error) (bool, error) {
	return withAdvisoryLock(ctx, r.db, domainLegacyLock, fn)
}
