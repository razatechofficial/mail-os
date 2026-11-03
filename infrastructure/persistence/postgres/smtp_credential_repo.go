package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/smtpcred"
	domain "github.com/razatechofficial/mail-os/domain/smtpcredential"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// SMTPCredentialRepository stores applications' SMTP credentials (hashes
// only).
type SMTPCredentialRepository struct {
	db *Pool
}

var _ app.Repository = (*SMTPCredentialRepository)(nil)

// NewSMTPCredentialRepository returns the repository.
func NewSMTPCredentialRepository(db *Pool) *SMTPCredentialRepository {
	return &SMTPCredentialRepository{db: db}
}

const smtpCredentialCols = `id, org_id, application_id, username, password_hash, description, created_by, created_at,
	rotated_at, rotated_by, last_used_at, last_used_ip, revoked_at, revoked_by`

func scanSMTPCredential(row pgx.Row) (domain.Credential, error) {
	var c domain.Credential
	err := row.Scan(&c.ID, &c.TenantID, &c.ApplicationID, &c.Username, &c.PasswordHash, &c.Description, &c.CreatedBy,
		&c.CreatedAt, &c.RotatedAt, &c.RotatedBy, &c.LastUsedAt, &c.LastUsedIP, &c.RevokedAt, &c.RevokedBy)
	return c, err
}

// Create inserts a credential.
func (r *SMTPCredentialRepository) Create(ctx context.Context, c domain.Credential) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO smtp_credentials (`+smtpCredentialCols+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		c.ID, c.TenantID, c.ApplicationID, c.Username, c.PasswordHash, c.Description, c.CreatedBy, c.CreatedAt,
		c.RotatedAt, c.RotatedBy, c.LastUsedAt, c.LastUsedIP, c.RevokedAt, c.RevokedBy)
	if IsUniqueViolation(err) {
		return apperrors.Conflict("that SMTP username exists; try again")
	}
	return err
}

// Get reads one of the tenant's credentials.
func (r *SMTPCredentialRepository) Get(ctx context.Context, tenantID, id string) (domain.Credential, error) {
	c, err := scanSMTPCredential(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+smtpCredentialCols+` FROM smtp_credentials WHERE id = $1 AND org_id = $2`, id, tenantID))
	return c, notFound(err, "smtp credential")
}

// ByUsername reads the credential of a username, in any tenant.
func (r *SMTPCredentialRepository) ByUsername(ctx context.Context, username string) (domain.Credential, error) {
	c, err := scanSMTPCredential(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+smtpCredentialCols+` FROM smtp_credentials WHERE username = $1`, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Credential{}, app.ErrNotFound
	}
	return c, err
}

// List returns an application's credentials, newest first.
func (r *SMTPCredentialRepository) List(ctx context.Context, tenantID, applicationID string) ([]domain.Credential, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT `+smtpCredentialCols+` FROM smtp_credentials
		WHERE org_id = $1 AND application_id = $2 ORDER BY created_at DESC, id DESC`, tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Credential{}
	for rows.Next() {
		c, err := scanSMTPCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetPassword stores a rotated password hash of an active credential.
func (r *SMTPCredentialRepository) SetPassword(ctx context.Context, c domain.Credential) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE smtp_credentials SET password_hash = $3, rotated_at = $4, rotated_by = $5
		WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
		c.ID, c.TenantID, c.PasswordHash, c.RotatedAt, c.RotatedBy)
	if err == nil && tag.RowsAffected() == 0 {
		return apperrors.Conflict("the credential was revoked meanwhile")
	}
	return err
}

// Revoke marks the credential revoked unless it already is.
func (r *SMTPCredentialRepository) Revoke(ctx context.Context, tenantID, id string, at time.Time, by string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE smtp_credentials SET revoked_at = $3, revoked_by = $4
		WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`, id, tenantID, at, by)
	return err
}

// Touch records a successful authentication, at most once a minute so a
// busy application does not write on every connection.
func (r *SMTPCredentialRepository) Touch(ctx context.Context, id string, at time.Time, ip string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE smtp_credentials SET last_used_at = $2, last_used_ip = $3
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < $2::timestamptz - interval '1 minute' OR last_used_ip <> $3)`,
		id, at, ip)
	return err
}
