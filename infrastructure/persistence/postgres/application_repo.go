package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	app "github.com/razatechofficial/mail-os/application/applications"
	domain "github.com/razatechofficial/mail-os/domain/application"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// ApplicationRepository stores the application registry.
type ApplicationRepository struct {
	db *Pool
}

var _ app.Repository = (*ApplicationRepository)(nil)

// NewApplicationRepository returns the repository.
func NewApplicationRepository(db *Pool) *ApplicationRepository { return &ApplicationRepository{db: db} }

const applicationCols = `id, org_id, name, description, kind, client_id, status, suspended_reason, environment, stream,
	message_types, senders, default_from_email, default_from_name, default_reply_to, rate_limit_per_minute, daily_quota,
	browser_templates, user_rate_limit_per_hour, allowed_origins, system, created_by, updated_by, created_at, updated_at`

func scanApplication(row pgx.Row) (domain.Application, error) {
	var a domain.Application
	var kind, status, env, stream string
	err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &kind, &a.ClientID, &status, &a.SuspendedReason, &env, &stream,
		&a.MessageTypes, &a.Senders, &a.DefaultFromEmail, &a.DefaultFromName, &a.DefaultReplyTo, &a.RatePerMinute, &a.DailyQuota,
		&a.BrowserTemplates, &a.UserRatePerHour, &a.AllowedOrigins, &a.System, &a.CreatedBy, &a.UpdatedBy, &a.CreatedAt, &a.UpdatedAt)
	a.Kind, a.Status, a.Environment, a.Stream = domain.Kind(kind), domain.Status(status), domain.Environment(env), domain.Stream(stream)
	return a, err
}

// conflict names the unique index a duplicate hit.
func applicationConflict(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != uniqueViolation {
		return err
	}
	if pgErr.ConstraintName == "applications_org_name_idx" {
		return apperrors.Conflict("another application of this tenant has that name")
	}
	return apperrors.Conflict("that IAM client is already a MailOS application")
}

// Create inserts an application.
func (r *ApplicationRepository) Create(ctx context.Context, a domain.Application) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO applications (`+applicationCols+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)`,
		a.ID, a.TenantID, a.Name, a.Description, string(a.Kind), a.ClientID, string(a.Status), a.SuspendedReason,
		string(a.Environment), string(a.Stream), nonNil(a.MessageTypes), nonNil(a.Senders), a.DefaultFromEmail, a.DefaultFromName,
		a.DefaultReplyTo, a.RatePerMinute, a.DailyQuota, nonNil(a.BrowserTemplates), a.UserRatePerHour, nonNil(a.AllowedOrigins),
		a.System, a.CreatedBy, a.UpdatedBy, a.CreatedAt, a.UpdatedAt)
	return applicationConflict(err)
}

// Update saves everything but the id, tenant and creation.
func (r *ApplicationRepository) Update(ctx context.Context, a domain.Application) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE applications SET name = $3, description = $4, kind = $5, client_id = $6, status = $7, suspended_reason = $8,
			environment = $9, stream = $10, message_types = $11, senders = $12, default_from_email = $13, default_from_name = $14,
			default_reply_to = $15, rate_limit_per_minute = $16, daily_quota = $17, browser_templates = $18,
			user_rate_limit_per_hour = $19, allowed_origins = $20, updated_by = $21, updated_at = $22
		WHERE id = $1 AND org_id = $2`,
		a.ID, a.TenantID, a.Name, a.Description, string(a.Kind), a.ClientID, string(a.Status), a.SuspendedReason,
		string(a.Environment), string(a.Stream), nonNil(a.MessageTypes), nonNil(a.Senders), a.DefaultFromEmail, a.DefaultFromName,
		a.DefaultReplyTo, a.RatePerMinute, a.DailyQuota, nonNil(a.BrowserTemplates), a.UserRatePerHour, nonNil(a.AllowedOrigins),
		a.UpdatedBy, a.UpdatedAt)
	if err != nil {
		return applicationConflict(err)
	}
	if tag.RowsAffected() == 0 {
		return apperrors.NotFound("application not found")
	}
	return nil
}

// Delete removes the tenant's application.
func (r *ApplicationRepository) Delete(ctx context.Context, tenantID, id string) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `DELETE FROM applications WHERE id = $1 AND org_id = $2`, id, tenantID)
	if err == nil && tag.RowsAffected() == 0 {
		return apperrors.NotFound("application not found")
	}
	return err
}

// Get reads one of the tenant's applications.
func (r *ApplicationRepository) Get(ctx context.Context, tenantID, id string) (domain.Application, error) {
	a, err := scanApplication(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+applicationCols+` FROM applications WHERE id = $1 AND org_id = $2`, id, tenantID))
	return a, notFound(err, "application")
}

// ByClientID reads the application of an IAM client, in any tenant.
func (r *ApplicationRepository) ByClientID(ctx context.Context, clientID string) (domain.Application, error) {
	a, err := scanApplication(QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT `+applicationCols+` FROM applications WHERE client_id = $1`, clientID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Application{}, app.ErrNotFound
	}
	return a, err
}

// List returns a page of the tenant's applications by name.
func (r *ApplicationRepository) List(ctx context.Context, f app.Filter) ([]domain.Application, int, error) {
	q := QuerierFromContext(ctx, r.db)
	where := `org_id = $1 AND ($2 = '' OR status = $2) AND ($3 = '' OR kind = $3)`
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM applications WHERE `+where, f.TenantID, f.Status, f.Kind).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query(ctx, `SELECT `+applicationCols+` FROM applications WHERE `+where+` ORDER BY lower(name) LIMIT $4 OFFSET $5`,
		f.TenantID, f.Status, f.Kind, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []domain.Application{}
	for rows.Next() {
		a, err := scanApplication(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// MessageCounts counts the application's messages per UTC day and status.
func (r *ApplicationRepository) MessageCounts(ctx context.Context, tenantID, id string, since time.Time) ([]app.StatusCount, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `
		SELECT date_trunc('day', created_at AT TIME ZONE 'UTC') AS day, status, count(*)
		FROM messages WHERE org_id = $1 AND application_id = $2 AND created_at >= $3
		GROUP BY day, status ORDER BY day`, tenantID, id, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.StatusCount
	for rows.Next() {
		var c app.StatusCount
		if err := rows.Scan(&c.Day, &c.Status, &c.Count); err != nil {
			return nil, err
		}
		c.Day = time.Date(c.Day.Year(), c.Day.Month(), c.Day.Day(), 0, 0, 0, 0, time.UTC)
		out = append(out, c)
	}
	return out, rows.Err()
}
