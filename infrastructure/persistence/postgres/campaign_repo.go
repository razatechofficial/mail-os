package postgres

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/campaign"
	domain "github.com/razatechofficial/mail-os/domain/campaign"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// CampaignRepository maps campaigns onto the campaigns table (deleted
// campaigns are hidden, not removed, so their recipient rows keep the
// counts) and checks the templates and lists they point at.
type CampaignRepository struct {
	db *Pool
}

var (
	_ app.Repository = (*CampaignRepository)(nil)
	_ app.Targets    = (*CampaignRepository)(nil)
)

// NewCampaignRepository returns the repository.
func NewCampaignRepository(db *Pool) *CampaignRepository { return &CampaignRepository{db: db} }

const campaignColumns = `id, org_id, name, subject, from_name, from_email, COALESCE(template_id, ''), COALESCE(contact_list_id, ''),
	type, status, scheduled_at, started_at, completed_at, total_recipients, sent_count, failed_count,
	COALESCE(metadata, '{}'::jsonb), created_at, updated_at`

func scanCampaign(row pgx.Row) (domain.Campaign, error) {
	var c domain.Campaign
	err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.Subject, &c.FromName, &c.FromEmail, &c.TemplateID, &c.ContactListID,
		&c.Type, &c.Status, &c.ScheduledAt, &c.StartedAt, &c.CompletedAt, &c.TotalRecipients, &c.SentCount, &c.FailedCount,
		&c.Metadata, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func collectCampaigns(rows pgx.Rows) ([]domain.Campaign, error) {
	defer rows.Close()
	out := []domain.Campaign{}
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *CampaignRepository) one(ctx context.Context, sql string, args ...any) (domain.Campaign, error) {
	c, err := scanCampaign(QuerierFromContext(ctx, r.db).QueryRow(ctx, sql, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Campaign{}, domain.ErrNotFound
	}
	return c, err
}

// Get reads one of the tenant's campaigns.
func (r *CampaignRepository) Get(ctx context.Context, tenant, id string) (domain.Campaign, error) {
	return r.one(ctx, `SELECT `+campaignColumns+` FROM campaigns WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenant)
}

// Lock reads the campaign FOR UPDATE (in the caller's transaction).
func (r *CampaignRepository) Lock(ctx context.Context, tenant, id string) (domain.Campaign, error) {
	return r.one(ctx, `SELECT `+campaignColumns+` FROM campaigns WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL FOR UPDATE`, id, tenant)
}

var campaignSortColumns = map[string]string{
	"created_at": "created_at", "updated_at": "updated_at", "name": "name", "status": "status", "scheduled_at": "scheduled_at",
}

// List returns a page of the tenant's campaigns, newest first by default.
func (r *CampaignRepository) List(ctx context.Context, tenant string, f app.Filter) ([]domain.Campaign, int, error) {
	where, args := "org_id = $1 AND deleted_at IS NULL", []any{tenant}
	if f.Status != "" {
		args = append(args, string(f.Status))
		where += " AND status = $2"
	}
	q := QuerierFromContext(ctx, r.db)
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM campaigns WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	col, ok := campaignSortColumns[f.SortBy]
	if !ok {
		col = "created_at"
	}
	dir := "DESC"
	if strings.EqualFold(f.SortOrder, "asc") {
		dir = "ASC"
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := q.Query(ctx, `SELECT `+campaignColumns+` FROM campaigns WHERE `+where+
		` ORDER BY `+col+` `+dir+` NULLS LAST, id `+dir+
		` LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := collectCampaigns(rows)
	return out, total, err
}

// Create inserts a campaign.
func (r *CampaignRepository) Create(ctx context.Context, c domain.Campaign) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO campaigns (id, org_id, name, subject, from_name, from_email, template_id, contact_list_id, type, status,
			scheduled_at, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), $9, $10, $11, $12, $13, $13)`,
		c.ID, c.OrgID, c.Name, c.Subject, c.FromName, c.FromEmail, c.TemplateID, c.ContactListID, string(c.Type), string(c.Status),
		c.ScheduledAt, c.Metadata, c.CreatedAt)
	return r.reference(err)
}

// reference maps a template or list deleted meanwhile to a field error.
func (r *CampaignRepository) reference(err error) error {
	if IsForeignKeyViolation(err) {
		return apperrors.Invalid("template_id", "not_found", "the template or contact list no longer exists")
	}
	return err
}

// Update saves the content, status and timestamps; the counts are the
// fan-out's (AddCounts, SetTotal).
func (r *CampaignRepository) Update(ctx context.Context, c domain.Campaign) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE campaigns SET name = $3, subject = $4, from_name = $5, from_email = $6, template_id = NULLIF($7, ''),
			contact_list_id = NULLIF($8, ''), type = $9, status = $10, scheduled_at = $11, started_at = $12, completed_at = $13,
			metadata = $14, updated_at = $15
		WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`,
		c.ID, c.OrgID, c.Name, c.Subject, c.FromName, c.FromEmail, c.TemplateID, c.ContactListID, string(c.Type), string(c.Status),
		c.ScheduledAt, c.StartedAt, c.CompletedAt, c.Metadata, c.UpdatedAt)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return r.reference(err)
}

// Delete hides the campaign.
func (r *CampaignRepository) Delete(ctx context.Context, tenant, id string) error {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`UPDATE campaigns SET deleted_at = now(), updated_at = now() WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, id, tenant)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return err
}

// Due returns scheduled campaigns whose time has come (idx_campaigns_due).
func (r *CampaignRepository) Due(ctx context.Context, now time.Time, limit int) ([]domain.Campaign, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT `+campaignColumns+` FROM campaigns
		WHERE status = 'scheduled' AND deleted_at IS NULL AND scheduled_at <= $1 ORDER BY scheduled_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	return collectCampaigns(rows)
}

// Stalled returns sending campaigns not updated since before
// (idx_campaigns_sending).
func (r *CampaignRepository) Stalled(ctx context.Context, before time.Time, limit int) ([]domain.Campaign, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `SELECT `+campaignColumns+` FROM campaigns
		WHERE status = 'sending' AND deleted_at IS NULL AND updated_at < $1 ORDER BY updated_at LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	return collectCampaigns(rows)
}

// SetTotal records the recipient total (and bumps updated_at).
func (r *CampaignRepository) SetTotal(ctx context.Context, id string, total int) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`UPDATE campaigns SET total_recipients = $2, updated_at = now() WHERE id = $1`, id, total)
	return err
}

// AddCounts adds to the sent and failed counts (and bumps updated_at).
func (r *CampaignRepository) AddCounts(ctx context.Context, id string, sent, failed int) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE campaigns SET sent_count = sent_count + $2, failed_count = failed_count + $3, updated_at = now() WHERE id = $1`,
		id, sent, failed)
	return err
}

// TemplateExists reports whether the template is the tenant's.
func (r *CampaignRepository) TemplateExists(ctx context.Context, tenant, id string) (bool, error) {
	var ok bool
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM templates WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL)`, id, tenant).Scan(&ok)
	return ok, err
}

// ListExists reports whether the contact list is the tenant's.
func (r *CampaignRepository) ListExists(ctx context.Context, tenant, id string) (bool, error) {
	var ok bool
	err := QuerierFromContext(ctx, r.db).QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM contact_lists WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL)`, id, tenant).Scan(&ok)
	return ok, err
}
