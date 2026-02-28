package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/internal/core/campaign"
	"github.com/razatechofficial/mail-os/internal/domain"
)

type campaignRepo struct {
	pool *pgxpool.Pool
}

var _ campaign.Repository = (*campaignRepo)(nil)

func NewCampaignRepo(pool *pgxpool.Pool) campaign.Repository {
	return &campaignRepo{pool: pool}
}

func (r *campaignRepo) Create(ctx context.Context, c *domain.Campaign) error {
	q := QuerierFromContext(ctx, r.pool)
	metadata, _ := json.Marshal(c.Metadata)
	_, err := q.Exec(ctx, `
		INSERT INTO campaigns (id, org_id, name, subject, from_name, from_email, template_id, contact_list_id, type, status,
			scheduled_at, started_at, completed_at, total_recipients, sent_count, failed_count, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
	`, string(c.ID), string(c.OrgID), c.Name, c.Subject, c.FromName, c.FromEmail, nullStr(string(c.TemplateID)), nullStr(string(c.ContactListID)),
		string(c.Type), string(c.Status), nullTime(c.ScheduledAt), nullTime(c.StartedAt), nullTime(c.CompletedAt),
		c.TotalRecipients, c.SentCount, c.FailedCount, metadata, c.CreatedAt, c.UpdatedAt)
	return err
}

func (r *campaignRepo) FindByID(ctx context.Context, id domain.CampaignID) (*domain.Campaign, error) {
	q := QuerierFromContext(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT id, org_id, name, subject, from_name, from_email, template_id, contact_list_id, type, status,
			scheduled_at, started_at, completed_at, total_recipients, sent_count, failed_count, metadata, created_at, updated_at, deleted_at
		FROM campaigns WHERE id = $1 AND deleted_at IS NULL
	`, string(id))
	camp, err := scanCampaign(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return camp, nil
}

func (r *campaignRepo) Update(ctx context.Context, c *domain.Campaign) error {
	q := QuerierFromContext(ctx, r.pool)
	metadata, _ := json.Marshal(c.Metadata)
	_, err := q.Exec(ctx, `
		UPDATE campaigns SET name = $2, subject = $3, from_name = $4, from_email = $5, template_id = $6, contact_list_id = $7,
			type = $8, status = $9, scheduled_at = $10, started_at = $11, completed_at = $12, total_recipients = $13,
			sent_count = $14, failed_count = $15, metadata = $16, updated_at = $17
		WHERE id = $1 AND deleted_at IS NULL
	`, string(c.ID), c.Name, c.Subject, c.FromName, c.FromEmail, nullStr(string(c.TemplateID)), nullStr(string(c.ContactListID)),
		string(c.Type), string(c.Status), nullTime(c.ScheduledAt), nullTime(c.StartedAt), nullTime(c.CompletedAt),
		c.TotalRecipients, c.SentCount, c.FailedCount, metadata, c.UpdatedAt)
	return err
}

func (r *campaignRepo) SoftDelete(ctx context.Context, id domain.CampaignID) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `UPDATE campaigns SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, string(id))
	return err
}

func (r *campaignRepo) FindAll(ctx context.Context, orgID domain.OrganizationID, params campaign.ListParams) ([]*domain.Campaign, int, error) {
	q := QuerierFromContext(ctx, r.pool)
	sortBy := allowedSortColumn(params.SortBy, []string{"created_at", "updated_at", "name", "status", "scheduled_at"}, "created_at")
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
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM campaigns WHERE org_id = $1 AND deleted_at IS NULL`, string(orgID)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx, `
		SELECT id, org_id, name, subject, from_name, from_email, template_id, contact_list_id, type, status,
			scheduled_at, started_at, completed_at, total_recipients, sent_count, failed_count, metadata, created_at, updated_at, deleted_at
		FROM campaigns WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY `+sortBy+` `+sortOrder+`
		LIMIT $2 OFFSET $3
	`, string(orgID), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var campaigns []*domain.Campaign
	for rows.Next() {
		camp, err := scanCampaign(rows)
		if err != nil {
			return nil, 0, err
		}
		campaigns = append(campaigns, camp)
	}
	return campaigns, total, rows.Err()
}

func (r *campaignRepo) UpdateStatus(ctx context.Context, id domain.CampaignID, status domain.CampaignStatus) error {
	q := QuerierFromContext(ctx, r.pool)
	now := time.Now()
	var stmt string
	switch status {
	case domain.CampaignStatusSending:
		stmt = `UPDATE campaigns SET status = $2, started_at = COALESCE(started_at, $3), updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	case domain.CampaignStatusCompleted, domain.CampaignStatusCancelled:
		stmt = `UPDATE campaigns SET status = $2, completed_at = COALESCE(completed_at, $3), updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	default:
		stmt = `UPDATE campaigns SET status = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	}
	_, err := q.Exec(ctx, stmt, string(id), string(status), now)
	return err
}

func (r *campaignRepo) UpdateCounts(ctx context.Context, id domain.CampaignID, sent, failed int) error {
	q := QuerierFromContext(ctx, r.pool)
	_, err := q.Exec(ctx, `
		UPDATE campaigns SET sent_count = sent_count + $2, failed_count = failed_count + $3, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`, string(id), sent, failed)
	return err
}

func scanCampaign(row pgx.Row) (*domain.Campaign, error) {
	var id, orgID, name, subject, fromName, fromEmail, status, campType string
	var templateID, contactListID *string
	var metadata []byte
	var createdAt, updatedAt time.Time
	var scheduledAt, startedAt, completedAt, deletedAt *time.Time
	var totalRecipients, sentCount, failedCount int
	err := row.Scan(&id, &orgID, &name, &subject, &fromName, &fromEmail, &templateID, &contactListID, &campType, &status,
		&scheduledAt, &startedAt, &completedAt, &totalRecipients, &sentCount, &failedCount, &metadata, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return nil, err
	}
	var metadataMap map[string]any
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &metadataMap)
	}
	return &domain.Campaign{
		ID:              domain.CampaignID(id),
		OrgID:           domain.OrganizationID(orgID),
		Name:            name,
		Subject:         subject,
		FromName:        fromName,
		FromEmail:       fromEmail,
		TemplateID:      domain.TemplateID(strVal(templateID)),
		ContactListID:   domain.ContactListID(strVal(contactListID)),
		Type:            domain.CampaignType(campType),
		Status:          domain.CampaignStatus(status),
		ScheduledAt:     scheduledAt,
		StartedAt:       startedAt,
		CompletedAt:     completedAt,
		TotalRecipients: totalRecipients,
		SentCount:       sentCount,
		FailedCount:     failedCount,
		Metadata:        metadataMap,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		DeletedAt:       deletedAt,
	}, nil
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
