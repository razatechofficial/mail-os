package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	app "github.com/razatechofficial/mail-os/application/campaign"
	domain "github.com/razatechofficial/mail-os/domain/campaign"
)

// CampaignRecipientRepository is the campaign fan-out's ledger
// (campaign_recipients): one row per contact handed to the sender, written
// before the send so a contact is never sent the campaign twice.
type CampaignRecipientRepository struct {
	db *Pool
}

var _ app.Recipients = (*CampaignRecipientRepository)(nil)

// NewCampaignRecipientRepository returns the repository.
func NewCampaignRecipientRepository(db *Pool) *CampaignRecipientRepository {
	return &CampaignRecipientRepository{db: db}
}

// eligibleMembers are the list's members who can receive the campaign and
// have no row yet: the tenant's active contacts whose address is not
// suppressed (suppressions and contacts both store the address lowercase).
// $1 tenant, $2 list, $3 campaign.
const eligibleMembers = `
	FROM contact_list_members m
	JOIN contact_lists l ON l.id = m.contact_list_id AND l.org_id = $1 AND l.deleted_at IS NULL
	JOIN contacts c ON c.id = m.contact_id AND c.org_id = $1 AND c.deleted_at IS NULL AND c.status = 'active'
	WHERE m.contact_list_id = $2
		AND NOT EXISTS (SELECT 1 FROM suppressions s WHERE s.org_id = $1 AND s.email = c.email)
		AND NOT EXISTS (SELECT 1 FROM campaign_recipients r WHERE r.campaign_id = $3 AND r.contact_id = c.id)`

// Pending returns the next eligible members by contact id.
func (r *CampaignRecipientRepository) Pending(ctx context.Context, tenant, campaignID, listID string, limit int) ([]app.Recipient, error) {
	rows, err := QuerierFromContext(ctx, r.db).Query(ctx, `
		SELECT c.id, c.email, COALESCE(c.first_name, ''), COALESCE(c.last_name, '')`+eligibleMembers+`
		ORDER BY m.contact_id LIMIT $4`, tenant, listID, campaignID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (app.Recipient, error) {
		var rc app.Recipient
		err := row.Scan(&rc.ContactID, &rc.Email, &rc.FirstName, &rc.LastName)
		return rc, err
	})
}

// Count returns the rows written so far and the members still eligible.
func (r *CampaignRecipientRepository) Count(ctx context.Context, tenant, campaignID, listID string) (int, int, error) {
	var recorded, pending int
	q := QuerierFromContext(ctx, r.db)
	if err := q.QueryRow(ctx, `SELECT count(*) FROM campaign_recipients WHERE campaign_id = $1`, campaignID).Scan(&recorded); err != nil {
		return 0, 0, err
	}
	if err := q.QueryRow(ctx, `SELECT count(*)`+eligibleMembers, tenant, listID, campaignID).Scan(&pending); err != nil {
		return 0, 0, err
	}
	return recorded, pending, nil
}

// Claim writes the queued row; false when it exists.
func (r *CampaignRecipientRepository) Claim(ctx context.Context, campaignID, contactID string) (bool, error) {
	tag, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		INSERT INTO campaign_recipients (campaign_id, contact_id, status, claimed_at) VALUES ($1, $2, $3, now())
		ON CONFLICT DO NOTHING`, campaignID, contactID, domain.RecipientQueued)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Release deletes a row still queued.
func (r *CampaignRecipientRepository) Release(ctx context.Context, campaignID, contactID string) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx,
		`DELETE FROM campaign_recipients WHERE campaign_id = $1 AND contact_id = $2 AND status = $3`,
		campaignID, contactID, domain.RecipientQueued)
	return err
}

// MarkSent records the message the recipient became.
func (r *CampaignRecipientRepository) MarkSent(ctx context.Context, campaignID, contactID, messageID string, at time.Time) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE campaign_recipients SET status = $3, message_id = NULLIF($4, ''), sent_at = $5, error = NULL
		WHERE campaign_id = $1 AND contact_id = $2`, campaignID, contactID, domain.RecipientSent, messageID, at)
	return err
}

// MarkFailed records why the sender refused the recipient.
func (r *CampaignRecipientRepository) MarkFailed(ctx context.Context, campaignID, contactID, reason string, _ time.Time) error {
	_, err := QuerierFromContext(ctx, r.db).Exec(ctx, `
		UPDATE campaign_recipients SET status = $3, error = $4 WHERE campaign_id = $1 AND contact_id = $2`,
		campaignID, contactID, domain.RecipientFailed, reason)
	return err
}
