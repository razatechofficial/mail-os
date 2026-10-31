// Package campaign is the campaign use case: a tenant's campaigns, the
// status changes the console asks for (launch, pause, resume, cancel), the
// release of scheduled campaigns, and the fan-out that hands each list
// member to the messaging slice through CampaignSender.
//
// The fan-out runs as worker tasks on the low queue. It pages through the
// list members who can receive the campaign (active contacts whose address
// is not suppressed), claims each one in campaign_recipients before
// sending, so nobody gets the campaign twice even when two fan-outs run at
// once, and re-reads the campaign between pages so a pause or cancel stops
// it there.
package campaign

import (
	"context"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/campaign"
)

// CampaignMessage is one campaign email for one contact. Data carries the
// mailos.campaign topic's variables (contact.email, contact.first_name,
// contact.last_name) as a nested "contact" object, and the campaign's id,
// name and subject under "campaign".
type CampaignMessage struct {
	TenantID   string
	CampaignID string
	TemplateID string
	To         string
	ToName     string
	FromName   string
	FromEmail  string
	Data       map[string]any
}

// CampaignSender queues one campaign message (the messaging slice). An
// error of kind Unavailable is temporary: the recipient is released and
// the fan-out retried. Any other error fails that recipient only.
type CampaignSender interface {
	SendCampaignMessage(ctx context.Context, m CampaignMessage) (messageID string, err error)
}

// Filter narrows and pages a listing.
type Filter struct {
	Status    domain.Status
	SortBy    string
	SortOrder string
	Limit     int
	Offset    int
}

// Repository stores campaigns, scoped to the tenant: a campaign of another
// tenant (or a deleted one) is domain.ErrNotFound.
type Repository interface {
	Get(ctx context.Context, tenant, id string) (domain.Campaign, error)
	// Lock reads the campaign FOR UPDATE in the caller's transaction, so
	// status changes do not race.
	Lock(ctx context.Context, tenant, id string) (domain.Campaign, error)
	List(ctx context.Context, tenant string, f Filter) ([]domain.Campaign, int, error)
	Create(ctx context.Context, c domain.Campaign) error
	// Update saves the content, status and timestamps.
	Update(ctx context.Context, c domain.Campaign) error
	// Delete hides the campaign (its recipient rows are kept for the
	// counts).
	Delete(ctx context.Context, tenant, id string) error
	// Due returns scheduled campaigns whose time has come, oldest first,
	// across tenants.
	Due(ctx context.Context, now time.Time, limit int) ([]domain.Campaign, error)
	// Stalled returns sending campaigns not updated since before, across
	// tenants: a fan-out that was lost (enqueue failure, worker crash).
	Stalled(ctx context.Context, before time.Time, limit int) ([]domain.Campaign, error)
	SetTotal(ctx context.Context, id string, total int) error
	// AddCounts adds to the sent and failed counts (and bumps updated_at,
	// the fan-out's heartbeat).
	AddCounts(ctx context.Context, id string, sent, failed int) error
}

// Targets checks what a campaign points at belongs to the tenant.
type Targets interface {
	TemplateExists(ctx context.Context, tenant, id string) (bool, error)
	ListExists(ctx context.Context, tenant, id string) (bool, error)
}

// Recipient is a list member the campaign can be sent to.
type Recipient struct {
	ContactID string
	Email     string
	FirstName string
	LastName  string
}

// Recipients is the campaign's recipient ledger (campaign_recipients).
type Recipients interface {
	// Pending returns up to limit members of the list, by contact id, who
	// are active, not suppressed and have no recipient row yet.
	Pending(ctx context.Context, tenant, campaignID, listID string, limit int) ([]Recipient, error)
	// Count returns the recipient rows already written and the members
	// still pending.
	Count(ctx context.Context, tenant, campaignID, listID string) (recorded, pending int, err error)
	// Claim writes the queued row; false when another fan-out has it.
	Claim(ctx context.Context, campaignID, contactID string) (bool, error)
	// Release deletes a queued row so the recipient is tried again.
	Release(ctx context.Context, campaignID, contactID string) error
	MarkSent(ctx context.Context, campaignID, contactID, messageID string, at time.Time) error
	MarkFailed(ctx context.Context, campaignID, contactID, reason string, at time.Time) error
}

// Queue starts a fan-out task.
type Queue interface {
	EnqueueFanout(ctx context.Context, tenant, campaignID string) error
}

// Auditor records changes.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Transactor runs fn in one database transaction.
type Transactor interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}
