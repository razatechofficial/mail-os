package campaign

import (
	"context"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/campaign"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Deps are the service's ports.
type Deps struct {
	Campaigns  Repository
	Targets    Targets
	Recipients Recipients
	Queue      Queue
	// Sender is nil until the messaging slice provides one; launching and
	// resuming then answer 503 and scheduled campaigns wait.
	Sender CampaignSender
	Tx     Transactor
	Audit  Auditor
	// ScopeTenant scopes the audit events a worker writes (no principal)
	// to the campaign's tenant.
	ScopeTenant func(ctx context.Context, tenant string) context.Context
}

// Config tunes the fan-out.
type Config struct {
	// PageSize is how many recipients one page hands to the sender
	// (default 100).
	PageSize int
	// PagesPerTask bounds one task; the fan-out then continues in a new
	// one (default 20).
	PagesPerTask int
	// StallAfter is how long a sending campaign may go without progress
	// before the release task restarts its fan-out (default 2 minutes).
	StallAfter time.Duration
}

// Service is the campaign use case.
type Service struct {
	d   Deps
	cfg Config
	now func() time.Time
}

// ErrSendingUnavailable answers a launch or resume while no sender is
// configured.
var ErrSendingUnavailable = apperrors.Unavailable("campaign sending is not available yet")

// NewService builds the service.
func NewService(d Deps, cfg Config) *Service {
	if cfg.PageSize <= 0 {
		cfg.PageSize = 100
	}
	if cfg.PagesPerTask <= 0 {
		cfg.PagesPerTask = 20
	}
	if cfg.StallAfter <= 0 {
		cfg.StallAfter = 2 * time.Minute
	}
	if d.ScopeTenant == nil {
		d.ScopeTenant = func(ctx context.Context, _ string) context.Context { return ctx }
	}
	return &Service{d: d, cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

// Get returns one of the tenant's campaigns.
func (s *Service) Get(ctx context.Context, tenant, id string) (domain.Campaign, error) {
	return s.d.Campaigns.Get(ctx, tenant, id)
}

// List returns one page of the tenant's campaigns.
func (s *Service) List(ctx context.Context, tenant string, f Filter) ([]domain.Campaign, int, error) {
	return s.d.Campaigns.List(ctx, tenant, f)
}

// checkTargets refuses a template or list that is not the tenant's.
func (s *Service) checkTargets(ctx context.Context, c domain.Campaign) error {
	var errs []apperrors.FieldError
	ok, err := s.d.Targets.TemplateExists(ctx, c.OrgID, c.TemplateID)
	if err != nil {
		return err
	}
	if !ok {
		errs = append(errs, apperrors.FieldError{Field: "template_id", Code: "not_found", Message: "template not found"})
	}
	if ok, err = s.d.Targets.ListExists(ctx, c.OrgID, c.ContactListID); err != nil {
		return err
	}
	if !ok {
		errs = append(errs, apperrors.FieldError{Field: "contact_list_id", Code: "not_found", Message: "contact list not found"})
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

// Create validates, stores and audits a draft campaign.
func (s *Service) Create(ctx context.Context, tenant string, c domain.Campaign) (domain.Campaign, error) {
	c.OrgID = tenant
	if err := c.Check(); err != nil {
		return domain.Campaign{}, err
	}
	if err := s.checkTargets(ctx, c); err != nil {
		return domain.Campaign{}, err
	}
	now := s.now()
	c.ID, c.Status, c.CreatedAt, c.UpdatedAt = id.New(), domain.StatusDraft, now, now
	c.StartedAt, c.CompletedAt, c.TotalRecipients, c.SentCount, c.FailedCount = nil, nil, 0, 0, 0
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		if err := s.d.Campaigns.Create(ctx, c); err != nil {
			return err
		}
		return s.d.Audit.Change(ctx, "campaign", c.ID, "campaign.created", nil, c, nil)
	})
	if err != nil {
		return domain.Campaign{}, err
	}
	return c, nil
}

// Update is a partial update: nil fields keep their value.
type Update struct {
	Name          *string
	Subject       *string
	FromName      *string
	FromEmail     *string
	TemplateID    *string
	ContactListID *string
	Type          *domain.Type
	ScheduledAt   *time.Time
	Metadata      *map[string]any
}

// Update changes a draft or scheduled campaign and audits before and after.
func (s *Service) Update(ctx context.Context, tenant, campaignID string, u Update) (domain.Campaign, error) {
	var out domain.Campaign
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		before, err := s.d.Campaigns.Lock(ctx, tenant, campaignID)
		if err != nil {
			return err
		}
		if err := before.Editable(); err != nil {
			return err
		}
		c := before
		set := func(dst *string, v *string) {
			if v != nil {
				*dst = *v
			}
		}
		set(&c.Name, u.Name)
		set(&c.Subject, u.Subject)
		set(&c.FromName, u.FromName)
		set(&c.FromEmail, u.FromEmail)
		set(&c.TemplateID, u.TemplateID)
		set(&c.ContactListID, u.ContactListID)
		if u.Type != nil {
			c.Type = *u.Type
		}
		if u.ScheduledAt != nil {
			at := u.ScheduledAt.UTC()
			c.ScheduledAt = &at
		}
		if u.Metadata != nil {
			c.Metadata = *u.Metadata
		}
		if err := c.Check(); err != nil {
			return err
		}
		if err := s.checkTargets(ctx, c); err != nil {
			return err
		}
		c.UpdatedAt = s.now()
		if err := s.d.Campaigns.Update(ctx, c); err != nil {
			return err
		}
		out = c
		return s.d.Audit.Change(ctx, "campaign", c.ID, "campaign.updated", before, c, nil)
	})
	return out, err
}

// Delete hides a campaign that is not sending.
func (s *Service) Delete(ctx context.Context, tenant, campaignID string) error {
	return s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		c, err := s.d.Campaigns.Lock(ctx, tenant, campaignID)
		if err != nil {
			return err
		}
		if err := c.Deletable(); err != nil {
			return err
		}
		if err := s.d.Campaigns.Delete(ctx, tenant, campaignID); err != nil {
			return err
		}
		return s.d.Audit.Change(ctx, "campaign", campaignID, "campaign.deleted", c, nil, nil)
	})
}

// transition locks the campaign, applies change and audits action. It
// reports the campaign after the change and whether a fan-out should start.
func (s *Service) transition(ctx context.Context, tenant, campaignID, action string, change func(ctx context.Context, c *domain.Campaign) (bool, error)) (domain.Campaign, bool, error) {
	var out domain.Campaign
	var fanout bool
	err := s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		c, err := s.d.Campaigns.Lock(ctx, tenant, campaignID)
		if err != nil {
			return err
		}
		before := c.Status
		if fanout, err = change(ctx, &c); err != nil {
			return err
		}
		if err := s.d.Campaigns.Update(ctx, c); err != nil {
			return err
		}
		out = c
		meta := map[string]any{"status_before": string(before), "status_after": string(c.Status)}
		if c.ScheduledAt != nil && c.Status == domain.StatusScheduled {
			meta["scheduled_at"] = c.ScheduledAt.Format(time.RFC3339)
		}
		return s.d.Audit.Append(ctx, "campaign", c.ID, action, meta)
	})
	if err != nil {
		return domain.Campaign{}, false, err
	}
	return out, fanout, nil
}

// start queues the fan-out after the status change committed. A failed
// enqueue is logged, not returned: the campaign is sending, and the
// release task restarts a fan-out that makes no progress.
func (s *Service) start(ctx context.Context, c domain.Campaign) {
	if err := s.d.Queue.EnqueueFanout(ctx, c.OrgID, c.ID); err != nil {
		logger.FromContext(ctx).Error("campaign fan-out enqueue failed; the release task retries it",
			logger.String("campaign_id", c.ID), logger.Err(err))
	}
}

// Launch sends a draft or scheduled campaign now, or holds a draft with a
// future scheduled_at until then.
func (s *Service) Launch(ctx context.Context, tenant, campaignID string) (domain.Campaign, error) {
	if s.d.Sender == nil {
		return domain.Campaign{}, ErrSendingUnavailable
	}
	c, fanout, err := s.transition(ctx, tenant, campaignID, "campaign.launched", func(ctx context.Context, c *domain.Campaign) (bool, error) {
		sending, err := c.Launch(s.now())
		if err != nil {
			return false, err
		}
		return sending, s.checkTargets(ctx, *c)
	})
	if err == nil && fanout {
		s.start(ctx, c)
	}
	return c, err
}

// Pause stops a sending campaign after the page in flight.
func (s *Service) Pause(ctx context.Context, tenant, campaignID string) (domain.Campaign, error) {
	c, _, err := s.transition(ctx, tenant, campaignID, "campaign.paused", func(ctx context.Context, c *domain.Campaign) (bool, error) {
		return false, c.Pause(s.now())
	})
	return c, err
}

// Resume continues a paused campaign with the recipients not yet sent to.
func (s *Service) Resume(ctx context.Context, tenant, campaignID string) (domain.Campaign, error) {
	if s.d.Sender == nil {
		return domain.Campaign{}, ErrSendingUnavailable
	}
	c, _, err := s.transition(ctx, tenant, campaignID, "campaign.resumed", func(ctx context.Context, c *domain.Campaign) (bool, error) {
		return true, c.Resume(s.now())
	})
	if err == nil {
		s.start(ctx, c)
	}
	return c, err
}

// Cancel ends a campaign; a fan-out in flight stops after its page.
func (s *Service) Cancel(ctx context.Context, tenant, campaignID string) (domain.Campaign, error) {
	c, _, err := s.transition(ctx, tenant, campaignID, "campaign.cancelled", func(ctx context.Context, c *domain.Campaign) (bool, error) {
		return false, c.Cancel(s.now())
	})
	return c, err
}
