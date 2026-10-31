package campaign

import (
	"context"
	"errors"
	"strings"

	domain "github.com/razatechofficial/mail-os/domain/campaign"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Fanout sends a sending campaign to the next pages of its recipients.
// It stops quietly when the campaign is gone or no longer sending (paused,
// cancelled), completes the campaign when no recipient is left, and queues
// its own continuation after PagesPerTask pages. A temporary sender
// failure (kind Unavailable) releases that recipient and returns the
// error, so the task retries with backoff.
func (s *Service) Fanout(ctx context.Context, tenant, campaignID string) error {
	ctx = s.d.ScopeTenant(ctx, tenant)
	c, err := s.d.Campaigns.Get(ctx, tenant, campaignID)
	if apperrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if c.Status != domain.StatusSending {
		return nil
	}
	if s.d.Sender == nil {
		return ErrSendingUnavailable
	}
	recorded, pending, err := s.d.Recipients.Count(ctx, tenant, c.ID, c.ContactListID)
	if err != nil {
		return err
	}
	if err := s.d.Campaigns.SetTotal(ctx, c.ID, recorded+pending); err != nil {
		return err
	}
	for page := 0; page < s.cfg.PagesPerTask; page++ {
		if page > 0 {
			if c, err = s.d.Campaigns.Get(ctx, tenant, campaignID); apperrors.IsNotFound(err) {
				return nil
			} else if err != nil {
				return err
			}
			if c.Status != domain.StatusSending {
				return nil
			}
		}
		batch, err := s.d.Recipients.Pending(ctx, tenant, c.ID, c.ContactListID, s.cfg.PageSize)
		if err != nil {
			return err
		}
		if err := s.sendPage(ctx, c, batch); err != nil {
			return err
		}
		if len(batch) < s.cfg.PageSize {
			return s.complete(ctx, tenant, campaignID)
		}
	}
	return s.d.Queue.EnqueueFanout(ctx, tenant, campaignID)
}

// sendPage claims and sends each recipient, then adds the page's counts.
func (s *Service) sendPage(ctx context.Context, c domain.Campaign, batch []Recipient) error {
	sent, failed := 0, 0
	defer func() {
		if sent+failed > 0 {
			if err := s.d.Campaigns.AddCounts(context.WithoutCancel(ctx), c.ID, sent, failed); err != nil {
				logger.FromContext(ctx).Error("campaign counts not saved", logger.String("campaign_id", c.ID), logger.Err(err))
			}
		}
	}()
	for _, r := range batch {
		ok, err := s.d.Recipients.Claim(ctx, c.ID, r.ContactID)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		msgID, err := s.d.Sender.SendCampaignMessage(ctx, message(c, r))
		if err != nil {
			if apperrors.KindOf(err) == apperrors.KindUnavailable || ctx.Err() != nil {
				if rerr := s.d.Recipients.Release(context.WithoutCancel(ctx), c.ID, r.ContactID); rerr != nil {
					return errors.Join(err, rerr)
				}
				return err
			}
			logger.FromContext(ctx).Warn("campaign recipient failed", logger.String("campaign_id", c.ID),
				logger.String("to", logger.MaskEmail(r.Email)), logger.Err(err))
			if err := s.d.Recipients.MarkFailed(ctx, c.ID, r.ContactID, apperrors.UserMessage(err), s.now()); err != nil {
				return err
			}
			failed++
			continue
		}
		if err := s.d.Recipients.MarkSent(ctx, c.ID, r.ContactID, msgID, s.now()); err != nil {
			return err
		}
		sent++
	}
	return nil
}

// message is the sender's view of one recipient.
func message(c domain.Campaign, r Recipient) CampaignMessage {
	return CampaignMessage{
		TenantID: c.OrgID, CampaignID: c.ID, TemplateID: c.TemplateID,
		To: r.Email, ToName: strings.TrimSpace(r.FirstName + " " + r.LastName),
		FromName: c.FromName, FromEmail: c.FromEmail,
		Data: map[string]any{
			"contact":  map[string]any{"email": r.Email, "first_name": r.FirstName, "last_name": r.LastName},
			"campaign": map[string]any{"id": c.ID, "name": c.Name, "subject": c.Subject},
		},
	}
}

// complete marks the campaign done if it is still sending.
func (s *Service) complete(ctx context.Context, tenant, campaignID string) error {
	return s.d.Tx.InTx(ctx, func(ctx context.Context) error {
		c, err := s.d.Campaigns.Lock(ctx, tenant, campaignID)
		if err != nil {
			return err
		}
		if c.Status != domain.StatusSending {
			return nil
		}
		if err := c.Complete(s.now()); err != nil {
			return err
		}
		if err := s.d.Campaigns.Update(ctx, c); err != nil {
			return err
		}
		return s.d.Audit.Append(ctx, "campaign", c.ID, "campaign.completed", map[string]any{
			"total_recipients": c.TotalRecipients, "sent": c.SentCount, "failed": c.FailedCount})
	})
}

// releaseBatch bounds one run of the release task.
const releaseBatch = 100

// Release is the periodic task: it starts scheduled campaigns that are due
// and restarts the fan-out of sending campaigns that made no progress for
// StallAfter. Without a sender it does nothing: scheduled campaigns wait.
func (s *Service) Release(ctx context.Context) error {
	if s.d.Sender == nil {
		return nil
	}
	now := s.now()
	due, err := s.d.Campaigns.Due(ctx, now, releaseBatch)
	if err != nil {
		return err
	}
	for _, d := range due {
		tctx := s.d.ScopeTenant(ctx, d.OrgID)
		c, fanout, err := s.transition(tctx, d.OrgID, d.ID, "campaign.released", func(_ context.Context, c *domain.Campaign) (bool, error) {
			return true, c.Release(now)
		})
		if apperrors.KindOf(err) == apperrors.KindConflict || apperrors.IsNotFound(err) {
			continue // launched, cancelled or deleted meanwhile
		}
		if err != nil {
			return err
		}
		if fanout {
			s.start(tctx, c)
		}
	}
	stalled, err := s.d.Campaigns.Stalled(ctx, now.Add(-s.cfg.StallAfter), releaseBatch)
	if err != nil {
		return err
	}
	for _, c := range stalled {
		s.start(ctx, c)
	}
	return nil
}
