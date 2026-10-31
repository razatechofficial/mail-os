package message

import (
	"context"
	"time"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// sweepBatch bounds one release or sweep.
const sweepBatch = 500

// queuedGrace is how long a queued message may wait before the sweep
// queues it again (its enqueue was lost).
const queuedGrace = 2 * time.Minute

// ReleaseScheduled queues the scheduled messages whose time has come.
func (s *Service) ReleaseScheduled(ctx context.Context) (int, error) {
	due, err := s.d.Repo.DueScheduled(ctx, s.now(), sweepBatch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range due {
		if err := m.Transition(domainmsg.StatusQueued, s.now()); err != nil {
			continue
		}
		ok, err := s.d.Repo.Update(ctx, m, domainmsg.StatusScheduled)
		if err != nil {
			return n, err
		}
		if !ok {
			continue // cancelled meanwhile
		}
		if err := s.d.Queue.EnqueueSend(ctx, m); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Sweep queues again what was lost: queued messages whose task vanished,
// and sending ones whose worker died. A worker that died after the
// provider accepted the message makes the retry a duplicate; that is the
// price of not losing a one-time code.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	now := s.now()
	stale, err := s.d.Repo.Stale(ctx, now.Add(-queuedGrace), now.Add(-s.cfg.StaleSending), sweepBatch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range stale {
		if m.Status == domainmsg.StatusSending {
			if err := m.Transition(domainmsg.StatusQueued, now); err != nil {
				continue
			}
			if ok, err := s.d.Repo.Update(ctx, m, domainmsg.StatusSending); err != nil || !ok {
				continue
			}
		}
		if err := s.d.Queue.EnqueueSend(ctx, m); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Purge erases the bodies and template data of finished messages past
// each tenant's retention (MESSAGE_RETENTION_DAYS, or the tenant's
// override), keeping the envelope, and audits messages.purged per tenant.
func (s *Service) Purge(ctx context.Context) (map[string]int, error) {
	tenants, err := s.d.Repo.PurgeTenants(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, t := range tenants {
		settings, err := s.d.Tenants.Settings(ctx, t)
		if err != nil {
			return counts, err
		}
		days := settings.RetentionDays(s.cfg.RetentionDays)
		before := s.now().Add(-time.Duration(days) * 24 * time.Hour)
		total := 0
		for {
			batch, err := s.d.Repo.PurgeCandidates(ctx, t, before, s.cfg.PurgeBatch)
			if err != nil {
				return counts, err
			}
			for _, m := range batch {
				m.PurgeBody(s.now())
				if err := s.d.Repo.SavePurged(ctx, m); err != nil {
					return counts, err
				}
			}
			total += len(batch)
			if len(batch) < s.cfg.PurgeBatch {
				break
			}
		}
		if total == 0 {
			continue
		}
		counts[t] = total
		tctx := audit.WithTenant(ctx, t)
		if err := s.d.Audit.Append(tctx, "message", t, "messages.purged", map[string]any{"count": total, "retention_days": days}); err != nil {
			logger.FromContext(ctx).Error("audit messages.purged", logger.Err(err))
		}
	}
	return counts, nil
}
