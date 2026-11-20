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
// price of not losing a one-time code. It first deletes every live secret
// past its expiry (at most an hour after it was stored), including any a
// final status failed to delete.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	now := s.now()
	if s.d.Secrets != nil {
		if n, err := s.d.Secrets.DeleteExpired(ctx, now); err != nil {
			logger.FromContext(ctx).Warn("sweep expired message secrets", logger.Err(err))
		} else if n > 0 {
			logger.Info("expired message secrets deleted", logger.Int64("count", n))
		}
	}
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
// override, at most 90 days), keeping the envelope; a message still not
// final after twice the retention is failed as abandoned and erased too.
// It deletes the inbound event receipts and finished webhook deliveries of
// the same age, and audits messages.purged per tenant. The counts are the
// messages whose bodies were erased.
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
		retention := time.Duration(days) * 24 * time.Hour
		before := s.now().Add(-retention)
		stuck := s.now().Add(-domainmsg.StuckFactor * retention)
		total, abandoned := 0, 0
		for {
			batch, err := s.d.Repo.PurgeCandidates(ctx, t, before, stuck, s.cfg.PurgeBatch)
			if err != nil {
				return counts, err
			}
			for _, m := range batch {
				if !m.Status.Final() {
					m.Abandon(s.now())
					abandoned++
				}
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
		records, err := s.d.Repo.PurgeRecords(ctx, t, before)
		if err != nil {
			return counts, err
		}
		if total == 0 && records == 0 {
			continue
		}
		if total > 0 {
			counts[t] = total
		}
		tctx := audit.WithTenant(ctx, t)
		if err := s.d.Audit.Append(tctx, "message", t, "messages.purged", map[string]any{"count": total, "records": records,
			"abandoned": abandoned, "retention_days": days}); err != nil {
			logger.FromContext(ctx).Error("audit messages.purged", logger.Err(err))
		}
	}
	return counts, nil
}
