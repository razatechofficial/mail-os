package message

import (
	"context"
	"errors"
	"maps"
	"time"

	analytics "github.com/razatechofficial/mail-os/application/analytics"
	"github.com/razatechofficial/mail-os/application/unsubscribe"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/webhook"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// RetryError asks the queue to try the delivery again, after the
// provider's Retry-After when it gave one.
type RetryError struct {
	Err   error
	After time.Duration
}

func (e *RetryError) Error() string { return "send will be retried: " + domainmsg.SafeDetail(e.Err) }

func (e *RetryError) Unwrap() error { return e.Err }

// RetryAfter is the worker's RetryAfter hook.
func (e *RetryError) RetryAfter() time.Duration { return e.After }

// Deliver sends one queued message: suppression check, rendering of the
// pinned version, DKIM key, the tenant's providers. A sandbox
// application's message is rendered and captured instead: no provider is
// called. A transient failure
// requeues the message and returns a RetryError; a permanent one, or the
// last attempt, records the outcome and returns nil. Messages that are no
// longer queued (cancelled, already sent) are skipped.
func (s *Service) Deliver(ctx context.Context, tenantID, id string) error {
	ctx = audit.WithTenant(ctx, tenantID)
	m, err := s.d.Repo.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if m.Status != domainmsg.StatusQueued {
		return nil
	}
	now := s.now()
	sup, err := s.d.Suppressions.Blocks(ctx, tenantID, m.ApplicationID, m.ToEmail, m.Type)
	if err != nil {
		return err
	}
	if sup != nil {
		m.LastError = "the recipient is on the suppression list (" + string(sup.Type) + ")"
		if err := m.Transition(domainmsg.StatusSuppressed, now); err != nil {
			return err
		}
		_, err := s.d.Repo.Update(ctx, m, domainmsg.StatusQueued)
		return err
	}
	unsub := s.unsubscribeURL(ctx, m)
	if m.TemplateVersionID != "" && m.HTMLBody == "" && m.TextBody == "" {
		if err := s.render(ctx, &m, unsub); err != nil {
			m.LastError = "the template could not be rendered"
			if terr := m.Transition(domainmsg.StatusFailed, now); terr != nil {
				return terr
			}
			if _, uerr := s.d.Repo.Update(ctx, m, domainmsg.StatusQueued); uerr != nil {
				return uerr
			}
			logger.FromContext(ctx).Warn("render failed", logger.String("message_id", m.ID), logger.Err(err))
			s.after(ctx, m, analytics.Failed, webhook.EventFailed)
			return nil
		}
	}
	if err := m.Transition(domainmsg.StatusSending, now); err != nil {
		return err
	}
	if ok, err := s.d.Repo.Update(ctx, m, domainmsg.StatusQueued); err != nil || !ok {
		return err // another worker claimed it
	}
	if m.Sandbox {
		if err := m.Transition(domainmsg.StatusCaptured, s.now()); err != nil {
			return err
		}
		_, err := s.d.Repo.Update(ctx, m, domainmsg.StatusSending)
		return err
	}

	out, err := m.Outgoing()
	if err != nil {
		return err
	}
	if unsub != "" && out.Headers["List-Unsubscribe"] == "" {
		if out.Headers == nil {
			out.Headers = map[string]string{}
		}
		for k, v := range s.d.Unsubscribe.Headers(unsub) {
			out.Headers[k] = v
		}
	}
	if s.d.Signer != nil {
		from := m.FromEmail
		if from == "" {
			from = s.cfg.DefaultFrom
		}
		if out.DKIM, err = s.d.Signer.SigningKey(ctx, tenantID, from); err != nil {
			logger.FromContext(ctx).Warn("dkim key unavailable; sending unsigned", logger.String("message_id", m.ID), logger.Err(err))
			out.DKIM = nil
		}
	}
	res, sendErr := s.d.Sender.Send(ctx, out)
	now = s.now()
	if sendErr == nil {
		if err := m.MarkSent(res.ProviderID, res.ProviderMessageID, now); err != nil {
			return err
		}
		if _, err := s.d.Repo.Update(ctx, m, domainmsg.StatusSending); err != nil {
			return err
		}
		s.after(ctx, m, analytics.Sent, webhook.EventSent)
		return nil
	}
	if errors.Is(sendErr, context.Canceled) && ctx.Err() != nil {
		// Shutting down: put it back for the next worker.
		_ = m.Transition(domainmsg.StatusQueued, now)
		_, _ = s.d.Repo.Update(context.WithoutCancel(ctx), m, domainmsg.StatusSending)
		return &RetryError{Err: sendErr}
	}
	retry, err := m.RecordSendFailure(sendErr, s.cfg.MaxAttempts, now)
	if err != nil {
		return err
	}
	if _, err := s.d.Repo.Update(ctx, m, domainmsg.StatusSending); err != nil {
		return err
	}
	switch m.Status {
	case domainmsg.StatusBounced:
		if err := s.d.Suppressions.RecordBounce(ctx, tenantID, m.ToEmail, m.LastError); err != nil {
			logger.FromContext(ctx).Warn("record bounce", logger.Err(err))
		}
		s.after(ctx, m, analytics.Bounced, webhook.EventBounced)
	case domainmsg.StatusFailed:
		s.after(ctx, m, analytics.Failed, webhook.EventFailed)
	}
	if retry {
		return &RetryError{Err: sendErr, After: domainmsg.RetryAfterOf(sendErr)}
	}
	return nil
}

// unsubscribeURL is the message's one-click unsubscribe link (RFC 8058):
// broadcast mail only (marketing, or an application's broadcast stream),
// and only when links are configured. A link that cannot be made leaves
// the message as its sender wrote it.
func (s *Service) unsubscribeURL(ctx context.Context, m domainmsg.Message) string {
	if s.d.Unsubscribe == nil || (m.Type != domainmsg.TypeMarketing && m.Stream != domainmsg.StreamBroadcast) {
		return ""
	}
	u, err := s.d.Unsubscribe.URL(unsubscribe.Link{TenantID: m.OrgID, ApplicationID: m.ApplicationID, Email: m.ToEmail,
		CampaignID: m.CampaignID, MessageID: m.ID})
	if err != nil {
		logger.FromContext(ctx).Warn("unsubscribe link not made", logger.String("message_id", m.ID), logger.Err(err))
		return ""
	}
	return u
}

// render fills the subject and bodies from the pinned version. unsub, when
// set, is the {{unsubscribe_url}} variable unless the data has one.
func (s *Service) render(ctx context.Context, m *domainmsg.Message, unsub string) error {
	if s.d.Versions == nil || s.d.Render == nil {
		return errors.New("templates are not available")
	}
	v, err := s.d.Versions.Version(ctx, m.OrgID, m.TemplateVersionID)
	if err != nil {
		return err
	}
	data := s.renderData(ctx, m.OrgID, m.Topic, m.TemplateData)
	if _, ok := data["unsubscribe_url"]; unsub != "" && !ok {
		data = maps.Clone(data)
		if data == nil {
			data = map[string]any{}
		}
		data["unsubscribe_url"] = unsub
	}
	c, err := s.d.Render(Content{Subject: v.Subject, HTML: v.HTMLBody, Text: v.TextBody}, data)
	if err != nil {
		return err
	}
	m.Subject, m.HTMLBody, m.TextBody = c.Subject, c.HTML, c.Text
	return nil
}

// after counts the outcome and tells the tenant's webhooks. Neither may
// fail the delivery that already happened.
func (s *Service) after(ctx context.Context, m domainmsg.Message, counter, event string) {
	if s.d.Stats != nil {
		if err := s.d.Stats.Count(ctx, m.OrgID, counter, s.now()); err != nil {
			logger.FromContext(ctx).Warn("stats", logger.Err(err))
		}
	}
	if s.d.Webhooks != nil {
		data := map[string]any{"message_id": m.ID, "status": string(m.Status), "to_email": m.ToEmail,
			"provider_id": m.ProviderID, "provider_message_id": m.ProviderMessageID, "tags": m.Tags}
		if m.LastError != "" {
			data["error"] = m.LastError
		}
		if m.ApplicationID != "" {
			data["application_id"] = m.ApplicationID
		}
		if err := s.d.Webhooks.Notify(ctx, m.OrgID, m.ApplicationID, event, m.ID, data); err != nil {
			logger.FromContext(ctx).Warn("webhook notify", logger.Err(err))
		}
	}
}
