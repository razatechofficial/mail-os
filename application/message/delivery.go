package message

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"time"

	analytics "github.com/razatechofficial/mail-os/application/analytics"
	"github.com/razatechofficial/mail-os/application/unsubscribe"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
	"github.com/razatechofficial/mail-os/domain/webhook"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/metrics"
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

// SecretExpired is the failure of an authentication-class message whose
// live secrets expired (or were never stored) before it could be sent: a
// stale code is useless, so it is not sent at all.
const SecretExpired = "secret_expired: the message's one-time code or link expired before it could be sent"

// Deliver sends one queued message: suppression check, rendering of the
// pinned version, DKIM key, the tenant's providers. A sandbox
// application's message is rendered and captured instead: no provider is
// called. A transient failure
// requeues the message and returns a RetryError; a permanent one, or the
// last attempt, records the outcome and returns nil. Messages that are no
// longer queued (cancelled, already sent) are skipped.
//
// An authentication-class message is rendered twice on every attempt: in
// full, in memory, with its live secrets from the sealed store, for the
// relay (tracking off); and redacted, from its stored data, for the row.
// Its secrets are scrubbed from every log line and error the attempt
// writes, and deleted once it is final.
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
	var live domainmsg.Secrets
	if m.AuthClass() {
		var found bool
		if live, found, err = s.openSecrets(ctx, m, now); err != nil {
			return err
		}
		if !found {
			return s.fail(ctx, m, SecretExpired, now)
		}
		ctx = logger.ScrubContext(ctx, live.Values())
	}
	sup, err := s.d.Suppressions.Blocks(ctx, tenantID, m.ApplicationID, m.ToEmail, m.Type)
	if err != nil {
		return err
	}
	if sup != nil {
		m.LastError = "the recipient is on the suppression list (" + string(sup.Type) + ")"
		if err := m.Transition(domainmsg.StatusSuppressed, now); err != nil {
			return err
		}
		_, err := s.update(ctx, m, domainmsg.StatusQueued)
		return err
	}
	unsub := s.unsubscribeURL(ctx, m)
	var sent *Content
	if m.TemplateVersionID != "" && (m.AuthClass() || m.HTMLBody == "" && m.TextBody == "") {
		c, err := s.render(ctx, &m, unsub, live)
		if err != nil {
			// The template's identity only: never the data or the error text.
			logger.FromContext(ctx).Warn("render failed", logger.String("message_id", m.ID),
				logger.String("template_id", m.TemplateID), logger.String("template_version_id", m.TemplateVersionID))
			return s.fail(ctx, m, "the template could not be rendered", now)
		}
		sent = &c
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
		_, err := s.update(ctx, m, domainmsg.StatusSending)
		return err
	}

	out, err := m.Outgoing()
	if err != nil {
		return err
	}
	if sent != nil {
		out.Subject, out.HTML, out.Text = sent.Subject, sent.HTML, sent.Text
	}
	out.NoTracking = m.AuthClass()
	if unsub != "" && out.Headers["List-Unsubscribe"] == "" {
		if out.Headers == nil {
			out.Headers = map[string]string{}
		}
		for k, v := range s.d.Unsubscribe.Headers(unsub) {
			out.Headers[k] = v
		}
	}
	var res SendResult
	var sendErr error
	if out.DKIM, sendErr = s.signingKey(ctx, tenantID, m); sendErr == nil {
		res, sendErr = s.d.Sender.Send(ctx, out)
	}
	now = s.now()
	if sendErr == nil {
		if err := m.MarkSent(res.ProviderID, res.ProviderMessageID, now); err != nil {
			return err
		}
		if len(s.cfg.DigestKey) > 0 {
			// Evidence of what was sent: of the full content, never stored.
			m.SentDigest = domainmsg.NewSentDigest(s.cfg.DigestKey, out.Subject, out.Text, out.HTML)
		}
		if _, err := s.update(ctx, m, domainmsg.StatusSending); err != nil {
			return err
		}
		s.after(ctx, m, analytics.Sent, webhook.EventSent)
		metrics.Delivered(now.Sub(acceptedAt(m)))
		return nil
	}
	// A provider may echo the content in its error: the error is scrubbed
	// before it is stored, logged or handed to the queue.
	sendErr = live.ScrubError(sendErr)
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
	m.LastError = live.Scrub(m.LastError)
	if _, err := s.update(ctx, m, domainmsg.StatusSending); err != nil {
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

// fail records a permanent failure of a queued message before it was
// handed to a provider, and tells the tenant's webhooks.
func (s *Service) fail(ctx context.Context, m domainmsg.Message, reason string, now time.Time) error {
	m.LastError = reason
	if err := m.Transition(domainmsg.StatusFailed, now); err != nil {
		return err
	}
	if _, err := s.update(ctx, m, domainmsg.StatusQueued); err != nil {
		return err
	}
	s.after(ctx, m, analytics.Failed, webhook.EventFailed)
	return nil
}

// update saves m when its status is still expect; once it is final, an
// authentication-class message's live secrets are deleted (a failed
// delete is left to the expiry sweep, which runs every few minutes).
func (s *Service) update(ctx context.Context, m domainmsg.Message, expect domainmsg.Status) (bool, error) {
	ok, err := s.d.Repo.Update(ctx, m, expect)
	if err != nil || !ok || !m.Status.Final() || !m.AuthClass() || s.d.Secrets == nil {
		return ok, err
	}
	if err := s.d.Secrets.Delete(context.WithoutCancel(ctx), m.OrgID, m.ID); err != nil {
		logger.FromContext(ctx).Warn("delete message secrets; the sweep removes them", logger.String("message_id", m.ID), logger.Err(err))
	}
	return ok, nil
}

// openSecrets reads and opens an authentication-class message's live
// secrets; found is false when there are none or they expired. A store or
// key manager failure is an error, retried by the queue.
func (s *Service) openSecrets(ctx context.Context, m domainmsg.Message, now time.Time) (domainmsg.Secrets, bool, error) {
	if s.d.Secrets == nil || s.d.SecretCipher == nil {
		return nil, false, nil
	}
	sealed, found, err := s.d.Secrets.Get(ctx, m.OrgID, m.ID, now)
	if err != nil || !found {
		return nil, false, err
	}
	plain, err := s.d.SecretCipher.Open(ctx, sealed)
	if err != nil {
		return nil, false, err
	}
	var live domainmsg.Secrets
	if err := json.Unmarshal(plain, &live); err != nil {
		return nil, false, err
	}
	return live, true, nil
}

// signingKey is the DKIM key for the message's sender, or nil when the
// sender is on no verified domain. A verified domain whose key cannot be
// opened (key manager or KMS down) is a transient send failure: mail sent
// unsigned from that domain would fail DMARC, so it waits and is retried
// like a provider outage, and fails after the last attempt.
func (s *Service) signingKey(ctx context.Context, tenantID string, m domainmsg.Message) (*sendingdomain.SigningKey, error) {
	if s.d.Signer == nil {
		return nil, nil
	}
	from := m.FromEmail
	if from == "" {
		from = s.cfg.DefaultFrom
	}
	key, err := s.d.Signer.SigningKey(ctx, tenantID, from)
	if err != nil {
		logger.FromContext(ctx).Warn("dkim key unavailable; the send waits for it", logger.String("message_id", m.ID), logger.Err(err))
		return nil, &domainmsg.SendError{Provider: "dkim", Reason: domainmsg.ReasonUnavailable,
			Detail: "the sending domain's DKIM key could not be opened", Err: err}
	}
	return key, nil
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

// render fills m's subject and bodies from the pinned version and its
// stored data, and returns what the relay sends: the same, or for an
// authentication-class message a render with its live secrets merged in,
// which is never stored. unsub, when set, is the {{unsubscribe_url}}
// variable unless the data has one.
func (s *Service) render(ctx context.Context, m *domainmsg.Message, unsub string, live domainmsg.Secrets) (Content, error) {
	if s.d.Versions == nil || s.d.Render == nil {
		return Content{}, errors.New("templates are not available")
	}
	v, err := s.d.Versions.Version(ctx, m.OrgID, m.TemplateVersionID)
	if err != nil {
		return Content{}, err
	}
	data := s.renderData(ctx, m.OrgID, m.Topic, m.TemplateData)
	if _, ok := data["unsubscribe_url"]; unsub != "" && !ok {
		data = maps.Clone(data)
		if data == nil {
			data = map[string]any{}
		}
		data["unsubscribe_url"] = unsub
	}
	tpl := Content{Subject: v.Subject, HTML: v.HTMLBody, Text: v.TextBody}
	stored, err := s.d.Render(tpl, data)
	if err != nil {
		return Content{}, err
	}
	sent := stored
	if len(live) > 0 {
		if sent, err = s.d.Render(tpl, live.Merge(data)); err != nil {
			return Content{}, err
		}
		stored = Content{Subject: live.Scrub(stored.Subject), HTML: live.Scrub(stored.HTML), Text: live.Scrub(stored.Text)}
	}
	m.Subject, m.HTMLBody, m.TextBody = stored.Subject, stored.HTML, stored.Text
	return sent, nil
}

// acceptedAt is when the message became due: its scheduled time, else
// when it was accepted.
func acceptedAt(m domainmsg.Message) time.Time {
	if m.ScheduledAt != nil && m.ScheduledAt.After(m.CreatedAt) {
		return *m.ScheduledAt
	}
	return m.CreatedAt
}

// after counts the outcome and tells the tenant's webhooks. Neither may
// fail the delivery that already happened.
func (s *Service) after(ctx context.Context, m domainmsg.Message, counter, event string) {
	metrics.Message(counter)
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
