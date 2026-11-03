package message

import (
	"context"

	appprovider "github.com/razatechofficial/mail-os/application/provider"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

var _ appprovider.TestRecorder = (*Service)(nil)

// RecordProviderTest keeps a provider test send in the message log: it was
// already handed to one provider, so it is stored final (sent or failed),
// never queued, and tagged "test" (appprovider.TestRecorder).
func (s *Service) RecordProviderTest(ctx context.Context, t appprovider.TestMessage) error {
	if err := s.d.Tenants.Ensure(ctx, t.TenantID); err != nil {
		return err
	}
	now := s.now()
	m := domainmsg.Message{
		ID: t.ID, OrgID: t.TenantID, FromName: t.From.Name, FromEmail: t.From.Email, ToEmail: t.ToEmail,
		Subject: t.Subject, HTMLBody: t.HTML, TextBody: t.Text, Type: domainmsg.TypeTransactional,
		Tags: []string{"test", "provider-test"}, Metadata: map[string]any{"test": true, "source": "provider_test"},
		Actor: actorOf(ctx), ProviderID: t.ProviderID, ProviderMessageID: t.ProviderMessageID,
		Attempts: 1, LastAttemptAt: &now, CreatedAt: now, UpdatedAt: now,
	}
	if t.Sent {
		m.Status, m.SentAt = domainmsg.StatusSent, &now
	} else {
		m.Status, m.FailedAt, m.LastError = domainmsg.StatusFailed, &now, t.Error
	}
	m.Normalize()
	if err := m.Validate(); err != nil {
		return err
	}
	if err := s.d.Repo.Create(ctx, m); err != nil {
		return err
	}
	return s.d.Audit.Append(ctx, "message", m.ID, "message.provider_test", map[string]any{
		"to": logger.MaskEmail(m.ToEmail), "status": string(m.Status), "provider_id": t.ProviderID,
	})
}
