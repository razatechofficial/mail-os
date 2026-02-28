package container

import (
	"context"

	"github.com/razatechofficial/mail-os/internal/core/message"
	"github.com/razatechofficial/mail-os/internal/core/organization"
	"github.com/razatechofficial/mail-os/internal/core/suppression"
	"github.com/razatechofficial/mail-os/internal/port"
)

type suppressionCheckerAdapter struct {
	svc suppression.Service
}

func (a *suppressionCheckerAdapter) IsEmailSuppressed(ctx context.Context, orgID string, email string) (bool, error) {
	return a.svc.IsSuppressed(ctx, orgID, email)
}

type quotaCheckerAdapter struct {
	svc organization.Service
}

func (a *quotaCheckerAdapter) CheckAndIncrement(ctx context.Context, orgID string) error {
	return a.svc.CheckQuota(ctx, orgID)
}

type messageEnqueuerAdapter struct {
	svc message.Service
}

func (a *messageEnqueuerAdapter) EnqueueForContact(ctx context.Context, orgID string, campaignID string, contactEmail string) error {
	return a.svc.EnqueueCampaignEmail(ctx, orgID, campaignID, contactEmail)
}

var (
	_ port.SuppressionChecker = (*suppressionCheckerAdapter)(nil)
	_ port.QuotaChecker       = (*quotaCheckerAdapter)(nil)
	_ port.MessageEnqueuer    = (*messageEnqueuerAdapter)(nil)
)
