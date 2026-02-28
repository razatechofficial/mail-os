package port

import "context"

type SuppressionChecker interface {
	IsEmailSuppressed(ctx context.Context, orgID string, email string) (bool, error)
}

type QuotaChecker interface {
	CheckAndIncrement(ctx context.Context, orgID string) error
}

type OrgSettingsReader interface {
	GetRateLimit(ctx context.Context, orgID string) (int, error)
	GetDailyLimit(ctx context.Context, orgID string) (int, error)
}

type MessageEnqueuer interface {
	EnqueueForContact(ctx context.Context, orgID string, campaignID string, contactEmail string) error
}
