// Package applications is the application registry use case: a tenant's
// administrators register the projects that send through MailOS, each bound
// to its IAM OAuth client, and every service or browser call is resolved
// to its application and authorised against it: who may call (an active
// application of the token's tenant), what it may send (message types,
// verified senders, stream), and how much (per-minute rate, daily quota,
// and for browser users a per-user hourly limit). Each refusal has a
// stable reason (domain/application.Reason) and is audited.
//
// IAM's own client is a system application, seeded from configuration at
// startup (SeedSystem), so the platform works without a console step.
package applications

import (
	"context"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/application"
)

// Filter selects a tenant's applications.
type Filter struct {
	TenantID string
	Status   string
	Kind     string
	Limit    int
	Offset   int
}

// StatusCount is the number of an application's messages in one status.
type StatusCount struct {
	Day    time.Time
	Status string
	Count  int
}

// Repository stores applications.
type Repository interface {
	// Create inserts a; a client_id that is already an application, or a
	// name the tenant already uses, is apperrors.Conflict.
	Create(ctx context.Context, a domain.Application) error
	Update(ctx context.Context, a domain.Application) error
	Delete(ctx context.Context, tenantID, id string) error
	// Get returns the tenant's application, apperrors.NotFound otherwise.
	Get(ctx context.Context, tenantID, id string) (domain.Application, error)
	// ByClientID returns the application of an IAM client in any tenant,
	// ErrNotFound when there is none.
	ByClientID(ctx context.Context, clientID string) (domain.Application, error)
	List(ctx context.Context, f Filter) ([]domain.Application, int, error)
	// MessageCounts counts the application's messages per UTC day and
	// status since the given time.
	MessageCounts(ctx context.Context, tenantID, id string, since time.Time) ([]StatusCount, error)
}

// Domains answers whether an address is on one of the tenant's verified
// sending domains (application/sendingdomain).
type Domains interface {
	VerifiedFrom(ctx context.Context, tenantID, fromEmail string) (bool, error)
}

// Counter keeps fixed-window counters (Redis).
type Counter interface {
	// Take adds n to key, which expires after ttl, unless the total would
	// exceed limit; then it adds nothing and returns false.
	Take(ctx context.Context, key string, n, limit int64, ttl time.Duration) (bool, error)
	// Peek reads key (0 when absent).
	Peek(ctx context.Context, key string) (int64, error)
}

// Tenants provisions the tenant a system application belongs to.
type Tenants interface {
	Ensure(ctx context.Context, tenantID string) error
}

// Auditor records changes and refusals.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Config tunes the registry.
type Config struct {
	// AllowPlaintext permits http:// spa origins (local and test).
	AllowPlaintext bool
	// ReservedClients are IAM clients that can never be an application:
	// the MailOS console's own clients.
	ReservedClients []string
}
