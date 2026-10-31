// Package message is the message use case: direct and templated sends,
// the delivery the worker runs for each message, scheduled releases, the
// retention purge, and the console's reads. Bodies are never in a list or
// get; reading one is its own audited call, and the values of a topic's
// secret variables are masked wherever a message is shown (contract §6).
package message

import (
	"context"
	"time"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
	"github.com/razatechofficial/mail-os/domain/suppression"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
)

// Filter selects messages for a list.
type Filter struct {
	TenantID string
	Status   string
	Type     string
	Topic    string
	To       string
	From     *time.Time
	Until    *time.Time
	Limit    int
	Offset   int
}

// Repository stores messages.
type Repository interface {
	// Create inserts m. A second message with the tenant's idempotency key
	// fails with ErrDuplicateKey.
	Create(ctx context.Context, m domainmsg.Message) error
	// Get returns the tenant's message, apperrors.NotFound otherwise.
	Get(ctx context.Context, tenantID, id string) (domainmsg.Message, error)
	ByIdempotencyKey(ctx context.Context, tenantID, key string) (*domainmsg.Message, error)
	List(ctx context.Context, f Filter) ([]domainmsg.Message, int, error)
	// Update saves m when its stored status is still expect (compare and
	// swap); false when another worker or request moved it first.
	Update(ctx context.Context, m domainmsg.Message, expect domainmsg.Status) (bool, error)
	// DueScheduled lists scheduled messages whose time has come.
	DueScheduled(ctx context.Context, now time.Time, limit int) ([]domainmsg.Message, error)
	// Stale lists queued messages not touched since queuedBefore and
	// sending ones not touched since sendingBefore.
	Stale(ctx context.Context, queuedBefore, sendingBefore time.Time, limit int) ([]domainmsg.Message, error)
	// PurgeTenants lists tenants with stored bodies of final messages.
	PurgeTenants(ctx context.Context) ([]string, error)
	// PurgeCandidates lists final messages created before t whose body is
	// still stored; SavePurged writes a purged message back.
	PurgeCandidates(ctx context.Context, tenantID string, before time.Time, limit int) ([]domainmsg.Message, error)
	SavePurged(ctx context.Context, m domainmsg.Message) error
}

// Queue schedules a message's delivery: the critical queue for
// transactional mail.
type Queue interface {
	EnqueueSend(ctx context.Context, m domainmsg.Message) error
}

// Suppressions is the tenant's suppression list.
type Suppressions interface {
	Blocks(ctx context.Context, tenantID, email string, mt domainmsg.Type) (*suppression.Suppression, error)
	RecordBounce(ctx context.Context, tenantID, email, reason string) error
}

// Tenants provisions tenants and reads their retention.
type Tenants interface {
	Ensure(ctx context.Context, tenantID string) error
	Settings(ctx context.Context, tenantID string) (domaintenant.Settings, error)
}

// TemplateResolver returns a template's published version for a locale
// (falling back to its default locale): application/template.Service.
type TemplateResolver interface {
	ResolvePublished(ctx context.Context, tenantID string, ref apptemplate.Ref, locale string) (domaintemplate.Template, domaintemplate.Version, error)
}

// VersionReader reads a pinned version.
type VersionReader interface {
	Version(ctx context.Context, tenantID, versionID string) (domaintemplate.Version, error)
}

// BrandingReader reads the tenant's branding (brand.company_name).
type BrandingReader interface {
	Branding(ctx context.Context, tenantID string) (domaintemplate.Branding, error)
}

// Content is a rendered subject and bodies.
type Content struct {
	Subject string
	HTML    string
	Text    string
}

// Renderer renders a template version's content with event data
// (infrastructure/render.Render).
type Renderer func(c Content, data map[string]any) (Content, error)

// SendResult is a provider's acceptance.
type SendResult struct {
	ProviderID        string
	ProviderMessageID string
}

// Sender hands a message to the tenant's providers (the mailer router).
type Sender interface {
	Send(ctx context.Context, out domainmsg.Outgoing) (SendResult, error)
}

// Signer returns the DKIM key of the verified domain fromEmail is on.
type Signer interface {
	SigningKey(ctx context.Context, tenantID, fromEmail string) (*sendingdomain.SigningKey, error)
}

// Notifier posts message events to the tenant's webhooks.
type Notifier interface {
	Notify(ctx context.Context, tenantID, event, messageID string, data map[string]any) error
}

// Stats counts sends.
type Stats interface {
	Count(ctx context.Context, tenantID, counter string, at time.Time) error
}

// Auditor records calls.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Deps are the service's ports. Templates, Versions, Branding, Signer,
// Webhooks and Stats may be nil.
type Deps struct {
	Repo         Repository
	Queue        Queue
	Suppressions Suppressions
	Tenants      Tenants
	Templates    TemplateResolver
	Versions     VersionReader
	Branding     BrandingReader
	Render       Renderer
	Sender       Sender
	Signer       Signer
	Webhooks     Notifier
	Stats        Stats
	Audit        Auditor
}

// Config tunes sending and retention.
type Config struct {
	// MaxAttempts bounds sends per message (WORKER_MAX_RETRY + 1).
	MaxAttempts int
	// RetentionDays is the platform body retention (MESSAGE_RETENTION_DAYS).
	RetentionDays int
	// PurgeBatch bounds one purge query (MESSAGE_RETENTION_BATCH).
	PurgeBatch int
	// DefaultFrom is the platform sender, used to find a DKIM key when a
	// message names no sender.
	DefaultFrom string
	// StaleSending is how long a message may stay sending before the sweep
	// queues it again (a worker died mid-send).
	StaleSending time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 9
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = 30
	}
	if c.PurgeBatch <= 0 {
		c.PurgeBatch = 1000
	}
	if c.StaleSending <= 0 {
		c.StaleSending = 10 * time.Minute
	}
	return c
}
