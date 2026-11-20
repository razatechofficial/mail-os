// Package message is the message use case: direct and templated sends,
// the delivery the worker runs for each message, scheduled releases, the
// retention purge, and the console's reads. Bodies are never in a list or
// get; reading one is its own audited call, and the values of a topic's
// secret variables are masked wherever a message is shown (contract §6).
package message

import (
	"context"
	"time"

	"github.com/razatechofficial/mail-os/application/applications"
	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/application/unsubscribe"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
	"github.com/razatechofficial/mail-os/domain/suppression"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
)

// Filter selects messages for a list.
type Filter struct {
	TenantID      string
	ApplicationID string
	Status        string
	Type          string
	Topic         string
	To            string
	// Search matches part of the recipient address, case-insensitively.
	// Subjects are not searched: they may hold a secret variable's value.
	Search string
	From   *time.Time
	Until  *time.Time
	// SortBy is created_at, updated_at, status or to_email (default
	// created_at); SortOrder is asc or desc (default desc).
	SortBy    string
	SortOrder string
	Limit     int
	Offset    int
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
	// PurgeRecords deletes the tenant's inbound event receipts and finished
	// webhook deliveries from before t, and returns how many.
	PurgeRecords(ctx context.Context, tenantID string, before time.Time) (int64, error)
}

// SecretStore keeps the sealed live secrets of authentication-class
// messages (message_secrets) until the message is final or the secrets
// expire, whichever is first; only the delivery path reads them.
type SecretStore interface {
	// InTx runs fn in one transaction, so a message and its secrets are
	// stored together or not at all.
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
	Put(ctx context.Context, tenantID, messageID, sealed string, createdAt, expiresAt time.Time) error
	// Get returns the sealed secrets; ok is false when there are none or
	// they expired by now.
	Get(ctx context.Context, tenantID, messageID string, now time.Time) (sealed string, ok bool, err error)
	Delete(ctx context.Context, tenantID, messageID string) error
	// DeleteExpired deletes every row expired by now, and returns how many.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// Cipher seals and opens the live secrets (key manager purpose
// message_secret).
type Cipher interface {
	Seal(ctx context.Context, plaintext []byte) (string, error)
	Open(ctx context.Context, ciphertext string) ([]byte, error)
}

// Queue schedules a message's delivery: the critical queue for
// transactional mail.
type Queue interface {
	EnqueueSend(ctx context.Context, m domainmsg.Message) error
}

// Suppressions is the tenant's suppression list: its tenant-wide entries
// and those of the sending application.
type Suppressions interface {
	Blocks(ctx context.Context, tenantID, applicationID, email string, mt domainmsg.Type) (*suppression.Suppression, error)
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

// Notifier posts message events to the tenant's webhooks: the tenant-wide
// ones and those of the sending application.
type Notifier interface {
	Notify(ctx context.Context, tenantID, applicationID, event, messageID string, data map[string]any) error
}

// Applications applies a sending application's rules to a message
// (applications.Service.AuthorizeSend).
type Applications interface {
	AuthorizeSend(ctx context.Context, applicationID string, ask applications.Ask) (applications.Grant, error)
}

// Stats counts sends.
type Stats interface {
	Count(ctx context.Context, tenantID, counter string, at time.Time) error
}

// Auditor records calls.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Unsubscribes issues the one-click unsubscribe link of broadcast mail
// (application/unsubscribe.Service).
type Unsubscribes interface {
	URL(l unsubscribe.Link) (string, error)
	Headers(u string) map[string]string
}

// Verdict is a virus scan's outcome; Reason names what was found.
type Verdict struct {
	Clean  bool
	Reason string
}

// Scanner checks an attachment before its message is queued: the
// virus-scan hook point (a ClamAV daemon, a cloud scanning API). An error
// means the file could not be scanned, and the send is refused as
// temporarily unavailable rather than sent unscanned.
type Scanner interface {
	Scan(ctx context.Context, name, contentType string, data []byte) (Verdict, error)
}

// NoScan is the default Scanner: every file is clean.
type NoScan struct{}

// Scan implements Scanner.
func (NoScan) Scan(context.Context, string, string, []byte) (Verdict, error) {
	return Verdict{Clean: true}, nil
}

// Deps are the service's ports. Templates, Versions, Branding, Signer,
// Webhooks, Stats, Events, Feedback, Unsubscribe and Scanner may be nil;
// Applications is
// required.
type Deps struct {
	Applications Applications
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
	// Events and Feedback record the providers' delivery webhooks; both
	// may be nil (then no provider events are taken).
	Events   DeliveryEvents
	Feedback Feedback
	// Unsubscribe adds List-Unsubscribe to broadcast mail; nil leaves it
	// to the sender.
	Unsubscribe Unsubscribes
	// Scanner checks attachments; nil is NoScan.
	Scanner Scanner
	// Secrets and SecretCipher keep the live secrets of
	// authentication-class messages for retries. Without them such a
	// message is refused, never stored with its secrets.
	Secrets      SecretStore
	SecretCipher Cipher
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
	// Attachments bound a message's files (ATTACHMENTS_*); the zero value
	// refuses every attachment.
	Attachments domainmsg.AttachmentLimits
	// SecretTTL is the longest an authentication-class message's live
	// secrets are kept for retries (at most and by default an hour).
	SecretTTL time.Duration
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
	if c.SecretTTL <= 0 || c.SecretTTL > domainmsg.DefaultSecretTTL {
		c.SecretTTL = domainmsg.DefaultSecretTTL
	}
	return c
}
