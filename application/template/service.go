// Package template is the email template designer's use case
// (docs/mailos-template-api.md): templates and their metadata, the draft
// of each locale, publishing it into an immutable version under the
// tenant's four-eyes rule, restoring, preview and test sends, and the
// organization's branding. It also resolves the published version a send
// renders, for the messaging slice.
//
// Every call is scoped to a tenant: another tenant's template is 404.
package template

import (
	"context"
	"strings"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/template"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// Repository stores templates, drafts, versions and branding. Reads of a
// template are scoped to the tenant and skip deleted ones; a miss is
// apperrors.ErrNotFound.
type Repository interface {
	// InTx runs fn in one transaction; calls with its ctx join it.
	InTx(ctx context.Context, fn func(ctx context.Context) error) error

	List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Template, int, error)
	Get(ctx context.Context, tenantID, templateID string) (domain.Template, error)
	// GetForUpdate is Get, locking the row until the transaction ends, so
	// publishes of one template number their versions one at a time.
	GetForUpdate(ctx context.Context, tenantID, templateID string) (domain.Template, error)
	GetBySlug(ctx context.Context, tenantID, slug string) (domain.Template, error)
	GetByTopic(ctx context.Context, tenantID, topic string) (domain.Template, error)
	// Create and Update return ErrSlugTaken or ErrTopicTaken for a slug or
	// topic another live template of the tenant has.
	Create(ctx context.Context, t domain.Template) error
	Update(ctx context.Context, t domain.Template) error
	Delete(ctx context.Context, tenantID, templateID string, at time.Time) error

	// Draft returns the saved draft, or ok false when none is.
	Draft(ctx context.Context, templateID string, locale domain.Locale) (d domain.Draft, ok bool, err error)
	// SaveDraft stores d if the stored revision is still prev (0: none is
	// saved), else returns a CONFLICT.
	SaveDraft(ctx context.Context, d domain.Draft, prev int) error

	// Versions lists newest first; locale "" lists every locale.
	Versions(ctx context.Context, templateID string, locale domain.Locale) ([]domain.Version, error)
	ActiveVersion(ctx context.Context, templateID string, locale domain.Locale) (domain.Version, error)
	VersionByNumber(ctx context.Context, templateID string, number int) (domain.Version, error)
	// VersionByID finds a version of one of the tenant's templates.
	VersionByID(ctx context.Context, tenantID, versionID string) (domain.Version, error)
	MaxVersionNumber(ctx context.Context, templateID string) (int, error)
	// InsertVersion stores v as its locale's active version, deactivating
	// the one before it.
	InsertVersion(ctx context.Context, v domain.Version) error

	// Branding returns the saved branding, or ok false when none is.
	Branding(ctx context.Context, tenantID string) (b domain.Branding, ok bool, err error)
	SaveBranding(ctx context.Context, b domain.Branding, by string) error
}

// Errors the repository returns for unique keys.
var (
	ErrSlugTaken  = apperrors.Invalid("slug", domain.CodeTaken, "another template already uses this slug")
	ErrTopicTaken = apperrors.Invalid("topic", domain.CodeTaken, "another template already serves this topic")
)

// Settings reads the tenant's security settings (four-eyes publishing).
type Settings interface {
	Settings(ctx context.Context, tenantID string) (domaintenant.Settings, error)
}

// Auditor records changes (infrastructure/audit.Writer).
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// TestMessage is a rendered test send.
type TestMessage struct {
	TenantID  string
	FromName  string
	FromEmail string
	To        string
	Subject   string
	HTML      string
	Text      string
	Tags      []string
}

// TestSender sends a test message as transactional mail.
type TestSender interface {
	SendTest(ctx context.Context, m TestMessage) (messageID, status string, err error)
}

// DomainChecker reports whether fromEmail is on one of the tenant's
// verified sending domains.
type DomainChecker interface {
	VerifiedFrom(ctx context.Context, tenantID, fromEmail string) (bool, error)
}

// Deps are the service's collaborators. Sender and Domains may be nil
// until messaging is wired: test sends then answer 503.
type Deps struct {
	Repo     Repository
	Settings Settings
	Audit    Auditor
	Sender   TestSender
	Domains  DomainChecker
	// RawHTMLBlocks is FEATURE_RAW_HTML_BLOCKS: administrators may save
	// html design nodes.
	RawHTMLBlocks bool
	Now           func() time.Time
	NewID         func() string
}

// Service is the template use case.
type Service struct {
	repo     Repository
	settings Settings
	audit    Auditor
	sender   TestSender
	domains  DomainChecker
	rawHTML  bool
	now      func() time.Time
	newID    func() string
}

// New builds the service.
func New(d Deps) *Service {
	s := &Service{repo: d.Repo, settings: d.Settings, audit: d.Audit, sender: d.Sender, domains: d.Domains,
		rawHTML: d.RawHTMLBlocks, now: d.Now, newID: d.NewID}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	if s.newID == nil {
		s.newID = id.New
	}
	return s
}

// SetTestSend wires test sends to messaging.
func (s *Service) SetTestSend(sender TestSender, domains DomainChecker) {
	s.sender, s.domains = sender, domains
}

// Editor is who changes content: the IAM user, and whether they are a
// MailOS administrator (who alone may save raw HTML blocks).
type Editor struct {
	ID    string
	Admin bool
}

func (s *Service) allowRawHTML(e Editor) bool { return s.rawHTML && e.Admin }

// ── templates ─────────────────────────────────────────────────────────────

// List returns one page of the tenant's templates.
func (s *Service) List(ctx context.Context, tenantID string, limit, offset int) ([]domain.Template, int, error) {
	return s.repo.List(ctx, tenantID, limit, offset)
}

// Get returns one of the tenant's templates.
func (s *Service) Get(ctx context.Context, tenantID, templateID string) (domain.Template, error) {
	return s.repo.Get(ctx, tenantID, templateID)
}

// CreateInput is a new template.
type CreateInput struct {
	Name, Slug, Description string
	Category                domain.Category
	Topic                   string
	DefaultLocale           domain.Locale
}

// Create validates, stores and audits a template.
func (s *Service) Create(ctx context.Context, tenantID string, in CreateInput) (domain.Template, error) {
	now := s.now()
	t, err := domain.Template{ID: s.newID(), OrgID: tenantID, Name: in.Name, Slug: in.Slug, Description: in.Description,
		Category: in.Category, Topic: in.Topic, DefaultLocale: in.DefaultLocale, IsActive: true, CreatedAt: now, UpdatedAt: now}.Normalize()
	if err != nil {
		return domain.Template{}, err
	}
	err = s.repo.InTx(ctx, func(ctx context.Context) error {
		if err := s.repo.Create(ctx, t); err != nil {
			return err
		}
		return s.audit.Change(ctx, "template", t.ID, "template.created", nil, templateRecord(t), nil)
	})
	if err != nil {
		return domain.Template{}, err
	}
	return t, nil
}

// UpdateInput changes the fields that are set.
type UpdateInput struct {
	Name, Slug, Description *string
	Category                *domain.Category
	Topic                   *string
	DefaultLocale           *domain.Locale
	IsActive                *bool
}

// Update changes a template's metadata.
func (s *Service) Update(ctx context.Context, tenantID, templateID string, in UpdateInput) (domain.Template, error) {
	var out domain.Template
	err := s.repo.InTx(ctx, func(ctx context.Context) error {
		before, err := s.repo.GetForUpdate(ctx, tenantID, templateID)
		if err != nil {
			return err
		}
		next := before
		set(&next.Name, in.Name)
		set(&next.Slug, in.Slug)
		set(&next.Description, in.Description)
		set(&next.Category, in.Category)
		set(&next.Topic, in.Topic)
		set(&next.DefaultLocale, in.DefaultLocale)
		set(&next.IsActive, in.IsActive)
		if next, err = next.Normalize(); err != nil {
			return err
		}
		next.UpdatedAt = s.now()
		if err := s.repo.Update(ctx, next); err != nil {
			return err
		}
		out = next
		return s.audit.Change(ctx, "template", next.ID, "template.updated", templateRecord(before), templateRecord(next), nil)
	})
	return out, err
}

func set[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// Delete removes a template; its versions stop resolving.
func (s *Service) Delete(ctx context.Context, tenantID, templateID string) error {
	return s.repo.InTx(ctx, func(ctx context.Context) error {
		t, err := s.repo.GetForUpdate(ctx, tenantID, templateID)
		if err != nil {
			return err
		}
		if err := s.repo.Delete(ctx, tenantID, templateID, s.now()); err != nil {
			return err
		}
		return s.audit.Change(ctx, "template", t.ID, "template.deleted", templateRecord(t), nil, nil)
	})
}

// templateRecord is the audited form of a template.
func templateRecord(t domain.Template) map[string]any {
	return map[string]any{"name": t.Name, "slug": t.Slug, "category": t.Category, "description": t.Description,
		"topic": t.Topic, "default_locale": t.DefaultLocale, "is_active": t.IsActive}
}

// Topics is the static topic catalogue.
func (s *Service) Topics() []domain.Topic { return domain.Topics() }

// ── branding ──────────────────────────────────────────────────────────────

// Branding returns the organization's branding, or the defaults when none
// is saved.
func (s *Service) Branding(ctx context.Context, tenantID string) (domain.Branding, error) {
	b, ok, err := s.repo.Branding(ctx, tenantID)
	if err != nil {
		return domain.Branding{}, err
	}
	if !ok {
		return domain.DefaultBranding(tenantID), nil
	}
	return b, nil
}

// UpdateBranding validates, stores and audits the organization's branding.
func (s *Service) UpdateBranding(ctx context.Context, tenantID string, next domain.Branding, by string) (domain.Branding, error) {
	next.OrgID = tenantID
	next, err := next.Normalize()
	if err != nil {
		return domain.Branding{}, err
	}
	next.UpdatedAt = s.now()
	err = s.repo.InTx(ctx, func(ctx context.Context) error {
		before, err := s.Branding(ctx, tenantID)
		if err != nil {
			return err
		}
		if err := s.repo.SaveBranding(ctx, next, by); err != nil {
			return err
		}
		return s.audit.Change(ctx, "template_branding", tenantID, "template_branding.updated", brandingRecord(before), brandingRecord(next), nil)
	})
	if err != nil {
		return domain.Branding{}, err
	}
	return next, nil
}

func brandingRecord(b domain.Branding) map[string]any {
	return map[string]any{"company_name": b.CompanyName, "logo_url": b.LogoURL, "logo_alt": b.LogoAlt,
		"primary_color": b.PrimaryColor, "background_color": b.BackgroundColor, "content_background_color": b.ContentBackgroundColor,
		"text_color": b.TextColor, "link_color": b.LinkColor, "font_family": b.FontFamily,
		"company_address": b.CompanyAddress, "footer_text": b.FooterText}
}

// ── resolving for sends ───────────────────────────────────────────────────

// Ref names a template by exactly one of its ID, slug or topic.
type Ref struct {
	TemplateID, Slug, Topic string
}

// ResolvePublished finds what a send renders: the active published version
// for locale, else for the template's default_locale. A missing or inactive
// template, or no published version in either locale, is 404.
func (s *Service) ResolvePublished(ctx context.Context, tenantID string, ref Ref, locale string) (domain.Template, domain.Version, error) {
	t, err := s.resolve(ctx, tenantID, ref)
	if err != nil {
		return domain.Template{}, domain.Version{}, err
	}
	if !t.IsActive {
		return domain.Template{}, domain.Version{}, apperrors.NotFound("template not found")
	}
	if l, ok := domain.ParseLocale(locale); ok {
		v, err := s.repo.ActiveVersion(ctx, t.ID, l)
		if err == nil {
			return t, v, nil
		}
		if !apperrors.IsNotFound(err) {
			return domain.Template{}, domain.Version{}, err
		}
	}
	v, err := s.repo.ActiveVersion(ctx, t.ID, t.DefaultLocale)
	if apperrors.IsNotFound(err) {
		return domain.Template{}, domain.Version{}, apperrors.NotFound("the template has no published version in this locale")
	}
	if err != nil {
		return domain.Template{}, domain.Version{}, err
	}
	return t, v, nil
}

func (s *Service) resolve(ctx context.Context, tenantID string, ref Ref) (domain.Template, error) {
	ref.TemplateID, ref.Slug, ref.Topic = strings.TrimSpace(ref.TemplateID), strings.TrimSpace(ref.Slug), strings.TrimSpace(ref.Topic)
	n := 0
	for _, v := range []string{ref.TemplateID, ref.Slug, ref.Topic} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		return domain.Template{}, apperrors.Invalid("template", domain.CodeInvalid, "name a template by exactly one of its id, slug or topic")
	}
	var (
		t   domain.Template
		err error
	)
	switch {
	case ref.TemplateID != "":
		t, err = s.repo.Get(ctx, tenantID, ref.TemplateID)
	case ref.Slug != "":
		t, err = s.repo.GetBySlug(ctx, tenantID, ref.Slug)
	default:
		t, err = s.repo.GetByTopic(ctx, tenantID, ref.Topic)
	}
	if apperrors.IsNotFound(err) {
		return domain.Template{}, apperrors.NotFound("template not found")
	}
	return t, err
}

// Version returns one published version of the tenant's templates, by ID:
// the version a queued message was pinned to.
func (s *Service) Version(ctx context.Context, tenantID, versionID string) (domain.Version, error) {
	v, err := s.repo.VersionByID(ctx, tenantID, versionID)
	if apperrors.IsNotFound(err) {
		return domain.Version{}, apperrors.NotFound("template version not found")
	}
	return v, err
}
