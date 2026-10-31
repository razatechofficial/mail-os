// Package templatetest has in-memory fakes of the template use case's
// ports for unit and handler tests: a repository with the same scoping and
// revision rules as Postgres, tenant settings, an audit log, a test sender
// and a sending-domain check.
package templatetest

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	app "github.com/razatechofficial/mail-os/application/template"
	domain "github.com/razatechofficial/mail-os/domain/template"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type draftKey struct {
	template string
	locale   domain.Locale
}

// Repository is an in-memory app.Repository. InTx does not roll back.
type Repository struct {
	mu        sync.Mutex
	templates map[string]domain.Template
	deleted   map[string]bool
	drafts    map[draftKey]domain.Draft
	versions  []domain.Version
	branding  map[string]domain.Branding
}

var _ app.Repository = (*Repository)(nil)

// NewRepository returns an empty repository.
func NewRepository() *Repository {
	return &Repository{templates: map[string]domain.Template{}, deleted: map[string]bool{},
		drafts: map[draftKey]domain.Draft{}, branding: map[string]domain.Branding{}}
}

// InTx runs fn.
func (r *Repository) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func notFound() error { return apperrors.NotFound("template not found") }

// List returns the tenant's live templates by name.
func (r *Repository) List(_ context.Context, tenantID string, limit, offset int) ([]domain.Template, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Template
	for id, t := range r.templates {
		if t.OrgID == tenantID && !r.deleted[id] {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	total := len(out)
	if offset > len(out) {
		offset = len(out)
	}
	out = out[offset:]
	if limit > 0 && limit < len(out) {
		out = out[:limit]
	}
	return out, total, nil
}

func (r *Repository) find(tenantID string, match func(domain.Template) bool) (domain.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.templates {
		if t.OrgID == tenantID && !r.deleted[id] && match(t) {
			return t, nil
		}
	}
	return domain.Template{}, notFound()
}

// Get finds a live template of the tenant.
func (r *Repository) Get(_ context.Context, tenantID, templateID string) (domain.Template, error) {
	return r.find(tenantID, func(t domain.Template) bool { return t.ID == templateID })
}

// GetForUpdate is Get.
func (r *Repository) GetForUpdate(ctx context.Context, tenantID, templateID string) (domain.Template, error) {
	return r.Get(ctx, tenantID, templateID)
}

// GetBySlug finds by slug.
func (r *Repository) GetBySlug(_ context.Context, tenantID, slug string) (domain.Template, error) {
	return r.find(tenantID, func(t domain.Template) bool { return t.Slug == slug })
}

// GetByTopic finds by topic.
func (r *Repository) GetByTopic(_ context.Context, tenantID, topic string) (domain.Template, error) {
	return r.find(tenantID, func(t domain.Template) bool { return topic != "" && t.Topic == topic })
}

func (r *Repository) unique(t domain.Template) error {
	for id, o := range r.templates {
		if id == t.ID || r.deleted[id] || o.OrgID != t.OrgID {
			continue
		}
		if o.Slug == t.Slug {
			return app.ErrSlugTaken
		}
		if t.Topic != "" && o.Topic == t.Topic {
			return app.ErrTopicTaken
		}
	}
	return nil
}

// Create stores a template.
func (r *Repository) Create(_ context.Context, t domain.Template) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.unique(t); err != nil {
		return err
	}
	r.templates[t.ID] = t
	return nil
}

// Update replaces a template.
func (r *Repository) Update(_ context.Context, t domain.Template) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.templates[t.ID]; !ok || r.deleted[t.ID] {
		return notFound()
	}
	if err := r.unique(t); err != nil {
		return err
	}
	r.templates[t.ID] = t
	return nil
}

// Delete marks a template deleted.
func (r *Repository) Delete(_ context.Context, tenantID, templateID string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.templates[templateID]
	if !ok || t.OrgID != tenantID || r.deleted[templateID] {
		return notFound()
	}
	r.deleted[templateID] = true
	return nil
}

// Draft returns a saved draft.
func (r *Repository) Draft(_ context.Context, templateID string, locale domain.Locale) (domain.Draft, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.drafts[draftKey{templateID, locale}]
	return cloneDraft(d), ok, nil
}

// SaveDraft stores d when the stored revision is prev.
func (r *Repository) SaveDraft(_ context.Context, d domain.Draft, prev int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := draftKey{d.TemplateID, d.Locale}
	if r.drafts[k].Revision != prev {
		return apperrors.Conflict("the draft was saved by someone else; reload it")
	}
	r.drafts[k] = cloneDraft(d)
	return nil
}

func cloneDraft(d domain.Draft) domain.Draft {
	d.Design = slices.Clone(d.Design)
	d.Variables = slices.Clone(d.Variables)
	return d
}

func cloneVersion(v domain.Version) domain.Version {
	v.Design = slices.Clone(v.Design)
	v.Variables = slices.Clone(v.Variables)
	return v
}

// Versions lists newest first.
func (r *Repository) Versions(_ context.Context, templateID string, locale domain.Locale) ([]domain.Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Version
	for _, v := range r.versions {
		if v.TemplateID == templateID && (locale == "" || v.Locale == locale) {
			out = append(out, cloneVersion(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number > out[j].Number })
	return out, nil
}

func (r *Repository) version(match func(domain.Version) bool) (domain.Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.versions {
		if match(v) {
			return cloneVersion(v), nil
		}
	}
	return domain.Version{}, apperrors.ErrNotFound
}

// ActiveVersion returns the locale's active version.
func (r *Repository) ActiveVersion(_ context.Context, templateID string, locale domain.Locale) (domain.Version, error) {
	return r.version(func(v domain.Version) bool { return v.TemplateID == templateID && v.Locale == locale && v.IsActive })
}

// VersionByNumber finds a version.
func (r *Repository) VersionByNumber(_ context.Context, templateID string, number int) (domain.Version, error) {
	return r.version(func(v domain.Version) bool { return v.TemplateID == templateID && v.Number == number })
}

// VersionByID finds a version of one of the tenant's live templates.
func (r *Repository) VersionByID(_ context.Context, tenantID, versionID string) (domain.Version, error) {
	r.mu.Lock()
	owner := map[string]bool{}
	for id, t := range r.templates {
		owner[id] = t.OrgID == tenantID && !r.deleted[id]
	}
	r.mu.Unlock()
	return r.version(func(v domain.Version) bool { return v.ID == versionID && owner[v.TemplateID] })
}

// MaxVersionNumber is the highest number, 0 for none.
func (r *Repository) MaxVersionNumber(_ context.Context, templateID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.versions {
		if v.TemplateID == templateID && v.Number > n {
			n = v.Number
		}
	}
	return n, nil
}

// InsertVersion stores v as its locale's active version.
func (r *Repository) InsertVersion(_ context.Context, v domain.Version) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.versions {
		if r.versions[i].TemplateID == v.TemplateID && r.versions[i].Locale == v.Locale {
			r.versions[i].IsActive = false
		}
	}
	r.versions = append(r.versions, cloneVersion(v))
	return nil
}

// Branding returns saved branding.
func (r *Repository) Branding(_ context.Context, tenantID string) (domain.Branding, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.branding[tenantID]
	return b, ok, nil
}

// SaveBranding stores branding.
func (r *Repository) SaveBranding(_ context.Context, b domain.Branding, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.branding[b.OrgID] = b
	return nil
}

// Settings are fixed tenant settings.
type Settings struct{ FourEyes bool }

// Settings returns the settings.
func (s *Settings) Settings(_ context.Context, tenantID string) (domaintenant.Settings, error) {
	return domaintenant.Settings{TenantID: tenantID, FourEyesPublish: s.FourEyes}, nil
}

// Audit records actions.
type Audit struct {
	mu      sync.Mutex
	Actions []string
	Meta    []map[string]any
}

// Append records an action.
func (a *Audit) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Actions = append(a.Actions, action)
	a.Meta = append(a.Meta, meta)
	return nil
}

// Change records a change.
func (a *Audit) Change(_ context.Context, _, _, action string, before, after any, _ map[string]any) error {
	return a.Append(context.Background(), "", "", action, map[string]any{"before": before, "after": after})
}

// Last returns the last action and its metadata.
func (a *Audit) Last() (string, map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.Actions) == 0 {
		return "", nil
	}
	return a.Actions[len(a.Actions)-1], a.Meta[len(a.Meta)-1]
}

// Sender records test messages.
type Sender struct {
	mu   sync.Mutex
	Sent []app.TestMessage
}

// SendTest records m.
func (s *Sender) SendTest(_ context.Context, m app.TestMessage) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Sent = append(s.Sent, m)
	return "msg-test-1", "queued", nil
}

// Domains verifies the listed domains.
type Domains struct{ Verified []string }

// VerifiedFrom reports whether the address's domain is listed.
func (d Domains) VerifiedFrom(_ context.Context, _, fromEmail string) (bool, error) {
	_, host, ok := strings.Cut(fromEmail, "@")
	return ok && slices.Contains(d.Verified, strings.ToLower(host)), nil
}
