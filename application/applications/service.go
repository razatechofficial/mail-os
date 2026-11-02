package applications

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/application"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// ErrNotFound is returned by Repository.ByClientID for a client that is no
// application.
var ErrNotFound = errors.New("application not found")

// ErrManagedByConfig refuses changing a system application in the console.
var ErrManagedByConfig = apperrors.Forbidden("this application is managed by the MailOS configuration; only its status can change")

// Service is the application registry use case.
type Service struct {
	repo    Repository
	domains Domains
	counter Counter
	tenants Tenants
	audit   Auditor
	cfg     Config
	now     func() time.Time
}

// NewService builds the service.
func NewService(repo Repository, domains Domains, counter Counter, tenants Tenants, audit Auditor, cfg Config) *Service {
	return &Service{repo: repo, domains: domains, counter: counter, tenants: tenants, audit: audit, cfg: cfg,
		now: func() time.Time { return time.Now().UTC() }}
}

// Input is what an administrator sets on an application. Status changes
// through Suspend and Activate.
type Input struct {
	Name             string
	Description      string
	Kind             domain.Kind
	ClientID         string
	Environment      domain.Environment
	Stream           domain.Stream
	MessageTypes     []string
	Senders          []string
	DefaultFromEmail string
	DefaultFromName  string
	DefaultReplyTo   string
	RatePerMinute    int
	DailyQuota       int
	BrowserTemplates []string
	UserRatePerHour  int
	AllowedOrigins   []string
}

func (in Input) apply(a *domain.Application) {
	a.Name, a.Description, a.Kind, a.ClientID = in.Name, in.Description, in.Kind, in.ClientID
	a.Environment, a.Stream = in.Environment, in.Stream
	a.MessageTypes, a.Senders = in.MessageTypes, in.Senders
	a.DefaultFromEmail, a.DefaultFromName, a.DefaultReplyTo = in.DefaultFromEmail, in.DefaultFromName, in.DefaultReplyTo
	a.RatePerMinute, a.DailyQuota = in.RatePerMinute, in.DailyQuota
	a.BrowserTemplates, a.UserRatePerHour, a.AllowedOrigins = in.BrowserTemplates, in.UserRatePerHour, in.AllowedOrigins
	if a.Environment == "" {
		a.Environment = domain.EnvSandbox
	}
	if a.Stream == "" {
		a.Stream = domain.StreamTransactional
	}
}

// record is what the audit trail keeps of an application.
type record struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	ClientID         string   `json:"client_id"`
	Status           string   `json:"status"`
	SuspendedReason  string   `json:"suspended_reason,omitempty"`
	Environment      string   `json:"environment"`
	Stream           string   `json:"stream"`
	MessageTypes     []string `json:"message_types"`
	Senders          []string `json:"senders"`
	DefaultFromEmail string   `json:"default_from_email"`
	DefaultReplyTo   string   `json:"default_reply_to"`
	RatePerMinute    int      `json:"rate_limit_per_minute"`
	DailyQuota       int      `json:"daily_quota"`
	BrowserTemplates []string `json:"browser_templates,omitempty"`
	UserRatePerHour  int      `json:"user_rate_limit_per_hour,omitempty"`
	AllowedOrigins   []string `json:"allowed_origins,omitempty"`
}

func recordOf(a domain.Application) record {
	return record{Name: a.Name, Kind: string(a.Kind), ClientID: a.ClientID, Status: string(a.Status),
		SuspendedReason: a.SuspendedReason, Environment: string(a.Environment), Stream: string(a.Stream),
		MessageTypes: a.MessageTypes, Senders: a.Senders, DefaultFromEmail: a.DefaultFromEmail, DefaultReplyTo: a.DefaultReplyTo,
		RatePerMinute: a.RatePerMinute, DailyQuota: a.DailyQuota, BrowserTemplates: a.BrowserTemplates,
		UserRatePerHour: a.UserRatePerHour, AllowedOrigins: a.AllowedOrigins}
}

// check validates a and its senders against the tenant's verified
// sending domains (SPF and DKIM found; DMARC published alongside).
func (s *Service) check(ctx context.Context, a domain.Application) error {
	a.Normalize()
	if err := a.Validate(s.cfg.AllowPlaintext); err != nil {
		return err
	}
	if slices.Contains(s.cfg.ReservedClients, a.ClientID) {
		return apperrors.Invalid("client_id", "reserved", "the MailOS console's client cannot be an application")
	}
	for _, sender := range a.Senders {
		ok, err := s.domains.VerifiedFrom(ctx, a.TenantID, "probe@"+domain.SenderDomain(sender))
		if err != nil {
			return err
		}
		if !ok {
			return apperrors.Invalid("senders", "unverified_domain",
				"sender "+sender+" is not on a verified sending domain; verify the domain (SPF, DKIM, DMARC) first")
		}
	}
	return nil
}

// Create registers an application, suspended-free and in the environment
// asked for (sandbox by default).
func (s *Service) Create(ctx context.Context, tenantID string, in Input, actor string) (domain.Application, error) {
	now := s.now()
	a := domain.Application{ID: id.New(), TenantID: tenantID, Status: domain.StatusActive, CreatedBy: actor, UpdatedBy: actor,
		CreatedAt: now, UpdatedAt: now}
	in.apply(&a)
	a.Normalize()
	if err := s.check(ctx, a); err != nil {
		return domain.Application{}, err
	}
	if err := s.repo.Create(ctx, a); err != nil {
		return domain.Application{}, err
	}
	if err := s.audit.Change(ctx, "application", a.ID, "application.created", nil, recordOf(a), nil); err != nil {
		return domain.Application{}, err
	}
	return a, nil
}

// Get returns one application.
func (s *Service) Get(ctx context.Context, tenantID, id string) (domain.Application, error) {
	return s.repo.Get(ctx, tenantID, id)
}

// List returns a page of the tenant's applications.
func (s *Service) List(ctx context.Context, f Filter) ([]domain.Application, int, error) {
	return s.repo.List(ctx, f)
}

// Update replaces what an administrator sets. A system application is
// refused: its configuration owns it.
func (s *Service) Update(ctx context.Context, tenantID, id string, in Input, actor string) (domain.Application, error) {
	a, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return domain.Application{}, err
	}
	if a.System {
		return domain.Application{}, ErrManagedByConfig
	}
	before := recordOf(a)
	in.apply(&a)
	a.Normalize()
	a.UpdatedBy, a.UpdatedAt = actor, s.now()
	if err := s.check(ctx, a); err != nil {
		return domain.Application{}, err
	}
	if err := s.repo.Update(ctx, a); err != nil {
		return domain.Application{}, err
	}
	if err := s.audit.Change(ctx, "application", a.ID, "application.updated", before, recordOf(a), nil); err != nil {
		return domain.Application{}, err
	}
	return a, nil
}

// Suspend stops every call of the application at once; Activate allows
// them again. Both work on a system application too (an emergency stop).
func (s *Service) Suspend(ctx context.Context, tenantID, id, reason, actor string) (domain.Application, error) {
	return s.setStatus(ctx, tenantID, id, domain.StatusSuspended, reason, actor)
}

// Activate lifts a suspension.
func (s *Service) Activate(ctx context.Context, tenantID, id, actor string) (domain.Application, error) {
	return s.setStatus(ctx, tenantID, id, domain.StatusActive, "", actor)
}

func (s *Service) setStatus(ctx context.Context, tenantID, id string, st domain.Status, reason, actor string) (domain.Application, error) {
	a, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return domain.Application{}, err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > domain.MaxSuspendReason {
		return domain.Application{}, apperrors.Invalid("reason", "too_long", "the reason must be at most 500 characters")
	}
	if a.Status == st && a.SuspendedReason == reason {
		return a, nil
	}
	before := recordOf(a)
	a.Status, a.SuspendedReason, a.UpdatedBy, a.UpdatedAt = st, reason, actor, s.now()
	if err := s.repo.Update(ctx, a); err != nil {
		return domain.Application{}, err
	}
	action := "application.suspended"
	if st == domain.StatusActive {
		action = "application.activated"
	}
	if err := s.audit.Change(ctx, "application", a.ID, action, before, recordOf(a), nil); err != nil {
		return domain.Application{}, err
	}
	return a, nil
}

// Delete removes an application. Its messages keep its id; its client is
// refused from then on. A system application cannot be deleted.
func (s *Service) Delete(ctx context.Context, tenantID, id, actor string) error {
	a, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if a.System {
		return ErrManagedByConfig
	}
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	return s.audit.Change(ctx, "application", id, "application.deleted", recordOf(a), nil, map[string]any{"by": actor})
}

// SystemSpec is a system application from configuration.
type SystemSpec struct {
	ClientID string
	TenantID string
	Name     string
	Topics   []string
}

// SeedSystem makes sure the configured system application exists with
// the configured topics. It is idempotent and safe on concurrent replicas;
// a status an administrator set is kept. It refuses a client that is
// already another tenant's or a non-system application, so configuration
// cannot take over an application.
func (s *Service) SeedSystem(ctx context.Context, spec SystemSpec) (domain.Application, error) {
	if err := s.tenants.Ensure(ctx, spec.TenantID); err != nil {
		return domain.Application{}, err
	}
	now := s.now()
	want := domain.Application{ID: id.New(), TenantID: spec.TenantID, Name: spec.Name, Kind: domain.KindServer,
		ClientID: spec.ClientID, Status: domain.StatusActive, Environment: domain.EnvLive, Stream: domain.StreamTransactional,
		MessageTypes: spec.Topics, System: true, CreatedBy: "system", UpdatedBy: "system", CreatedAt: now, UpdatedAt: now}
	want.Normalize()
	if err := want.Validate(s.cfg.AllowPlaintext); err != nil {
		return domain.Application{}, fmt.Errorf("system application %s: %w", spec.ClientID, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		got, err := s.repo.ByClientID(ctx, spec.ClientID)
		switch {
		case errors.Is(err, ErrNotFound):
			if err := s.repo.Create(ctx, want); err != nil {
				if apperrors.KindOf(err) == apperrors.KindConflict {
					continue // another replica created it first
				}
				return domain.Application{}, err
			}
			return want, s.audit.Change(ctx, "application", want.ID, "application.created", nil, recordOf(want),
				map[string]any{"system": true})
		case err != nil:
			return domain.Application{}, err
		}
		if !got.System || !strings.EqualFold(got.TenantID, spec.TenantID) {
			return domain.Application{}, fmt.Errorf("client %s is already application %s of tenant %s; it cannot be the system application",
				spec.ClientID, got.ID, got.TenantID)
		}
		if slices.Equal(got.MessageTypes, want.MessageTypes) && got.Name == want.Name {
			return got, nil
		}
		before := recordOf(got)
		got.MessageTypes, got.Name, got.UpdatedBy, got.UpdatedAt = want.MessageTypes, want.Name, "system", now
		if err := s.repo.Update(ctx, got); err != nil {
			return domain.Application{}, err
		}
		return got, s.audit.Change(ctx, "application", got.ID, "application.updated", before, recordOf(got), map[string]any{"system": true})
	}
	return domain.Application{}, fmt.Errorf("system application %s: concurrent creation did not settle", spec.ClientID)
}

// Usage is an application's sending over a period.
type Usage struct {
	ApplicationID  string         `json:"application_id"`
	Days           int            `json:"days"`
	QuotaUsedToday int64          `json:"quota_used_today"`
	DailyQuota     int            `json:"daily_quota"`
	RatePerMinute  int            `json:"rate_limit_per_minute"`
	Totals         map[string]int `json:"totals"`
	Daily          []UsageDay     `json:"daily"`
}

// UsageDay is one UTC day's messages by outcome.
type UsageDay struct {
	Day        string `json:"day"`
	Total      int    `json:"total"`
	Sent       int    `json:"sent"`
	Delivered  int    `json:"delivered"`
	Bounced    int    `json:"bounced"`
	Failed     int    `json:"failed"`
	Suppressed int    `json:"suppressed"`
	Captured   int    `json:"captured"`
}

// usageStatuses are the statuses Totals always lists.
var usageStatuses = []string{"queued", "scheduled", "sending", "sent", "delivered", "bounced", "failed", "cancelled", "suppressed", "captured"}

// Usage returns the application's messages per day and status over the
// last days (1 to 90), and today's quota use.
func (s *Service) Usage(ctx context.Context, tenantID, id string, days int) (Usage, error) {
	if days == 0 {
		days = 30
	}
	if days < 1 || days > 90 {
		return Usage{}, apperrors.Invalid("days", "out_of_range", "days must be between 1 and 90")
	}
	a, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return Usage{}, err
	}
	now := s.now()
	start := now.Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	counts, err := s.repo.MessageCounts(ctx, tenantID, id, start)
	if err != nil {
		return Usage{}, err
	}
	u := Usage{ApplicationID: a.ID, Days: days, DailyQuota: a.DailyQuota, RatePerMinute: a.RatePerMinute,
		Totals: map[string]int{}, Daily: make([]UsageDay, days)}
	for _, st := range usageStatuses {
		u.Totals[st] = 0
	}
	for i := range u.Daily {
		u.Daily[i].Day = start.AddDate(0, 0, i).Format(time.DateOnly)
	}
	for _, c := range counts {
		u.Totals[c.Status] += c.Count
		i := int(c.Day.UTC().Truncate(24*time.Hour).Sub(start) / (24 * time.Hour))
		if i < 0 || i >= days {
			continue
		}
		d := &u.Daily[i]
		d.Total += c.Count
		switch c.Status {
		case "sent":
			d.Sent += c.Count
		case "delivered":
			d.Delivered += c.Count
		case "bounced":
			d.Bounced += c.Count
		case "failed":
			d.Failed += c.Count
		case "suppressed":
			d.Suppressed += c.Count
		case "captured":
			d.Captured += c.Count
		}
	}
	if u.QuotaUsedToday, err = s.counter.Peek(ctx, quotaKey(a.ID, now)); err != nil {
		u.QuotaUsedToday = -1 // the counter is unavailable; the console shows it as unknown
	}
	return u, nil
}
