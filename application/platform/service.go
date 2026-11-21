// Package platform is the platform API's read side (ADR 0001 §3.1,
// contract C6): tenants as aggregates only, the connector catalogue, and
// the platform templates (the IAM topics with their platform defaults).
// Nothing here reads a message's subject, recipient or body, or a
// connector's credential: the platform plane sees counts, never content.
package platform

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/provider"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/internal/provision"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// TenantAggregate is one tenant as the platform sees it: counts only.
type TenantAggregate struct {
	ID           string    `json:"id"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	Applications int64     `json:"applications"`
	Domains      int64     `json:"domains"`
	Messages30d  int64     `json:"messages_30d"`
}

// Repository reads the aggregates (infrastructure/persistence/postgres).
type Repository interface {
	// TenantAggregates lists tenants ordered by (created_at, id) after the
	// given position, counting messages created since since.
	TenantAggregates(ctx context.Context, afterCreated time.Time, afterID string, limit int, since time.Time) ([]TenantAggregate, error)
	// ProviderKindsInUse are the kinds at least one tenant has an active
	// provider of.
	ProviderKindsInUse(ctx context.Context) ([]string, error)
}

// Service serves the platform API's reads.
type Service struct {
	repo            Repository
	relayConfigured bool
	now             func() time.Time
}

// New builds the service; relayConfigured is whether the platform relay
// (SMTP_*) is set up.
func New(repo Repository, relayConfigured bool) *Service {
	return &Service{repo: repo, relayConfigured: relayConfigured, now: time.Now}
}

// Page sizes of the tenants list.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var errCursor = apperrors.Invalid("cursor", "invalid", "the cursor is not one this list returned")

func encodeCursor(t TenantAggregate) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(t.CreatedAt.UnixNano(), 10) + "|" + t.ID))
}

func decodeCursor(s string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", errCursor
	}
	ns, id, ok := strings.Cut(string(raw), "|")
	n, err := strconv.ParseInt(ns, 10, 64)
	if !ok || err != nil || id == "" || len(id) > 64 {
		return time.Time{}, "", errCursor
	}
	return time.Unix(0, n).UTC(), id, nil
}

// Tenants lists tenants with their counts, limit at a time (1 to 200,
// default 50); next is "" on the last page.
func (s *Service) Tenants(ctx context.Context, limit int, cursor string) (items []TenantAggregate, next string, err error) {
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return nil, "", apperrors.Invalid("limit", "out_of_range", "limit must be between 1 and 200")
	}
	var after time.Time
	var afterID string
	if cursor != "" {
		if after, afterID, err = decodeCursor(cursor); err != nil {
			return nil, "", err
		}
	}
	items, err = s.repo.TenantAggregates(ctx, after, afterID, limit+1, s.now().Add(-30*24*time.Hour))
	if err != nil {
		return nil, "", err
	}
	if len(items) > limit {
		items = items[:limit]
		next = encodeCursor(items[limit-1])
	}
	if items == nil {
		items = []TenantAggregate{}
	}
	return items, next, nil
}

// Connector is one entry of the connector catalogue: a provider kind
// tenants may configure, or the platform relay. Never a credential.
type Connector struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	// TrackingOffSupported: the kind can send with click and open tracking
	// off, so it may carry authentication mail.
	TrackingOffSupported bool `json:"tracking_off_supported"`
	PlatformRelay        bool `json:"platform_relay"`
	// Configured: the relay is set up; a kind has an active provider in at
	// least one tenant.
	Configured bool `json:"configured"`
}

// RelayKind is the platform relay's entry in the catalogue.
const RelayKind = "platform_relay"

// Connectors is the catalogue: every provider kind MailOS supports, then
// the platform relay.
func (s *Service) Connectors(ctx context.Context) ([]Connector, error) {
	inUse, err := s.repo.ProviderKindsInUse(ctx)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, k := range inUse {
		used[k] = true
	}
	out := make([]Connector, 0, len(provider.Kinds)+1)
	for _, k := range provider.Kinds {
		name := string(k)
		if sc, ok := provider.SchemaOf(k); ok {
			name = sc.Label
		}
		out = append(out, Connector{Kind: string(k), Name: name, TrackingOffSupported: mailer.TracksOff(k), Configured: used[string(k)]})
	}
	// The relay is SMTP: it never rewrites links or adds pixels.
	out = append(out, Connector{Kind: RelayKind, Name: "Platform relay", TrackingOffSupported: true, PlatformRelay: true, Configured: s.relayConfigured})
	return out, nil
}

// Variable is a template variable's name and kind.
type Variable struct {
	Name string              `json:"name"`
	Kind domaintemplate.Kind `json:"kind"`
}

// TemplateSummary is a platform topic in the templates list.
type TemplateSummary struct {
	Topic     string     `json:"topic"`
	Name      string     `json:"name"`
	AuthClass bool       `json:"auth_class"`
	Variables []Variable `json:"variables"`
}

// Template is a platform topic with its platform default.
type Template struct {
	TemplateSummary
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text"`
}

func summary(t domaintemplate.Topic) TemplateSummary {
	vars := make([]Variable, 0, len(t.Variables))
	for _, v := range t.Variables {
		vars = append(vars, Variable{Name: v.Key, Kind: v.Kind})
	}
	return TemplateSummary{Topic: t.Key, Name: t.Name, AuthClass: t.AuthClass, Variables: vars}
}

// Templates lists the platform topics (the IAM's), in catalogue order.
func (s *Service) Templates() []TemplateSummary {
	var out []TemplateSummary
	for _, t := range domaintemplate.Topics() {
		if t.Source == domaintemplate.SourceIAM {
			out = append(out, summary(t))
		}
	}
	return out
}

// ErrNoTemplate is a topic that is not a platform topic.
var ErrNoTemplate = apperrors.NotFound("no platform template for this topic")

// Template returns a platform topic's default: never a tenant's override.
func (s *Service) Template(topic string) (Template, error) {
	t, ok := domaintemplate.TopicByKey(topic)
	if !ok || t.Source != domaintemplate.SourceIAM {
		return Template{}, ErrNoTemplate
	}
	d := provision.DefaultFor(t)
	return Template{TemplateSummary: summary(t), Subject: d.Subject, HTML: d.HTML, Text: d.Text}, nil
}
