package platform

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/provider"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type memRepo struct {
	tenants []TenantAggregate
	since   time.Time
	kinds   []string
}

func (m *memRepo) TenantAggregates(_ context.Context, after time.Time, afterID string, limit int, since time.Time) ([]TenantAggregate, error) {
	m.since = since
	var out []TenantAggregate
	for _, t := range m.tenants {
		if !after.IsZero() && (t.CreatedAt.Before(after) || (t.CreatedAt.Equal(after) && t.ID <= afterID)) {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, t)
	}
	return out, nil
}

func (m *memRepo) ProviderKindsInUse(context.Context) ([]string, error) { return m.kinds, nil }

func TestTenantsPages(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := &memRepo{}
	for i := range 5 {
		repo.tenants = append(repo.tenants, TenantAggregate{ID: fmt.Sprintf("t%d", i), CreatedAt: base.Add(time.Duration(i/2) * time.Hour)})
	}
	s := New(repo, false)
	now := time.Now()
	s.now = func() time.Time { return now }
	var seen []string
	cursor := ""
	for range 5 {
		items, next, err := s.Tenants(context.Background(), 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			seen = append(seen, it.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if strings.Join(seen, ",") != "t0,t1,t2,t3,t4" {
		t.Fatalf("pages: %v", seen)
	}
	if !repo.since.Equal(now.Add(-30 * 24 * time.Hour)) {
		t.Fatalf("messages counted since %s", repo.since)
	}
	if items, next, err := s.Tenants(context.Background(), 0, ""); err != nil || len(items) != 5 || next != "" {
		t.Fatalf("default page: %d %q %v", len(items), next, err)
	}
	for _, bad := range []struct {
		limit  int
		cursor string
	}{{-1, ""}, {201, ""}, {10, "!!"}, {10, "bm90LWEtY3Vyc29y"}} {
		if _, _, err := s.Tenants(context.Background(), bad.limit, bad.cursor); apperrors.KindOf(err) != apperrors.KindInvalidInput {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	empty := New(&memRepo{}, false)
	if items, _, err := empty.Tenants(context.Background(), 10, ""); err != nil || items == nil {
		t.Fatalf("empty list is null: %v", err)
	}
}

func TestConnectors(t *testing.T) {
	s := New(&memRepo{kinds: []string{"ses"}}, true)
	got, err := s.Connectors(context.Background())
	if err != nil || len(got) != len(provider.Kinds)+1 {
		t.Fatalf("%d %v", len(got), err)
	}
	byKind := map[string]Connector{}
	for _, c := range got {
		byKind[c.Kind] = c
	}
	if c := byKind["ses"]; !c.Configured || !c.TrackingOffSupported || c.PlatformRelay || c.Name == "" {
		t.Fatalf("ses: %+v", c)
	}
	if c := byKind["resend"]; c.Configured || c.TrackingOffSupported {
		t.Fatalf("resend: %+v", c)
	}
	if c := byKind[RelayKind]; !c.PlatformRelay || !c.Configured {
		t.Fatalf("relay: %+v", c)
	}
}

// The platform templates are the IAM topics with their defaults; a
// tenant's own topic is not one.
func TestTemplates(t *testing.T) {
	s := New(&memRepo{}, false)
	list := s.Templates()
	if len(list) == 0 {
		t.Fatal("no platform templates")
	}
	for _, it := range list {
		if !strings.HasPrefix(it.Topic, "iam.") || it.Name == "" || len(it.Variables) == 0 {
			t.Fatalf("%+v", it)
		}
	}
	got, err := s.Template(domaintemplate.TopicPasswordReset)
	if err != nil || !got.AuthClass || got.Subject == "" || !strings.Contains(got.HTML, "{{reset_link}}") || !strings.Contains(got.Text, "{{reset_link}}") {
		t.Fatalf("password reset: %+v %v", got.TemplateSummary, err)
	}
	for _, topic := range []string{domaintemplate.TopicCampaign, "iam.unknown", ""} {
		if _, err := s.Template(topic); !apperrors.IsNotFound(err) {
			t.Errorf("%q: %v", topic, err)
		}
	}
}
