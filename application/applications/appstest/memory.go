// Package appstest is an in-memory application registry for the tests of
// the slices that authorise callers through it (inbound events, messages,
// the HTTP and gRPC transports). It runs the real applications.Service.
package appstest

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/mail-os/application/applications"
	domain "github.com/razatechofficial/mail-os/domain/application"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// Repo is an in-memory applications.Repository.
type Repo struct {
	mu   sync.Mutex
	apps map[string]domain.Application
}

var _ applications.Repository = (*Repo)(nil)

// NewRepo holds apps.
func NewRepo(apps ...domain.Application) *Repo {
	r := &Repo{apps: map[string]domain.Application{}}
	for _, a := range apps {
		r.apps[a.ID] = a
	}
	return r
}

// Create implements applications.Repository.
func (r *Repo) Create(_ context.Context, a domain.Application) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.apps {
		if o.ClientID == a.ClientID {
			return apperrors.Conflict("that IAM client is already a MailOS application")
		}
	}
	r.apps[a.ID] = a
	return nil
}

// Update implements applications.Repository.
func (r *Repo) Update(_ context.Context, a domain.Application) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apps[a.ID] = a
	return nil
}

// Delete implements applications.Repository.
func (r *Repo) Delete(_ context.Context, _, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.apps, id)
	return nil
}

// Get implements applications.Repository.
func (r *Repo) Get(_ context.Context, tenantID, id string) (domain.Application, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.apps[id]
	if !ok || !strings.EqualFold(a.TenantID, tenantID) {
		return domain.Application{}, apperrors.NotFound("application not found")
	}
	return a, nil
}

// ByClientID implements applications.Repository.
func (r *Repo) ByClientID(_ context.Context, clientID string) (domain.Application, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.apps {
		if a.ClientID == clientID {
			return a, nil
		}
	}
	return domain.Application{}, applications.ErrNotFound
}

// List implements applications.Repository.
func (r *Repo) List(_ context.Context, f applications.Filter) ([]domain.Application, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []domain.Application{}
	for _, a := range r.apps {
		if a.TenantID == f.TenantID {
			out = append(out, a)
		}
	}
	return out, len(out), nil
}

// MessageCounts implements applications.Repository (no messages).
func (r *Repo) MessageCounts(context.Context, string, string, time.Time) ([]applications.StatusCount, error) {
	return nil, nil
}

// AllVerified treats every sender as on a verified domain.
type AllVerified struct{}

// VerifiedFrom implements applications.Domains.
func (AllVerified) VerifiedFrom(context.Context, string, string) (bool, error) { return true, nil }

// Counter is an in-memory applications.Counter.
type Counter struct {
	mu sync.Mutex
	n  map[string]int64
}

// Take implements applications.Counter.
func (c *Counter) Take(_ context.Context, key string, n, limit int64, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int64{}
	}
	if n > 0 && c.n[key]+n > limit {
		return false, nil
	}
	c.n[key] += n
	return true, nil
}

// Peek implements applications.Counter.
func (c *Counter) Peek(_ context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[key], nil
}

type nopTenants struct{}

func (nopTenants) Ensure(context.Context, string) error { return nil }

type nopAudit struct{}

func (nopAudit) Append(context.Context, string, string, string, map[string]any) error { return nil }
func (nopAudit) Change(context.Context, string, string, string, any, any, map[string]any) error {
	return nil
}

// New returns the real registry over apps, with every sender verified,
// in-memory counters and no audit trail.
func New(apps ...domain.Application) *applications.Service {
	return applications.NewService(NewRepo(apps...), AllVerified{}, &Counter{}, nopTenants{}, nopAudit{}, applications.Config{AllowPlaintext: true})
}

// Server is an active, live, unlimited server application of tenant for
// clientID, allowed to send types.
func Server(clientID, tenant string, types ...string) domain.Application {
	now := time.Now().UTC()
	return domain.Application{ID: id.New(), TenantID: strings.ToLower(tenant), Name: clientID, Kind: domain.KindServer,
		ClientID: clientID, Status: domain.StatusActive, Environment: domain.EnvLive, Stream: domain.StreamTransactional,
		MessageTypes: types, System: true, CreatedAt: now, UpdatedAt: now}
}
