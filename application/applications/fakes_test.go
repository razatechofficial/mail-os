package applications

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	domain "github.com/razatechofficial/mail-os/domain/application"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type memRepo struct {
	mu     sync.Mutex
	apps   map[string]domain.Application
	counts []StatusCount
}

func newMemRepo() *memRepo { return &memRepo{apps: map[string]domain.Application{}} }

func (r *memRepo) Create(_ context.Context, a domain.Application) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.apps {
		if o.ClientID == a.ClientID {
			return apperrors.Conflict("client_id is already an application")
		}
		if o.TenantID == a.TenantID && strings.EqualFold(o.Name, a.Name) {
			return apperrors.Conflict("name taken")
		}
	}
	r.apps[a.ID] = a
	return nil
}

func (r *memRepo) Update(_ context.Context, a domain.Application) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apps[a.ID] = a
	return nil
}

func (r *memRepo) Delete(_ context.Context, tenantID, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.apps, id)
	return nil
}

func (r *memRepo) Get(_ context.Context, tenantID, id string) (domain.Application, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.apps[id]
	if !ok || a.TenantID != tenantID {
		return domain.Application{}, apperrors.NotFound("application not found")
	}
	return a, nil
}

func (r *memRepo) ByClientID(_ context.Context, clientID string) (domain.Application, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.apps {
		if a.ClientID == clientID {
			return a, nil
		}
	}
	return domain.Application{}, ErrNotFound
}

func (r *memRepo) List(_ context.Context, f Filter) ([]domain.Application, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domain.Application
	for _, a := range r.apps {
		if a.TenantID == f.TenantID {
			out = append(out, a)
		}
	}
	return out, len(out), nil
}

func (r *memRepo) MessageCounts(context.Context, string, string, time.Time) ([]StatusCount, error) {
	return r.counts, nil
}

type fakeDomains struct{ verified []string }

func (d fakeDomains) VerifiedFrom(_ context.Context, _ string, from string) (bool, error) {
	dom := from[strings.LastIndexByte(from, '@')+1:]
	for _, v := range d.verified {
		if dom == v || strings.HasSuffix(dom, "."+v) {
			return true, nil
		}
	}
	return false, nil
}

type memCounter struct {
	mu   sync.Mutex
	n    map[string]int64
	fail bool
}

func newCounter() *memCounter { return &memCounter{n: map[string]int64{}} }

func (c *memCounter) Take(_ context.Context, key string, n, limit int64, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return false, errors.New("redis down")
	}
	if c.n[key]+n > limit {
		return false, nil
	}
	c.n[key] += n
	return true, nil
}

func (c *memCounter) Peek(_ context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[key], nil
}

type nopTenants struct{ ensured []string }

func (t *nopTenants) Ensure(_ context.Context, id string) error {
	t.ensured = append(t.ensured, id)
	return nil
}

type auditEntry struct {
	Action string
	Meta   map[string]any
}

type memAudit struct {
	mu      sync.Mutex
	entries []auditEntry
}

func (a *memAudit) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, auditEntry{Action: action, Meta: meta})
	return nil
}

func (a *memAudit) Change(_ context.Context, _, _, action string, _, _ any, extra map[string]any) error {
	return a.Append(context.Background(), "", "", action, extra)
}

func (a *memAudit) last() auditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) == 0 {
		return auditEntry{}
	}
	return a.entries[len(a.entries)-1]
}
