package smtp

import (
	"context"
	"sort"
	"sync"
	"time"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/application/smtpcred"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/smtpcredential"
	"github.com/razatechofficial/mail-os/domain/suppression"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// The in-memory ports of the real message and credential use cases.

type memMessages struct {
	mu   sync.Mutex
	msgs map[string]domainmsg.Message
}

func (r *memMessages) Create(_ context.Context, m domainmsg.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.msgs {
		if m.IdempotencyKey != "" && o.OrgID == m.OrgID && o.IdempotencyKey == m.IdempotencyKey {
			return appmsg.ErrDuplicateKey
		}
	}
	r.msgs[m.ID] = m
	return nil
}

func (r *memMessages) Get(_ context.Context, tenantID, id string) (domainmsg.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.msgs[id]
	if !ok || m.OrgID != tenantID {
		return domainmsg.Message{}, apperrors.NotFound("message not found")
	}
	return m, nil
}

func (r *memMessages) ByIdempotencyKey(_ context.Context, tenantID, key string) (*domainmsg.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.msgs {
		if m.OrgID == tenantID && m.IdempotencyKey == key {
			return &m, nil
		}
	}
	return nil, nil
}

func (r *memMessages) all() []domainmsg.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domainmsg.Message, 0, len(r.msgs))
	for _, m := range r.msgs {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ToEmail < out[j].ToEmail })
	return out
}

func (r *memMessages) List(context.Context, appmsg.Filter) ([]domainmsg.Message, int, error) {
	return nil, 0, nil
}

func (r *memMessages) Update(_ context.Context, m domainmsg.Message, expect domainmsg.Status) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.msgs[m.ID].Status != expect {
		return false, nil
	}
	r.msgs[m.ID] = m
	return true, nil
}

func (r *memMessages) DueScheduled(context.Context, time.Time, int) ([]domainmsg.Message, error) {
	return nil, nil
}
func (r *memMessages) Stale(context.Context, time.Time, time.Time, int) ([]domainmsg.Message, error) {
	return nil, nil
}
func (r *memMessages) PurgeTenants(context.Context) ([]string, error) { return nil, nil }
func (r *memMessages) PurgeCandidates(context.Context, string, time.Time, time.Time, int) ([]domainmsg.Message, error) {
	return nil, nil
}
func (r *memMessages) SavePurged(context.Context, domainmsg.Message) error            { return nil }
func (r *memMessages) PurgeRecords(context.Context, string, time.Time) (int64, error) { return 0, nil }

type nopQueue struct{}

func (nopQueue) EnqueueSend(context.Context, domainmsg.Message) error { return nil }

type noSuppressions struct{}

func (noSuppressions) Blocks(context.Context, string, string, string, domainmsg.Type) (*suppression.Suppression, error) {
	return nil, nil
}
func (noSuppressions) RecordBounce(context.Context, string, string, string) error { return nil }

type nopTenants struct{}

func (nopTenants) Ensure(context.Context, string) error { return nil }
func (nopTenants) Settings(context.Context, string) (domaintenant.Settings, error) {
	return domaintenant.Settings{}, nil
}

// sender records what would reach a provider.
type sender struct {
	mu  sync.Mutex
	out []domainmsg.Outgoing
}

func (s *sender) Send(_ context.Context, o domainmsg.Outgoing) (appmsg.SendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out = append(s.out, o)
	return appmsg.SendResult{ProviderID: "p1", ProviderMessageID: o.MessageID}, nil
}

func (s *sender) sent() []domainmsg.Outgoing {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domainmsg.Outgoing(nil), s.out...)
}

// auditLog records audit actions with their metadata.
type auditLog struct {
	mu      sync.Mutex
	entries []auditEntry
}

type auditEntry struct {
	action string
	meta   map[string]any
}

func (a *auditLog) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, auditEntry{action, meta})
	return nil
}

func (a *auditLog) Change(_ context.Context, _, _, action string, _, _ any, extra map[string]any) error {
	return a.Append(context.Background(), "", "", action, extra)
}

func (a *auditLog) find(action string) (auditEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.entries) - 1; i >= 0; i-- {
		if a.entries[i].action == action {
			return a.entries[i], true
		}
	}
	return auditEntry{}, false
}

type memCreds struct {
	mu    sync.Mutex
	creds map[string]smtpcredential.Credential
}

func (r *memCreds) Create(_ context.Context, c smtpcredential.Credential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.creds[c.ID] = c
	return nil
}

func (r *memCreds) Get(_ context.Context, tenantID, id string) (smtpcredential.Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.creds[id]
	if !ok || c.TenantID != tenantID {
		return c, apperrors.NotFound("smtp credential not found")
	}
	return c, nil
}

func (r *memCreds) ByUsername(_ context.Context, u string) (smtpcredential.Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.creds {
		if c.Username == u {
			return c, nil
		}
	}
	return smtpcredential.Credential{}, smtpcred.ErrNotFound
}

func (r *memCreds) List(_ context.Context, tenantID, appID string) ([]smtpcredential.Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []smtpcredential.Credential
	for _, c := range r.creds {
		if c.TenantID == tenantID && c.ApplicationID == appID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *memCreds) SetPassword(_ context.Context, c smtpcredential.Credential) error {
	return r.Create(context.Background(), c)
}

func (r *memCreds) Revoke(_ context.Context, _, id string, at time.Time, by string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.creds[id]
	c.RevokedAt, c.RevokedBy = &at, by
	r.creds[id] = c
	return nil
}

func (r *memCreds) Touch(context.Context, string, time.Time, string) error { return nil }
