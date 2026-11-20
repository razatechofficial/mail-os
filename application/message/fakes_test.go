package message

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
	"github.com/razatechofficial/mail-os/domain/suppression"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type memRepo struct {
	mu   sync.Mutex
	msgs map[string]domainmsg.Message
	// records are each tenant's inbound receipts and finished webhook
	// deliveries; recordsBefore the cut-off PurgeRecords was given.
	records       map[string]int64
	recordsBefore map[string]time.Time
}

func newMemRepo() *memRepo { return &memRepo{msgs: map[string]domainmsg.Message{}} }

func (r *memRepo) Create(_ context.Context, m domainmsg.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.msgs {
		if m.IdempotencyKey != "" && o.OrgID == m.OrgID && o.IdempotencyKey == m.IdempotencyKey {
			return ErrDuplicateKey
		}
	}
	r.msgs[m.ID] = m
	return nil
}

func (r *memRepo) Get(_ context.Context, tenantID, id string) (domainmsg.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.msgs[id]
	if !ok || m.OrgID != tenantID {
		return domainmsg.Message{}, apperrors.NotFound("message not found")
	}
	return m, nil
}

func (r *memRepo) ByIdempotencyKey(_ context.Context, tenantID, key string) (*domainmsg.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.msgs {
		if m.OrgID == tenantID && m.IdempotencyKey == key {
			return &m, nil
		}
	}
	return nil, nil
}

func (r *memRepo) List(_ context.Context, f Filter) ([]domainmsg.Message, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domainmsg.Message
	for _, m := range r.msgs {
		if m.OrgID == f.TenantID && (f.Status == "" || string(m.Status) == f.Status) {
			out = append(out, m)
		}
	}
	return out, len(out), nil
}

func (r *memRepo) Update(_ context.Context, m domainmsg.Message, expect domainmsg.Status) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.msgs[m.ID].Status != expect {
		return false, nil
	}
	r.msgs[m.ID] = m
	return true, nil
}

func (r *memRepo) filter(keep func(domainmsg.Message) bool) []domainmsg.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []domainmsg.Message
	for _, m := range r.msgs {
		if keep(m) {
			out = append(out, m)
		}
	}
	return out
}

func (r *memRepo) DueScheduled(_ context.Context, now time.Time, _ int) ([]domainmsg.Message, error) {
	return r.filter(func(m domainmsg.Message) bool {
		return m.Status == domainmsg.StatusScheduled && !m.ScheduledAt.After(now)
	}), nil
}

func (r *memRepo) Stale(_ context.Context, q, s time.Time, _ int) ([]domainmsg.Message, error) {
	return r.filter(func(m domainmsg.Message) bool {
		return m.Status == domainmsg.StatusQueued && m.UpdatedAt.Before(q) || m.Status == domainmsg.StatusSending && m.UpdatedAt.Before(s)
	}), nil
}

func (r *memRepo) PurgeTenants(context.Context) ([]string, error) {
	var out []string
	for _, m := range r.filter(func(m domainmsg.Message) bool { return m.BodyPurgedAt == nil }) {
		if !slices.Contains(out, m.OrgID) {
			out = append(out, m.OrgID)
		}
	}
	for t := range r.records {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (r *memRepo) PurgeCandidates(_ context.Context, t string, before, stuck time.Time, _ int) ([]domainmsg.Message, error) {
	return r.filter(func(m domainmsg.Message) bool {
		return m.OrgID == t && m.BodyPurgedAt == nil &&
			(m.Status.Final() && m.CreatedAt.Before(before) || !m.Status.Final() && m.CreatedAt.Before(stuck))
	}), nil
}

func (r *memRepo) PurgeRecords(_ context.Context, t string, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recordsBefore == nil {
		r.recordsBefore = map[string]time.Time{}
	}
	r.recordsBefore[t] = before
	return r.records[t], nil
}

func (r *memRepo) SavePurged(_ context.Context, m domainmsg.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs[m.ID] = m
	return nil
}

type memQueue struct {
	mu  sync.Mutex
	ids []string
	err error
}

func (q *memQueue) EnqueueSend(_ context.Context, m domainmsg.Message) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.ids = append(q.ids, m.ID)
	return nil
}

type memSuppressions struct {
	list    map[string]suppression.Type
	bounced []string
}

func (s *memSuppressions) Blocks(_ context.Context, _, appID, email string, mt domainmsg.Type) (*suppression.Suppression, error) {
	t, ok := s.list[strings.ToLower(email)]
	if !ok && appID != "" {
		t, ok = s.list[appID+"/"+strings.ToLower(email)]
	}
	if !ok || !t.Blocks(mt) {
		return nil, nil
	}
	return &suppression.Suppression{Email: email, Type: t}, nil
}

func (s *memSuppressions) RecordBounce(_ context.Context, _, email, _ string) error {
	s.bounced = append(s.bounced, email)
	return nil
}

type memTenants struct{ days *int }

func (memTenants) Ensure(context.Context, string) error { return nil }
func (t memTenants) Settings(_ context.Context, id string) (domaintenant.Settings, error) {
	return domaintenant.Settings{TenantID: id, MessageRetentionDays: t.days}, nil
}

type memTemplates struct {
	tpl domaintemplate.Template
	ver domaintemplate.Version
}

func (t memTemplates) ResolvePublished(_ context.Context, _ string, ref apptemplate.Ref, _ string) (domaintemplate.Template, domaintemplate.Version, error) {
	// The real resolver takes exactly one of id, slug or topic.
	n := 0
	for _, v := range []string{ref.TemplateID, ref.Slug, ref.Topic} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		return domaintemplate.Template{}, domaintemplate.Version{}, apperrors.Invalid("template", "invalid", "name a template by exactly one of its id, slug or topic")
	}
	if ref.Slug != "" && ref.Slug != t.tpl.Slug {
		return domaintemplate.Template{}, domaintemplate.Version{}, apperrors.NotFound("template not found")
	}
	return t.tpl, t.ver, nil
}

func (t memTemplates) Version(_ context.Context, _, id string) (domaintemplate.Version, error) {
	if id != t.ver.ID {
		return domaintemplate.Version{}, apperrors.NotFound("version not found")
	}
	return t.ver, nil
}

func (memTemplates) Branding(context.Context, string) (domaintemplate.Branding, error) {
	return domaintemplate.Branding{CompanyName: "Bank of Tests"}, nil
}

// fakeRender replaces {{key}} with data values, as render.Render does.
func fakeRender(c Content, data map[string]any) (Content, error) {
	value := func(k string) string {
		if v, ok := domaintemplate.Lookup(data, k); ok {
			return fmt.Sprint(v)
		}
		return ""
	}
	r := func(s string) string { return domaintemplate.ReplacePlaceholders(s, value) }
	return Content{Subject: r(c.Subject), HTML: r(c.HTML), Text: r(c.Text)}, nil
}

type memSender struct {
	mu   sync.Mutex
	errs []error
	sent []domainmsg.Outgoing
}

func (s *memSender) Send(_ context.Context, out domainmsg.Outgoing) (SendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) > 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		if err != nil {
			return SendResult{}, err
		}
	}
	s.sent = append(s.sent, out)
	return SendResult{ProviderID: "p1", ProviderMessageID: "pm-" + out.MessageID}, nil
}

type memSigner struct {
	key *sendingdomain.SigningKey
	err error
}

func (s memSigner) SigningKey(context.Context, string, string) (*sendingdomain.SigningKey, error) {
	return s.key, s.err
}

type memNotifier struct {
	events []string
	apps   []string
	data   []map[string]any
}

func (n *memNotifier) Notify(_ context.Context, _, appID, event, _ string, data map[string]any) error {
	n.events = append(n.events, event)
	n.data = append(n.data, data)
	n.apps = append(n.apps, appID)
	return nil
}

type memStats struct{ counts map[string]int }

func (s *memStats) Count(_ context.Context, _, c string, _ time.Time) error {
	s.counts[c]++
	return nil
}

type memAudit struct {
	mu      sync.Mutex
	actions []string
	meta    []map[string]any
}

func (a *memAudit) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, action)
	a.meta = append(a.meta, meta)
	return nil
}

func (a *memAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Contains(a.actions, action)
}

var errDown = errors.New("down")

// memSecrets is the sealed secret store in memory.
type memSecrets struct {
	mu   sync.Mutex
	rows map[string]memSecret
	// putErr fails the next Put.
	putErr error
}

type memSecret struct {
	sealed, tenant string
	expires        time.Time
}

func newMemSecrets() *memSecrets { return &memSecrets{rows: map[string]memSecret{}} }

func (s *memSecrets) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

func (s *memSecrets) Put(_ context.Context, tenantID, messageID, sealed string, _, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	s.rows[messageID] = memSecret{sealed: sealed, tenant: tenantID, expires: expiresAt}
	return nil
}

func (s *memSecrets) Get(_ context.Context, tenantID, messageID string, now time.Time) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[messageID]
	if !ok || r.tenant != tenantID || !now.Before(r.expires) {
		return "", false, nil
	}
	return r.sealed, true, nil
}

func (s *memSecrets) Delete(_ context.Context, _, messageID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, messageID)
	return nil
}

func (s *memSecrets) DeleteExpired(_ context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, r := range s.rows {
		if !now.Before(r.expires) {
			delete(s.rows, id)
			n++
		}
	}
	return n, nil
}

func (s *memSecrets) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.rows[id]
	return ok
}

// fakeCipher "seals" by reversing the bytes behind a prefix: never the
// plaintext as it is.
type fakeCipher struct{}

func (fakeCipher) Seal(_ context.Context, p []byte) (string, error) {
	return "km1.test." + base64.StdEncoding.EncodeToString(p), nil
}

func (fakeCipher) Open(_ context.Context, c string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(c, "km1.test."))
}
