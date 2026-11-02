package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

const (
	tenantA = "8d3b1f7a-2c4e-4f6a-9b1d-3e5f7a9c1b2d"
	tenantB = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
)

type memStore struct {
	mu   sync.Mutex
	rows map[string]Record
}

func (m *memStore) Claim(_ context.Context, r Record) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prior, ok := m.rows[r.TenantID+"/"+r.EventID]; ok {
		return prior, false, nil
	}
	m.rows[r.TenantID+"/"+r.EventID] = r
	return Record{}, true, nil
}

func (m *memStore) Complete(_ context.Context, tenant, id, messageID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rows[tenant+"/"+id]
	r.MessageID = messageID
	m.rows[tenant+"/"+id] = r
	return nil
}

// fakeTx rolls the store back when fn fails, as a transaction would.
type fakeTx struct{ store *memStore }

func (t fakeTx) InTx(ctx context.Context, fn func(context.Context) error) error {
	t.store.mu.Lock()
	saved := make(map[string]Record, len(t.store.rows))
	for k, v := range t.store.rows {
		saved[k] = v
	}
	t.store.mu.Unlock()
	if err := fn(ctx); err != nil {
		t.store.mu.Lock()
		t.store.rows = saved
		t.store.mu.Unlock()
		return err
	}
	return nil
}

type fakeDispatcher struct {
	sent []Delivery
	err  error
}

func (d *fakeDispatcher) Dispatch(_ context.Context, del Delivery) (string, error) {
	if d.err != nil {
		return "", d.err
	}
	d.sent = append(d.sent, del)
	return "msg-" + del.EventID, nil
}

type auditEntry struct {
	action string
	tenant string
	meta   map[string]any
}

type fakeAudit struct{ entries []auditEntry }

func (a *fakeAudit) Append(ctx context.Context, _, _, action string, meta map[string]any) error {
	p, _ := access.FromContext(ctx)
	a.entries = append(a.entries, auditEntry{action: action, tenant: p.TenantID, meta: meta})
	return nil
}

type fakeTenants struct{ ensured []string }

func (f *fakeTenants) Ensure(_ context.Context, id string) error {
	f.ensured = append(f.ensured, id)
	return nil
}

type fixture struct {
	svc      *Service
	store    *memStore
	dispatch *fakeDispatcher
	audit    *fakeAudit
	tenants  *fakeTenants
}

func newFixture() *fixture {
	f := &fixture{store: &memStore{rows: map[string]Record{}}, dispatch: &fakeDispatcher{}, audit: &fakeAudit{}, tenants: &fakeTenants{}}
	suspended := appstest.Server("iam-suspended", tenantA, "iam.*")
	suspended.Status = domainapp.StatusSuspended
	apps := appstest.New(appstest.Server("iam", tenantA, "iam.*"), suspended)
	f.svc = NewService(apps, f.tenants, f.store, fakeTx{f.store}, f.dispatch, f.audit)
	return f
}

func service(client, tenant string) context.Context {
	return access.WithPrincipal(context.Background(), access.Principal{
		Kind: access.KindService, Subject: "client:" + client, ClientID: client, TenantID: tenant})
}

func resetEvent(id, tenant string) event.Event {
	data, _ := json.Marshal(template.SampleData(template.TopicPasswordReset))
	return event.Event{ID: id, Type: template.TopicPasswordReset, Source: "iam", Data: data, TenantUUID: tenant}
}

func (f *fixture) actions() []string {
	out := make([]string, len(f.audit.entries))
	for i, e := range f.audit.entries {
		out[i] = e.action
	}
	return out
}

func TestDispatchAcceptsAndDispatchesOnce(t *testing.T) {
	f := newFixture()
	ctx := service("iam", tenantA)
	in := In{Transport: TransportHTTP, Event: resetEvent("e1", tenantA)}
	res, err := f.svc.Dispatch(ctx, in)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !res.Accepted || res.Duplicate || res.DeliveryID != "msg-e1" || res.EventID != "e1" {
		t.Fatalf("result = %+v", res)
	}
	if len(f.dispatch.sent) != 1 {
		t.Fatalf("dispatched %d", len(f.dispatch.sent))
	}
	d := f.dispatch.sent[0]
	if d.TenantID != tenantA || d.ClientID != "iam" || d.Topic != template.TopicPasswordReset || d.Data["email"] == nil {
		t.Fatalf("delivery = %+v", d)
	}
	if len(f.tenants.ensured) != 1 || f.tenants.ensured[0] != tenantA {
		t.Fatalf("tenants ensured %v", f.tenants.ensured)
	}
	acc := f.audit.entries[0]
	if acc.action != AuditAccepted || acc.tenant != tenantA || acc.meta["message_id"] != "msg-e1" {
		t.Fatalf("audit = %+v", acc)
	}
	if _, ok := acc.meta["data"]; ok {
		t.Fatal("the audit row carries the event data")
	}

	// The same event again, with new trace metadata: accepted, no message.
	in.Event.Metadata = map[string]string{"traceparent": "00-x"}
	res, err = f.svc.Dispatch(ctx, in)
	if err != nil || !res.Duplicate || res.DeliveryID != "msg-e1" {
		t.Fatalf("duplicate = %+v, %v", res, err)
	}
	if len(f.dispatch.sent) != 1 {
		t.Fatal("a duplicate was dispatched again")
	}
	if dup := f.audit.entries[1]; dup.action != AuditAccepted || dup.meta["duplicate"] != true {
		t.Fatalf("duplicate audit = %+v", dup)
	}

	// The id reused for other data is a conflict.
	other := resetEvent("e1", tenantA)
	other.Data = json.RawMessage(`{"email":"x@example.com","reset_link":"https://iam.example/r"}`)
	if _, err := f.svc.Dispatch(ctx, In{Transport: TransportHTTP, Event: other}); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("reused id: %v", err)
	}
}

// The application decides the tenant: a token and an event naming none
// act for the application's, and the delivery carries the application.
func TestDispatchUsesTheApplicationTenant(t *testing.T) {
	f := newFixture()
	res, err := f.svc.Dispatch(service("iam", ""), In{Transport: TransportGRPC, Event: resetEvent("", "")})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.EventID == "" || f.dispatch.sent[0].TenantID != tenantA || f.dispatch.sent[0].ApplicationID == "" {
		t.Fatalf("result %+v, delivery %+v", res, f.dispatch.sent[0])
	}
}

func TestDispatchRefusals(t *testing.T) {
	cases := []struct {
		name   string
		ctx    context.Context
		in     In
		reason string
	}{
		{"no principal", context.Background(), In{Transport: TransportHTTP, Event: resetEvent("e", tenantA)}, "not_service_caller"},
		{"user", access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindUser, Subject: "u", TenantID: tenantA}),
			In{Transport: TransportHTTP, Event: resetEvent("e", tenantA)}, "not_service_caller"},
		{"unknown client", service("crm", tenantA), In{Transport: TransportHTTP, Event: resetEvent("e", tenantA)}, "unknown_client"},
		{"foreign tenant", service("iam", tenantA), In{Transport: TransportHTTP, Event: resetEvent("e", tenantB)}, "tenant_mismatch"},
		{"token for another tenant", service("iam", tenantB), In{Transport: TransportHTTP, Event: resetEvent("e", "")}, "tenant_mismatch"},
		{"suspended application", service("iam-suspended", tenantA), In{Transport: TransportHTTP, Event: resetEvent("e", tenantA)}, "application_suspended"},
		{"wrong topic", service("iam", tenantA), In{Transport: TransportHTTP, Event: func() event.Event {
			e := resetEvent("e", tenantA)
			e.Type = "mailos.campaign"
			return e
		}()}, "message_type_not_allowed"},
		{"topic hint", service("iam", tenantA), In{Transport: TransportGRPC, Event: resetEvent("e", tenantA), TopicHint: "iam.auth.login"}, "message_type_not_allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			_, err := f.svc.Dispatch(tc.ctx, tc.in)
			if apperrors.KindOf(err) != apperrors.KindForbidden {
				t.Fatalf("err = %v, want 403", err)
			}
			if _, ok := IsRefusal(err); !ok {
				t.Fatalf("IsRefusal(%v) = false", err)
			}
			if len(f.audit.entries) != 1 || f.audit.entries[0].action != AuditRefused || f.audit.entries[0].meta["reason"] != tc.reason {
				t.Fatalf("audit = %+v, want event.refused %s", f.audit.entries, tc.reason)
			}
			if len(f.dispatch.sent) != 0 {
				t.Fatal("a refused event was dispatched")
			}
		})
	}
}

func TestDispatchOverKafkaLeavesTheRejectionAuditToTheConsumer(t *testing.T) {
	f := newFixture()
	_, err := f.svc.Dispatch(service("crm", tenantA), In{Transport: TransportKafka, Event: resetEvent("e", tenantA)})
	if reason, ok := IsRefusal(err); !ok || reason != "unknown_client" || !errors.Is(err, domainapp.ErrUnknownClient) {
		t.Fatalf("err = %v", err)
	}
	if len(f.audit.entries) != 0 {
		t.Fatalf("audited %v", f.actions())
	}
}

func TestDispatchValidatesData(t *testing.T) {
	f := newFixture()
	ctx := service("iam", tenantA)
	noEmail := resetEvent("e1", tenantA)
	noEmail.Data = json.RawMessage(`{"reset_link":"https://iam.example/r"}`)
	_, err := f.svc.Dispatch(ctx, In{Transport: TransportHTTP, Event: noEmail})
	if apperrors.KindOf(err) != apperrors.KindInvalidInput || !hasField(err, "data.email") {
		t.Fatalf("missing email: %v %+v", err, apperrors.DetailsOf(err))
	}
	unknown := resetEvent("e2", tenantA)
	unknown.Type = "iam.auth.login"
	if _, err := f.svc.Dispatch(ctx, In{Transport: TransportHTTP, Event: unknown}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("topic outside the catalogue: %v", err)
	}
	bad := resetEvent("e3", tenantA)
	bad.Type = "IAM"
	if _, err := f.svc.Dispatch(ctx, In{Transport: TransportHTTP, Event: bad}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("bad type: %v", err)
	}
	if len(f.dispatch.sent) != 0 || len(f.store.rows) != 0 {
		t.Fatal("an invalid event was recorded or dispatched")
	}
}

func TestDispatchFailureRecordsNothing(t *testing.T) {
	f := newFixture()
	f.dispatch.err = apperrors.Unavailable("smtp down")
	ctx := service("iam", tenantA)
	in := In{Transport: TransportKafka, Event: resetEvent("e1", tenantA)}
	if _, err := f.svc.Dispatch(ctx, in); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("err = %v", err)
	}
	f.dispatch.err = nil
	res, err := f.svc.Dispatch(ctx, in)
	if err != nil || res.Duplicate || len(f.dispatch.sent) != 1 {
		t.Fatalf("retry after a failed dispatch: %+v %v", res, err)
	}
	if _, err := (Unconfigured{}).Dispatch(ctx, Delivery{}); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("Unconfigured: %v", err)
	}
}

func hasField(err error, field string) bool {
	for _, d := range apperrors.DetailsOf(err) {
		if strings.EqualFold(d.Field, field) {
			return true
		}
	}
	return false
}

// A send the application refuses while dispatching (its sender, its
// quota) rolls the event back and is audited as the event's refusal,
// keeping the 429 or 403 the application answered.
func TestDispatchAuditsASendRefusedByTheApplication(t *testing.T) {
	f := newFixture()
	f.dispatch.err = apperrors.Wrap(domainapp.ErrQuotaExceeded, apperrors.KindRateLimited, apperrors.CodeRateLimited, "quota")
	_, err := f.svc.Dispatch(service("iam", tenantA), In{Transport: TransportHTTP, Event: resetEvent("e9", tenantA)})
	if apperrors.KindOf(err) != apperrors.KindRateLimited {
		t.Fatalf("err = %v, want the 429", err)
	}
	if len(f.audit.entries) != 1 || f.audit.entries[0].action != AuditRefused || f.audit.entries[0].meta["reason"] != "quota_exceeded" ||
		f.audit.entries[0].meta["application_id"] == nil {
		t.Fatalf("audit = %+v", f.audit.entries)
	}
	if _, fresh, _ := f.store.Claim(context.Background(), Record{TenantID: tenantA, EventID: "e9"}); !fresh {
		t.Fatal("the refused event stayed recorded")
	}
}
