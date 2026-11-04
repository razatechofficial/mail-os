package inbound

import (
	"context"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type fakeDeliveries struct {
	msgs   map[string]domainmsg.Message
	events map[string][]domainmsg.DeliveryEvent
}

func (f fakeDeliveries) Delivery(_ context.Context, tenantID, id string) (domainmsg.Message, []domainmsg.DeliveryEvent, error) {
	m, ok := f.msgs[id]
	if !ok || m.OrgID != tenantID {
		return domainmsg.Message{}, nil, apperrors.NotFound("message not found")
	}
	return m, f.events[id], nil
}

func (m *memStore) Record(_ context.Context, tenantID, eventID string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[tenantID+"/"+eventID]
	if !ok {
		return Record{}, apperrors.NotFound("event not found")
	}
	return r, nil
}

func TestDeliveryStatusScopedToTheCallersApplication(t *testing.T) {
	iam := appstest.Server("iam", tenantA, "iam.*")
	crm := appstest.Server("crm", tenantA, "iam.*")
	other := appstest.Server("other", tenantB, "iam.*")
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	sent, delivered := t0.Add(time.Second), t0.Add(time.Minute)
	msgs := map[string]domainmsg.Message{
		"m-iam": {ID: "m-iam", OrgID: tenantA, ApplicationID: iam.ID, Status: domainmsg.StatusDelivered, EventID: "evt-1",
			CreatedAt: t0, UpdatedAt: delivered, SentAt: &sent, DeliveredAt: &delivered},
		"m-crm":     {ID: "m-crm", OrgID: tenantA, ApplicationID: crm.ID, Status: domainmsg.StatusSent, CreatedAt: t0},
		"m-console": {ID: "m-console", OrgID: tenantA, Status: domainmsg.StatusQueued, CreatedAt: t0},
		"m-sched":   {ID: "m-sched", OrgID: tenantA, ApplicationID: iam.ID, Status: domainmsg.StatusScheduled, CreatedAt: t0},
	}
	events := map[string][]domainmsg.DeliveryEvent{"m-iam": {
		{Type: domainmsg.EventDeferred, OccurredAt: t0.Add(30 * time.Second)},
		{Type: domainmsg.EventDelivered, OccurredAt: delivered},
	}}
	store := &memStore{rows: map[string]Record{
		tenantA + "/evt-1": {TenantID: tenantA, EventID: "evt-1", ApplicationID: iam.ID, MessageID: "m-iam"},
		tenantA + "/evt-2": {TenantID: tenantA, EventID: "evt-2", ApplicationID: crm.ID, MessageID: "m-crm"},
		tenantA + "/evt-3": {TenantID: tenantA, EventID: "evt-3", ApplicationID: iam.ID},
	}}
	svc := NewStatusService(appstest.New(iam, crm, other), fakeDeliveries{msgs: msgs, events: events}, store)
	ctx := service("iam", tenantA)

	st, err := svc.ByDelivery(ctx, "m-iam")
	if err != nil || st.Status != DeliveryDelivered || st.EventID != "evt-1" || st.DeliveryID != "m-iam" {
		t.Fatalf("%+v %v", st, err)
	}
	var types []string
	for _, e := range st.Events {
		types = append(types, e.Type)
	}
	if want := []string{"queued", "sent", "deferred", "delivered"}; len(types) != len(want) ||
		types[0] != want[0] || types[1] != want[1] || types[2] != want[2] || types[3] != want[3] {
		t.Fatalf("steps %v, want %v", types, want)
	}
	byEvent, err := svc.ByEvent(ctx, "evt-1")
	if err != nil || byEvent.DeliveryID != "m-iam" || byEvent.Status != DeliveryDelivered {
		t.Fatalf("%+v %v", byEvent, err)
	}
	if st, _ := svc.ByDelivery(ctx, "m-sched"); st.Status != DeliveryQueued {
		t.Fatalf("scheduled is reported as %s", st.Status)
	}

	// Another application's, the console's, an unknown, another tenant's
	// or a not-yet-dispatched event's message is not found.
	for name, call := range map[string]func() error{
		"other app's delivery":  func() error { _, err := svc.ByDelivery(ctx, "m-crm"); return err },
		"console message":       func() error { _, err := svc.ByDelivery(ctx, "m-console"); return err },
		"unknown delivery":      func() error { _, err := svc.ByDelivery(ctx, "nope"); return err },
		"other app's event":     func() error { _, err := svc.ByEvent(ctx, "evt-2"); return err },
		"event without message": func() error { _, err := svc.ByEvent(ctx, "evt-3"); return err },
		"other tenant": func() error {
			_, err := svc.ByDelivery(service("other", tenantB), "m-iam")
			return err
		},
	} {
		if err := call(); !apperrors.IsNotFound(err) {
			t.Errorf("%s: err = %v, want not found", name, err)
		}
	}
	// A user, or an unknown client, cannot ask.
	if _, err := svc.ByDelivery(access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindUser, Subject: "u", TenantID: tenantA}), "m-iam"); err == nil {
		t.Fatal("a user read a service's delivery")
	}
	if _, err := svc.ByDelivery(service("crm-unknown", tenantA), "m-iam"); err == nil {
		t.Fatal("an unknown client read a delivery")
	}
}
