package message

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	analytics "github.com/razatechofficial/mail-os/application/analytics"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/suppression"
	"github.com/razatechofficial/mail-os/domain/webhook"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type memEvents struct {
	mu   sync.Mutex
	repo *memRepo
	list []domainmsg.DeliveryEvent
}

func (e *memEvents) ByProviderMessageID(_ context.Context, tenantID, providerID, pmid string) (domainmsg.Message, error) {
	for _, m := range e.repo.filter(func(m domainmsg.Message) bool {
		return m.OrgID == tenantID && m.ProviderID == providerID && m.ProviderMessageID == pmid
	}) {
		return m, nil
	}
	return domainmsg.Message{}, apperrors.NotFound("message not found")
}

func (e *memEvents) Add(_ context.Context, ev domainmsg.DeliveryEvent) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, o := range e.list {
		if o.MessageID == ev.MessageID && o.Type == ev.Type && o.Key == ev.Key {
			return false, nil
		}
	}
	e.list = append(e.list, ev)
	return true, nil
}

func (e *memEvents) List(_ context.Context, tenantID, messageID string) ([]domainmsg.DeliveryEvent, error) {
	var out []domainmsg.DeliveryEvent
	for _, o := range e.list {
		if o.TenantID == tenantID && o.MessageID == messageID {
			out = append(out, o)
		}
	}
	return out, nil
}

type memFeedback struct {
	got []string
}

func (f *memFeedback) RecordFeedback(_ context.Context, _, email string, t suppression.Type, _ string) error {
	f.got = append(f.got, string(t)+":"+email)
	return nil
}

// sentMessage is a message p1 accepted as pm-1.
func sentMessage(t *testing.T, f *fixture, id string) domainmsg.Message {
	t.Helper()
	m := domainmsg.Message{ID: id, OrgID: tenant, ToEmail: "ana@example.com", FromEmail: "noreply@bank.example", Subject: "s",
		TextBody: "b", Status: domainmsg.StatusSent, ProviderID: "p1", ProviderMessageID: "pm-" + id, ApplicationID: "app-1",
		CreatedAt: time.Now().UTC()}
	if err := f.repo.Create(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	return m
}

func eventsFixture(t *testing.T) (*fixture, *memEvents, *memFeedback) {
	f := newFixture(t)
	ev, fb := &memEvents{repo: f.repo}, &memFeedback{}
	f.svc.d.Events, f.svc.d.Feedback = ev, fb
	return f, ev, fb
}

func TestDeliveredEventMovesAndCounts(t *testing.T) {
	f, events, _ := eventsFixture(t)
	sentMessage(t, f, "m1")
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	e := domainmsg.ProviderEvent{Type: domainmsg.EventDelivered, ProviderMessageID: "pm-m1", Recipient: "ana@example.com", OccurredAt: at}
	out, err := f.svc.RecordProviderEvent(context.Background(), tenant, "p1", e)
	if err != nil || out != OutcomeRecorded {
		t.Fatalf("%s %v", out, err)
	}
	m, _ := f.repo.Get(context.Background(), tenant, "m1")
	if m.Status != domainmsg.StatusDelivered || m.DeliveredAt == nil || !m.DeliveredAt.Equal(at) {
		t.Fatalf("message %+v", m)
	}
	if f.stats.counts[analytics.Delivered] != 1 || len(f.notifier.events) != 1 || f.notifier.events[0] != webhook.EventDelivered {
		t.Fatalf("stats %v webhooks %v", f.stats.counts, f.notifier.events)
	}
	// A redelivered webhook is recorded once.
	if out, _ := f.svc.RecordProviderEvent(context.Background(), tenant, "p1", e); out != OutcomeDuplicate {
		t.Fatalf("redelivery: %s", out)
	}
	if len(events.list) != 1 || f.stats.counts[analytics.Delivered] != 1 {
		t.Fatalf("events %v", events.list)
	}
	v, err := f.svc.Get(context.Background(), tenant, "m1")
	if err != nil || len(v.Events) != 1 || v.Events[0].Type != domainmsg.EventDelivered {
		t.Fatalf("view events %+v %v", v.Events, err)
	}
}

func TestHardBounceAndComplaintSuppress(t *testing.T) {
	f, _, fb := eventsFixture(t)
	sentMessage(t, f, "m1")
	sentMessage(t, f, "m2")
	ctx := context.Background()
	if _, err := f.svc.RecordProviderEvent(ctx, tenant, "p1", domainmsg.ProviderEvent{Type: domainmsg.EventBounced, MessageID: "m1",
		Recipient: "ANA@example.com", Reason: "550 5.1.1 unknown"}); err != nil {
		t.Fatal(err)
	}
	m, _ := f.repo.Get(ctx, tenant, "m1")
	if m.Status != domainmsg.StatusBounced || m.LastError != "550 5.1.1 unknown" {
		t.Fatalf("bounced %+v", m)
	}
	if _, err := f.svc.RecordProviderEvent(ctx, tenant, "p1", domainmsg.ProviderEvent{Type: domainmsg.EventComplained,
		ProviderMessageID: "pm-m2", Recipient: "ana@example.com"}); err != nil {
		t.Fatal(err)
	}
	m, _ = f.repo.Get(ctx, tenant, "m2")
	if m.Status != domainmsg.StatusComplained {
		t.Fatalf("complained %+v", m)
	}
	if len(fb.got) != 2 || fb.got[0] != "bounce:ana@example.com" || fb.got[1] != "complaint:ana@example.com" {
		t.Fatalf("feedback %v", fb.got)
	}
	if !f.audit.has("message.bounced") || !f.audit.has("message.complained") {
		t.Fatalf("audit %v", f.audit.actions)
	}
	if f.stats.counts[analytics.Bounced] != 1 || f.stats.counts[analytics.Complained] != 1 {
		t.Fatalf("stats %v", f.stats.counts)
	}
}

func TestSoftBounceRecordsOnly(t *testing.T) {
	f, events, fb := eventsFixture(t)
	sentMessage(t, f, "m1")
	out, err := f.svc.RecordProviderEvent(context.Background(), tenant, "p1",
		domainmsg.ProviderEvent{Type: domainmsg.EventSoftBounced, ProviderMessageID: "pm-m1"})
	if err != nil || out != OutcomeRecorded || len(events.list) != 1 || len(fb.got) != 0 {
		t.Fatalf("%s %v %v %v", out, err, events.list, fb.got)
	}
	if m, _ := f.repo.Get(context.Background(), tenant, "m1"); m.Status != domainmsg.StatusSent {
		t.Fatalf("status %s", m.Status)
	}
}

// Another provider's, or another tenant's, message is unknown: a webhook
// can only speak for what its own provider sent.
func TestEventScopedToProviderAndTenant(t *testing.T) {
	f, events, _ := eventsFixture(t)
	sentMessage(t, f, "m1")
	ctx := context.Background()
	for _, c := range []struct{ tenant, provider string }{{tenant, "p2"}, {"other-tenant", "p1"}} {
		out, err := f.svc.RecordProviderEvent(ctx, c.tenant, c.provider,
			domainmsg.ProviderEvent{Type: domainmsg.EventBounced, MessageID: "m1", ProviderMessageID: "pm-m1"})
		if err != nil || out != OutcomeUnknownMessage {
			t.Fatalf("%+v: %s %v", c, out, err)
		}
	}
	if len(events.list) != 0 {
		t.Fatal("recorded an event for a message the provider did not send")
	}
}

func TestEventForMessageStillSending(t *testing.T) {
	f, _, _ := eventsFixture(t)
	m := sentMessage(t, f, "m1")
	m.Status, m.ProviderID = domainmsg.StatusSending, ""
	f.repo.msgs["m1"] = m
	_, err := f.svc.RecordProviderEvent(context.Background(), tenant, "p1",
		domainmsg.ProviderEvent{Type: domainmsg.EventDelivered, MessageID: "m1"})
	if !errors.Is(err, ErrStillSending) {
		t.Fatalf("err = %v", err)
	}
}

// A late delivered event after a bounce is kept but does not undo it.
func TestLateEventKeepsStatus(t *testing.T) {
	f, events, _ := eventsFixture(t)
	m := sentMessage(t, f, "m1")
	m.Status = domainmsg.StatusBounced
	f.repo.msgs["m1"] = m
	out, err := f.svc.RecordProviderEvent(context.Background(), tenant, "p1",
		domainmsg.ProviderEvent{Type: domainmsg.EventDelivered, MessageID: "m1"})
	if err != nil || out != OutcomeRecorded || len(events.list) != 1 {
		t.Fatalf("%s %v", out, err)
	}
	if got, _ := f.repo.Get(context.Background(), tenant, "m1"); got.Status != domainmsg.StatusBounced {
		t.Fatalf("status %s", got.Status)
	}
	if f.stats.counts[analytics.Delivered] != 0 {
		t.Fatal("a delivered event that moved nothing is not counted")
	}
}
