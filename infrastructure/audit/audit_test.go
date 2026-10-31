package audit

import (
	"context"
	"testing"

	"github.com/razatechofficial/mail-os/domain/access"
)

type memStore struct {
	events []Event
	stream []bool
}

func (m *memStore) Insert(_ context.Context, ev Event, stream bool) error {
	m.events = append(m.events, ev)
	m.stream = append(m.stream, stream)
	return nil
}

const tenant = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"

func TestUserEventCarriesActorTenantAndRequest(t *testing.T) {
	store := &memStore{}
	w := NewWriter(store, true)
	ctx := access.WithPrincipal(context.Background(), access.Principal{
		Kind: access.KindUser, Subject: "0b6c1c3e-6a38-4a8f-9a59-2b9d3b6a8a11", TenantID: tenant, ClientID: "mailos-console",
	})
	ctx = WithRequestMeta(ctx, RequestMeta{IP: "10.0.0.7", UserAgent: "ua", RequestID: "req-1"})
	if err := w.Append(ctx, "template", "t1", "template.published", map[string]any{"version": 4}); err != nil {
		t.Fatal(err)
	}
	ev := store.events[0]
	if ev.Service != Service || ev.ActorType != ActorUser || ev.ActorUUID == nil || ev.TenantUUID.String() != tenant {
		t.Fatalf("event %+v", ev)
	}
	if ev.Metadata["request_id"] != "req-1" || ev.IPAddress != "10.0.0.7" || ev.Tier != TierCritical || ev.Severity != SeverityNotice {
		t.Fatalf("event %+v", ev)
	}
	if !store.stream[0] {
		t.Fatal("the audit stream flag did not reach the store")
	}
}

func TestServiceEventNamesClient(t *testing.T) {
	store := &memStore{}
	ctx := access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindService, Subject: "client:mailos-iam", ClientID: "mailos-iam", TenantID: tenant})
	_ = NewWriter(store, false).Append(ctx, "event", "e1", "event.accepted", nil)
	ev := store.events[0]
	if ev.ActorType != ActorService || ev.Metadata["client_id"] != "mailos-iam" || ev.ActorUUID != nil || ev.Severity != SeverityInformational {
		t.Fatalf("event %+v", ev)
	}
}

func TestChangeRedactsSecrets(t *testing.T) {
	store := &memStore{}
	type provider struct {
		Name        string `json:"name"`
		Credentials string `json:"credentials"`
		Priority    int    `json:"priority"`
	}
	_ = NewWriter(store, false).Change(context.Background(), "provider", "p1", "provider.updated",
		provider{Name: "ses", Credentials: "old-secret", Priority: 1}, provider{Name: "ses", Credentials: "new-secret", Priority: 2}, nil)
	meta := store.events[0].Metadata
	before, after := meta["before"].(map[string]any), meta["after"].(map[string]any)
	if before["credentials"] != RedactedValue || after["credentials"] != RedactedValue {
		t.Fatalf("secret written: %v %v", before, after)
	}
	if _, ok := after["name"]; ok {
		t.Fatal("unchanged field recorded")
	}
	if after["priority"] != float64(2) {
		t.Fatalf("after %v", after)
	}
}

func TestSeverities(t *testing.T) {
	cases := map[string]Severity{
		"mailos.message_rejected": SeverityWarning,
		"access_denied":           SeverityWarning,
		"step_up_required":        SeverityWarning,
		"provider.updated":        SeverityNotice,
		"template.published":      SeverityNotice,
		"message.body_viewed":     SeverityNotice,
		"audit_log.exported":      SeverityNotice,
		"messages.purged":         SeverityNotice,
		"message.send_error":      SeverityError,
		"message.sent":            SeverityInformational,
		"event.accepted":          SeverityInformational,
	}
	for action, want := range cases {
		if got := SeverityOfAction(action, Classify(action)); got != want {
			t.Errorf("%s = %s, want %s", action, got, want)
		}
	}
	forged := Event{Action: "mailos.message_rejected", Tier: TierCritical, Metadata: map[string]any{"reason": "signature"}}
	if SeverityOf(forged) != SeverityAlert {
		t.Fatal("a forged message signature must be an Alert")
	}
	misconfigured := Event{Action: "mailos.message_rejected", Tier: TierCritical, Metadata: map[string]any{"reason": "unknown_client"}}
	if SeverityOf(misconfigured) != SeverityWarning {
		t.Fatal("an unknown client is a Warning")
	}
}
