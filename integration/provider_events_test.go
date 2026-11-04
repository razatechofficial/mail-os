//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	appprovider "github.com/razatechofficial/mail-os/application/provider"
	appsuppression "github.com/razatechofficial/mail-os/application/suppression"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domainprovider "github.com/razatechofficial/mail-os/domain/provider"
	domainsup "github.com/razatechofficial/mail-os/domain/suppression"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/pkg/id"
)

// A provider's delivery events find the message by the provider's id, are
// stored once, move its status and suppress a hard-bounced address.
func TestProviderDeliveryEvents(t *testing.T) {
	e := newMsgEnv(t)
	ctx := e.userCtx()
	providers := appprovider.NewService(postgres.NewProviderRepository(e.db), e.keys.Cipher(domainkm.PurposeProvider), e.audit, appprovider.Config{})
	p, err := providers.Create(ctx, e.tenant, appprovider.Input{Name: "Postmark", Kind: domainprovider.KindPostmark,
		Credentials: domainprovider.Credentials{ServerToken: "pm-token", WebhookSecret: "hook-password"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewMessageRepository(e.db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	m := domainmsg.Message{ID: id.New(), OrgID: e.tenant, ToEmail: "gone-" + e.tenant[:8] + "@example.com", FromEmail: "noreply@bank.example",
		Subject: "s", TextBody: "b", Status: domainmsg.StatusSent, ProviderID: p.ID, ProviderMessageID: "pm-msg-" + e.tenant[:8],
		SentAt: &now, CreatedAt: now, UpdatedAt: now}
	m.Normalize()
	if err := repo.Create(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	events := postgres.NewMessageEventRepository(e.db)
	found, err := events.ByProviderMessageID(context.Background(), e.tenant, p.ID, m.ProviderMessageID)
	if err != nil || found.ID != m.ID {
		t.Fatalf("by provider id: %+v %v", found, err)
	}

	sups := appsuppression.NewService(postgres.NewSuppressionRepository(e.db), e.audit)
	svc := appmessage.NewService(appmessage.Deps{Repo: repo, Suppressions: sups, Tenants: e.tenants, Audit: e.audit,
		Events: events, Feedback: sups}, appmessage.Config{})
	ev := domainmsg.ProviderEvent{Type: domainmsg.EventBounced, ProviderMessageID: m.ProviderMessageID, Recipient: m.ToEmail,
		Reason: "HardBounce: unknown user", ProviderEventID: "bounce:1", OccurredAt: now}
	if out, err := svc.RecordProviderEvent(context.Background(), e.tenant, p.ID, ev); err != nil || out != appmessage.OutcomeRecorded {
		t.Fatalf("record: %s %v", out, err)
	}
	if out, _ := svc.RecordProviderEvent(context.Background(), e.tenant, p.ID, ev); out != appmessage.OutcomeDuplicate {
		t.Fatalf("redelivery: %s", out)
	}
	stored, _ := repo.Get(context.Background(), e.tenant, m.ID)
	if stored.Status != domainmsg.StatusBounced || stored.BouncedAt == nil {
		t.Fatalf("stored %+v", stored)
	}
	list, err := events.List(context.Background(), e.tenant, m.ID)
	if err != nil || len(list) != 1 || list[0].Type != domainmsg.EventBounced || list[0].Reason != ev.Reason || list[0].ProviderID != p.ID {
		t.Fatalf("events %+v %v", list, err)
	}
	if v := e.raw(t, `SELECT provider FROM message_events WHERE message_id = $1`, m.ID); v != string(domainprovider.KindPostmark) {
		t.Fatalf("provider kind %q", v)
	}
	sup, err := sups.Blocks(context.Background(), e.tenant, "", m.ToEmail, domainmsg.TypeTransactional)
	if err != nil || sup == nil || sup.Type != domainsup.TypeBounce || sup.Source != domainsup.SourceWebhook {
		t.Fatalf("suppression %+v %v", sup, err)
	}
}
