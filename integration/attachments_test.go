//go:build integration

package integration

import (
	"context"
	"testing"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	appprovider "github.com/razatechofficial/mail-os/application/provider"
	appsuppression "github.com/razatechofficial/mail-os/application/suppression"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/infrastructure/mailer"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// A direct send's attachments are stored with it, loaded for delivery,
// and erased with the body by the retention purge.
func TestAttachmentsStoredDeliveredAndPurged(t *testing.T) {
	e := newMsgEnv(t)
	rdb := connectRedis(t)
	sink := mailer.NewE2ESink(rdb.Client, platformFrom)
	providers := appprovider.NewService(postgres.NewProviderRepository(e.db), e.keys.Cipher(domainkm.PurposeProvider), e.audit, appprovider.Config{})
	svc := appmessage.NewService(appmessage.Deps{Repo: postgres.NewMessageRepository(e.db), Queue: nopQueue{},
		Suppressions: appsuppression.NewService(postgres.NewSuppressionRepository(e.db), e.audit), Tenants: e.tenants,
		Render: renderContent, Sender: routerSender{mailer.NewRouter(provSource{providers}, sink, mailer.Options{})},
		Audit: e.audit}, appmessage.Config{MaxAttempts: 3, RetentionDays: 30,
		Attachments: domainmsg.AttachmentLimits{MaxBytes: 1 << 20, MaxTotalBytes: 2 << 20, MaxCount: 5}})
	ctx := context.Background()
	to := "files-" + e.tenant[:8] + "@example.com"
	r, err := svc.Send(e.userCtx(), appmessage.SendInput{TenantID: e.tenant, FromEmail: "noreply@bank.example", ToEmail: to,
		Subject: "Your statement", Text: "Attached.", Attachments: []domainmsg.Attachment{
			{Filename: "statement.pdf", Data: []byte("%PDF-1.7 statement")},
			{Filename: "logo.png", ContentID: "logo", Inline: true, Data: []byte("png")},
		}})
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewMessageRepository(e.db)
	m, err := repo.Get(ctx, e.tenant, r.MessageID)
	if err != nil || len(m.Attachments) != 2 || m.Attachments[0].ContentType != "application/pdf" ||
		string(m.Attachments[0].Data) != "%PDF-1.7 statement" || m.Attachments[1].ContentID != "logo" || !m.Attachments[1].Inline {
		t.Fatalf("stored %+v %v", m.Attachments, err)
	}
	if v := e.raw(t, `SELECT sha256 FROM message_attachments WHERE message_id = $1 AND position = 0`, m.ID); len(v) != 64 {
		t.Fatalf("sha256 %q", v)
	}
	if err := svc.Deliver(ctx, e.tenant, m.ID); err != nil {
		t.Fatal(err)
	}
	mustExec(t, e, `UPDATE messages SET created_at = now() - interval '31 days' WHERE id = $1`, m.ID)
	if _, err := svc.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	if v := e.raw(t, `SELECT count(*)::text FROM message_attachments WHERE message_id = $1`, m.ID); v != "0" {
		t.Fatalf("purge kept %s attachments", v)
	}
}
