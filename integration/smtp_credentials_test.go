//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/applications"
	"github.com/razatechofficial/mail-os/application/smtpcred"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// SMTP credentials round-trip through Postgres with only a hash at rest,
// follow the application's opt-in, and a revocation is seen at once.
func TestSMTPCredentialRepository(t *testing.T) {
	e := newAppsEnv(t)
	a := e.create(t, func(in *applications.Input) { in.SMTPPasswordAuth = true })
	if got, err := e.repo.Get(e.userCtx(), e.tenant, a.ID); err != nil || !got.SMTPPasswordAuth {
		t.Fatalf("smtp_password_auth round-trips: %+v %v", got, err)
	}
	svc := smtpcred.NewService(postgres.NewSMTPCredentialRepository(e.db), e.svc, e.audit, smtpcred.Config{})
	ctx := e.userCtx()
	c, password, err := svc.Create(ctx, e.tenant, a.ID, "batch host", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if stored := e.raw(t, `SELECT password_hash FROM smtp_credentials WHERE id = $1`, c.ID); !strings.HasPrefix(stored, "$argon2id$") ||
		strings.Contains(stored, password) {
		t.Fatalf("only an Argon2id hash is stored: %q", stored)
	}
	got, app, err := svc.Authenticate(context.Background(), c.Username, password, "10.1.2.3")
	if err != nil || got.ID != c.ID || app.ID != a.ID {
		t.Fatalf("authenticate: %v", err)
	}
	if ip := e.raw(t, `SELECT last_used_ip FROM smtp_credentials WHERE id = $1`, c.ID); ip != "10.1.2.3" {
		t.Fatalf("last use: %q", ip)
	}
	if _, _, err := svc.Rotate(ctx, e.tenant, a.ID, c.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Authenticate(context.Background(), c.Username, password, ""); err == nil {
		t.Fatal("the old password stops after rotation")
	}
	if err := svc.Revoke(ctx, e.tenant, a.ID, c.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(context.Background(), c); err == nil {
		t.Fatal("a revoked credential stops an open session")
	}
	list, err := svc.List(ctx, e.tenant, a.ID)
	if err != nil || len(list) != 1 || list[0].Active() || list[0].RevokedBy != "admin" {
		t.Fatalf("list %+v %v", list, err)
	}
}

// A direct send's List-Unsubscribe headers are stored with the message.
func TestMessageHeadersRoundTrip(t *testing.T) {
	e := newMsgEnv(t)
	repo := postgres.NewMessageRepository(e.db)
	now := time.Now().UTC()
	m := domainmsg.Message{ID: uuid.NewString(), OrgID: e.tenant, FromEmail: "news@bank.example",
		ToEmail: "amna@example.com", Subject: "Offers", HTMLBody: "<p>Offers</p>", Type: domainmsg.TypeMarketing,
		Status: domainmsg.StatusQueued, Priority: domainmsg.PriorityNormal, Stream: domainmsg.StreamBroadcast,
		Headers:   map[string]string{"List-Unsubscribe": "<https://bank.example/u/1>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"},
		CreatedAt: now, UpdatedAt: now}
	if err := repo.Create(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(context.Background(), e.tenant, m.ID)
	if err != nil || got.Headers["List-Unsubscribe"] != "<https://bank.example/u/1>" || len(got.Headers) != 2 {
		t.Fatalf("headers %v %v", got.Headers, err)
	}
}
