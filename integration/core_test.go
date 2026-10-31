//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	"github.com/razatechofficial/mail-os/application/tenant"
	"github.com/razatechofficial/mail-os/domain/access"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	infrakm "github.com/razatechofficial/mail-os/infrastructure/keymanager"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// A tenant is created on first use, its settings change is audited with
// before and after, and the audit row lands in IAM's format.
func TestTenantProvisioningAndAudit(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	auditRepo := postgres.NewAuditRepository(db)
	w := audit.NewWriter(auditRepo, true)
	svc := tenant.NewService(postgres.NewTenantRepository(db), w, time.Minute)
	id := uuid.NewString()
	if err := svc.Ensure(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := svc.Ensure(ctx, id); err != nil {
		t.Fatal("second ensure:", err)
	}
	actor := uuid.NewString()
	ctx = access.WithPrincipal(ctx, access.Principal{Kind: access.KindUser, Subject: actor, TenantID: id})
	days := 7
	got, err := svc.Settings(ctx, id)
	if err != nil || got.FourEyesPublish {
		t.Fatalf("defaults %+v %v", got, err)
	}
	got.FourEyesPublish, got.MessageRetentionDays = true, &days
	if _, err := svc.UpdateSettings(ctx, got, actor); err != nil {
		t.Fatal(err)
	}
	events, total, err := auditRepo.List(ctx, postgres.AuditFilter{TenantUUID: uuid.MustParse(id), Limit: 10})
	if err != nil || total != 1 || events[0].Action != "tenant_settings.updated" || events[0].ActorUUID.String() != actor {
		t.Fatalf("audit %+v %d %v", events, total, err)
	}
	if events[0].Severity != audit.SeverityNotice || events[0].Tier != audit.TierCritical {
		t.Fatalf("severity %v tier %s", events[0].Severity, events[0].Tier)
	}
	published, err := auditRepo.ClaimOutbox(ctx, 100, func(postgres.OutboxRow) error { return nil }, func(int) time.Duration { return time.Second })
	if err != nil || published < 1 {
		t.Fatalf("outbox relay: %d %v", published, err)
	}
}

// Two replicas bootstrap the key manager against one database: one active
// key per purpose, and each opens what the other sealed.
func TestKeyManagerReplicas(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	master := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	newSvc := func() *appkm.Service {
		p, _ := infrakm.NewSoftwareProvider(master)
		s := appkm.New(p, postgres.NewEncryptionKeyRepository(db), nil, appkm.Config{})
		if err := s.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	a, b := newSvc(), newSvc()
	sealed, err := a.Seal(ctx, domainkm.PurposeDKIM, []byte("-----BEGIN PRIVATE KEY-----"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Open(ctx, domainkm.PurposeDKIM, sealed); err != nil || string(got) != "-----BEGIN PRIVATE KEY-----" {
		t.Fatalf("replica open: %q %v", got, err)
	}
	if _, err := a.Rotate(ctx, domainkm.PurposeDKIM, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(ctx, domainkm.PurposeDKIM, sealed); err != nil {
		t.Fatalf("value sealed before rotation: %v", err)
	}
	st, err := b.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, ps := range st {
		active := 0
		for _, k := range ps.Keys {
			if k.State == domainkm.StateActive {
				active++
			}
		}
		if active != 1 {
			t.Fatalf("%s has %d active keys", ps.Purpose, active)
		}
	}
}
