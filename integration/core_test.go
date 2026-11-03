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
		s := appkm.New(softwareKEKs(t, master, ""), postgres.NewEncryptionKeyRepository(db), nil, appkm.Config{})
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

// softwareKEKs is the software KEK of master and, when set, the new one.
func softwareKEKs(t *testing.T, master, newMaster string) *appkm.KEKs {
	t.Helper()
	cur, err := infrakm.NewSoftwareKEK("KEY_MANAGER_MASTER_KEY", master)
	if err != nil {
		t.Fatal(err)
	}
	var next appkm.KEK
	if newMaster != "" {
		if next, err = infrakm.NewSoftwareKEK("KEY_MANAGER_NEW_MASTER_KEY", newMaster); err != nil {
			t.Fatal(err)
		}
	}
	keks, err := appkm.NewKEKs(cur, next)
	if err != nil {
		t.Fatal(err)
	}
	return keks
}

// A KEK rotation against Postgres: every data key is re-wrapped under the
// new master key (kek_id recorded), one rotation runs at a time, and the
// new master key alone opens what was sealed before. It rotates back at the
// end, so the other tests keep their master key.
func TestKEKRotationPostgres(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	repo := postgres.NewEncryptionKeyRepository(db)
	oldKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	newKey := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	a := appkm.New(softwareKEKs(t, oldKey, ""), repo, nil, appkm.Config{})
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	sealed, err := a.Seal(ctx, domainkm.PurposeWebhook, []byte("whsec_1"))
	if err != nil {
		t.Fatal(err)
	}
	rotate := func(from, to string) appkm.KEKRotationStatus {
		t.Helper()
		s := appkm.New(softwareKEKs(t, from, to), repo, nil, appkm.Config{KEKSettle: time.Nanosecond})
		if err := s.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		r, err := s.StartKEKRotation(ctx, "test", "integration")
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.InsertKEKRotation(ctx, *r); err == nil {
			t.Fatal("second running rotation stored")
		}
		if err := s.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		st, err := s.KEKStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(st.WrappedBy) != 1 || st.WrappedBy[r.ToKEK] == 0 || st.History[0].State != domainkm.RotationCompleted {
			t.Fatalf("status %+v", st)
		}
		return st.History[0]
	}
	rotate(oldKey, newKey)
	promoted := appkm.New(softwareKEKs(t, newKey, ""), repo, nil, appkm.Config{})
	if err := promoted.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := promoted.Open(ctx, domainkm.PurposeWebhook, sealed); err != nil || string(got) != "whsec_1" {
		t.Fatalf("open after rotation: %q %v", got, err)
	}
	if err := appkm.New(softwareKEKs(t, oldKey, ""), repo, nil, appkm.Config{}).Bootstrap(ctx); err == nil {
		t.Fatal("the old master key alone still loads")
	}
	back := rotate(newKey, oldKey)
	if back.Rewrapped == 0 || back.Remaining != 0 {
		t.Fatalf("rotation back %+v", back)
	}
}
