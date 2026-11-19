//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/auditintegrity"
	"github.com/razatechofficial/mail-os/application/tenant"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// Audit rows written through the writer are sealed by a signed digest
// that verifies on Postgres, and editing a sealed row is found.
func TestAuditDigestsOnPostgres(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	w := audit.NewWriter(postgres.NewAuditRepository(db), false)
	id := uuid.NewString()
	if err := tenant.NewService(postgres.NewTenantRepository(db), w, time.Minute).Ensure(ctx, id); err != nil {
		t.Fatal(err)
	}
	actx := access.WithPrincipal(audit.WithTenant(ctx, id), access.Principal{Kind: access.KindUser, Subject: uuid.NewString(), TenantID: id})
	for i := range 3 {
		if err := w.Append(actx, "template", uuid.NewString(), "template.published", map[string]any{"version": i, "note": "é ü"}); err != nil {
			t.Fatal(err)
		}
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := auditintegrity.NewSigner(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	svc := auditintegrity.NewService(postgres.NewAuditIntegrityRepository(db), signer)
	svc.SetLag(-time.Second)
	d, err := svc.Seal(ctx)
	if err != nil || d == nil || d.RecordCount < 3 {
		t.Fatalf("seal %+v %v", d, err)
	}
	if again, err := svc.Seal(ctx); err != nil || again != nil {
		t.Fatalf("second seal with nothing new: %+v %v", again, err)
	}
	rep, err := svc.Verify(ctx)
	if err != nil || !rep.Intact || rep.Records < 3 {
		t.Fatalf("verify %+v %v", rep, err)
	}
	if _, err := db.Exec(ctx, `UPDATE audit_events SET metadata = metadata || '{"version": 99}'
		WHERE seq = (SELECT max(seq) FROM audit_events WHERE tenant_uuid = $1)`, id); err != nil {
		t.Fatal(err)
	}
	rep, err = svc.Verify(ctx)
	if err != nil || rep.Intact || rep.Problems[len(rep.Problems)-1].Kind != "records_changed" {
		t.Fatalf("edited row not found: %+v %v", rep, err)
	}
	// Leave the shared database verifiable for the next run.
	if _, err := db.Exec(ctx, `DELETE FROM audit_digests`); err != nil {
		t.Fatal(err)
	}
}

// The retention sweep deletes a tenant's old inbound receipts and finished
// webhook deliveries, and keeps new ones and pending deliveries.
func TestDeliveryRecordsPurge(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	id := uuid.NewString()
	if err := tenant.NewService(postgres.NewTenantRepository(db), audit.NewWriter(nil, false), time.Minute).Ensure(ctx, id); err != nil {
		t.Fatal(err)
	}
	old, recent := time.Now().Add(-40*24*time.Hour), time.Now()
	for _, at := range []time.Time{old, recent} {
		if _, err := db.Exec(ctx, `INSERT INTO inbound_events (org_id, event_id, topic, client_id, transport, data_sha256, received_at)
			VALUES ($1, $2, 'iam.auth.mfa_email_code_requested', 'iam', 'http', repeat('a', 64), $3)`, id, uuid.NewString(), at); err != nil {
			t.Fatal(err)
		}
	}
	hook := uuid.NewString()
	if _, err := db.Exec(ctx, `INSERT INTO webhooks (id, org_id, url, secret) VALUES ($1, $2, 'https://hooks.example/x', 'sealed')`, hook, id); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct {
		status string
		at     time.Time
	}{{"delivered", old}, {"failed", old}, {"pending", old}, {"delivered", recent}} {
		if _, err := db.Exec(ctx, `INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, created_at)
			VALUES ($1, $2, 'message.sent', '{}', $3, $4)`, uuid.NewString(), hook, d.status, d.at); err != nil {
			t.Fatal(err)
		}
	}
	repo := postgres.NewMessageRepository(db)
	tenants, err := repo.PurgeTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tid := range tenants {
		found = found || tid == id
	}
	if !found {
		t.Fatal("a tenant with only delivery records is not swept")
	}
	n, err := repo.PurgeRecords(ctx, id, time.Now().Add(-30*24*time.Hour))
	if err != nil || n != 3 {
		t.Fatalf("purged %d %v, want 3", n, err)
	}
	var inbound, hooks int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM inbound_events WHERE org_id = $1`, id).Scan(&inbound)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM webhook_deliveries WHERE webhook_id = $1`, hook).Scan(&hooks)
	if inbound != 1 || hooks != 2 {
		t.Fatalf("left %d receipts and %d deliveries, want 1 and 2 (the recent and the pending)", inbound, hooks)
	}
}
