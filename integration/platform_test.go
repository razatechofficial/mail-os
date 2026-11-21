//go:build integration

package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// The platform's tenant list counts each tenant's applications, live
// sending domains and the messages of the last 30 days, pages in
// (created_at, id) order, and skips deleted tenants.
func TestPlatformTenantAggregates(t *testing.T) {
	db := connectPostgres(t)
	ctx := context.Background()
	repo := postgres.NewPlatformRepository(db)
	// Far in the future, so these sort after every other test's tenants.
	base := time.Date(2990+time.Now().Nanosecond()%9, 1, 1, 0, 0, 0, 0, time.UTC)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for i, id := range ids {
		exec(`INSERT INTO organizations (id, name, slug, is_active, created_at, updated_at) VALUES ($1, $1, $1, $2, $3, $3)`,
			id, i != 1, base.Add(time.Duration(i)*time.Minute))
	}
	exec(`UPDATE organizations SET deleted_at = now() WHERE id = $1`, ids[3])
	exec(`INSERT INTO applications (id, org_id, name, kind, client_id) VALUES ($1, $2, 'a', 'server', $1), ($3, $2, 'b', 'spa', $3)`,
		uuid.NewString(), ids[0], uuid.NewString())
	exec(`INSERT INTO sending_domains (id, org_id, domain) VALUES ($1, $2, 'a.example'), ($3, $2, 'b.example')`, uuid.NewString(), ids[0], uuid.NewString())
	exec(`UPDATE sending_domains SET deleted_at = now() WHERE org_id = $1 AND domain = 'b.example'`, ids[0])
	msg := `INSERT INTO messages (id, org_id, from_name, from_email, to_email, subject, created_at) VALUES ($1, $2, 'f', 'f@x.example', 'to@y.example', 's', $3)`
	exec(msg, uuid.NewString(), ids[0], time.Now().Add(-time.Hour))
	exec(msg, uuid.NewString(), ids[0], time.Now().Add(-24*time.Hour))
	exec(msg, uuid.NewString(), ids[0], time.Now().Add(-40*24*time.Hour))
	exec(`INSERT INTO providers (id, org_id, name, type, is_active) VALUES ($1, $2, 'p', 'mailjet', true)`, uuid.NewString(), ids[0])

	since := time.Now().Add(-30 * 24 * time.Hour)
	page, err := repo.TenantAggregates(ctx, base.Add(-time.Nanosecond), "", 2, since)
	if err != nil || len(page) != 2 {
		t.Fatalf("first page: %+v %v", page, err)
	}
	a := page[0]
	if a.ID != ids[0] || !a.Active || a.Applications != 2 || a.Domains != 1 || a.Messages30d != 2 || !a.CreatedAt.Equal(base) {
		t.Fatalf("tenant 0: %+v", a)
	}
	if b := page[1]; b.ID != ids[1] || b.Active || b.Applications != 0 || b.Domains != 0 || b.Messages30d != 0 {
		t.Fatalf("tenant 1: %+v", b)
	}
	next, err := repo.TenantAggregates(ctx, page[1].CreatedAt, page[1].ID, 10, since)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range next {
		got = append(got, x.ID)
	}
	if !slices.Contains(got, ids[2]) || slices.Contains(got, ids[3]) || slices.Contains(got, ids[0]) {
		t.Fatalf("second page: %v (deleted %s)", got, ids[3])
	}
	kinds, err := repo.ProviderKindsInUse(ctx)
	if err != nil || !slices.Contains(kinds, "mailjet") {
		t.Fatalf("kinds in use: %v %v", kinds, err)
	}
}
