//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	domainsup "github.com/razatechofficial/mail-os/domain/suppression"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// An unsubscribe stops marketing only. A later hard bounce or complaint
// for the same address replaces it, so transactional mail stops too; an
// unsubscribe never weakens a bounce.
func TestSuppressionBounceReplacesUnsubscribe(t *testing.T) {
	e := newMsgEnv(t)
	ctx := context.Background()
	repo := postgres.NewSuppressionRepository(e.db)
	put := func(typ domainsup.Type) domainsup.Suppression {
		t.Helper()
		s, err := repo.Upsert(ctx, domainsup.Suppression{ID: uuid.NewString(), OrgID: e.tenant, Email: "gone@example.com",
			Type: typ, Source: domainsup.SourceSend, CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := put(domainsup.TypeUnsubscribe)
	if got := put(domainsup.TypeBounce); got.Type != domainsup.TypeBounce || got.ID != first.ID {
		t.Fatalf("bounce after unsubscribe: %+v", got)
	}
	if got := put(domainsup.TypeUnsubscribe); got.Type != domainsup.TypeBounce {
		t.Fatalf("unsubscribe replaced a bounce: %+v", got)
	}
	if got := put(domainsup.TypeComplaint); got.Type != domainsup.TypeBounce {
		t.Fatalf("a bounce is kept as the first stopping reason: %+v", got)
	}
}
