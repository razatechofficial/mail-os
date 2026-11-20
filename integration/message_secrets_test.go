//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// storeMessage inserts a bare queued message of the tenant.
func storeMessage(t *testing.T, e msgEnv) string {
	t.Helper()
	now := time.Now().UTC()
	m := domainmsg.Message{ID: uuid.NewString(), OrgID: e.tenant, FromEmail: "noreply@bank.example", ToEmail: "s@example.com",
		Subject: "s", TextBody: "t", Type: domainmsg.TypeTransactional, Status: domainmsg.StatusQueued,
		Priority: domainmsg.PriorityNormal, CreatedAt: now, UpdatedAt: now}
	if err := postgres.NewMessageRepository(e.db).Create(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	return m.ID
}

// The live secrets of a message are sealed at rest (km1 ciphertext of the
// message_secret purpose), readable until they expire, deleted with the
// message or on demand, swept when expired, and counted for key rotation.
func TestMessageSecretsSealed(t *testing.T) {
	e := newMsgEnv(t)
	ctx := context.Background()
	repo := postgres.NewMessageSecretRepository(e.db)
	cipher := e.keys.Cipher(domainkm.PurposeMessageSecret)
	now := time.Now().UTC().Truncate(time.Microsecond)

	id := storeMessage(t, e)
	sealed, err := cipher.Seal(ctx, []byte(`{"code":"731904"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.InTx(ctx, func(ctx context.Context) error {
		return repo.Put(ctx, e.tenant, id, sealed, now, now.Add(30*time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	if v := e.raw(t, `SELECT sealed FROM message_secrets WHERE message_id = $1`, id); !domainkm.IsCiphertext(v) || strings.Contains(v, "731904") {
		t.Fatalf("at rest %q", v)
	}
	got, ok, err := repo.Get(ctx, e.tenant, id, now)
	if err != nil || !ok {
		t.Fatalf("get %v %v", ok, err)
	}
	if plain, err := cipher.Open(ctx, got); err != nil || string(plain) != `{"code":"731904"}` {
		t.Fatalf("open %q %v", plain, err)
	}
	if _, ok, _ := repo.Get(ctx, uuid.NewString(), id, now); ok {
		t.Fatal("another tenant read the secrets")
	}
	if _, ok, _ := repo.Get(ctx, e.tenant, id, now.Add(31*time.Minute)); ok {
		t.Fatal("expired secrets returned")
	}
	if n, err := repo.SealedColumn().CountByKID(ctx, strings.Split(got, ".")[1]); err != nil || n < 1 {
		t.Fatalf("sealed column count %d %v", n, err)
	}
	// More than an hour is refused by the table itself.
	other := storeMessage(t, e)
	if err := repo.Put(ctx, e.tenant, other, sealed, now, now.Add(61*time.Minute)); err == nil {
		t.Fatal("a secret kept longer than an hour was stored")
	}

	if err := repo.Delete(ctx, e.tenant, id); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := repo.Get(ctx, e.tenant, id, now); ok {
		t.Fatal("deleted secrets returned")
	}

	expired := storeMessage(t, e)
	live := storeMessage(t, e)
	if err := repo.Put(ctx, e.tenant, expired, sealed, now.Add(-2*time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Put(ctx, e.tenant, live, sealed, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.DeleteExpired(ctx, now); err != nil || n < 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	if v := e.raw(t, `SELECT count(*)::text FROM message_secrets WHERE message_id = $1`, expired); v != "0" {
		t.Fatal("expired row kept")
	}
	if _, ok, _ := repo.Get(ctx, e.tenant, live, now); !ok {
		t.Fatal("live row swept")
	}
	// Deleting the message deletes its secrets.
	mustExec(t, e, `DELETE FROM messages WHERE id = $1`, live)
	if v := e.raw(t, `SELECT count(*)::text FROM message_secrets WHERE message_id = $1`, live); v != "0" {
		t.Fatal("secrets outlived their message")
	}
}
