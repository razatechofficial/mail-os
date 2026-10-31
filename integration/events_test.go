//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/application/tenant"
	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/infrastructure/kafka"
	"github.com/razatechofficial/mail-os/infrastructure/msgsig"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/transport/pubsub"
)

// countingDispatcher stands in for the messaging use case.
type countingDispatcher struct {
	mu   sync.Mutex
	sent []inbound.Delivery
	fail error
}

func (d *countingDispatcher) Dispatch(_ context.Context, del inbound.Delivery) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		return "", d.fail
	}
	d.sent = append(d.sent, del)
	return uuid.NewString(), nil
}

func (d *countingDispatcher) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sent)
}

type eventsEnv struct {
	db     *postgres.Pool
	audit  *postgres.AuditRepository
	svc    *inbound.Service
	disp   *countingDispatcher
	grants access.ServiceGrants
	writer *audit.Writer
	tenant string
}

func newEventsEnv(t *testing.T) eventsEnv {
	t.Helper()
	db := connectPostgres(t)
	auditRepo := postgres.NewAuditRepository(db)
	w := audit.NewWriter(auditRepo, false)
	tenants := tenant.NewService(postgres.NewTenantRepository(db), w, time.Minute)
	grants := access.NewServiceGrants([]access.ServiceGrant{{ClientID: "iam", TopicPatterns: []string{"iam.*"}}})
	disp := &countingDispatcher{}
	svc := inbound.NewService(grants, tenants, postgres.NewInboundEventRepository(db), db, disp, w)
	return eventsEnv{db: db, audit: auditRepo, svc: svc, disp: disp, grants: grants, writer: w, tenant: uuid.NewString()}
}

func (e eventsEnv) serviceCtx() context.Context {
	return access.WithPrincipal(context.Background(), access.Principal{
		Kind: access.KindService, Subject: "client:iam", ClientID: "iam", TenantID: e.tenant})
}

func resetEvent(id, tenant string) event.Event {
	data, _ := json.Marshal(template.SampleData(template.TopicPasswordReset))
	return event.Event{ID: id, Type: template.TopicPasswordReset, Source: "iam", Data: data, TenantUUID: tenant}
}

func (e eventsEnv) actions(t *testing.T, action string) []audit.Event {
	t.Helper()
	events, _, err := e.audit.List(context.Background(), postgres.AuditFilter{TenantUUID: uuid.MustParse(e.tenant), Action: action, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// An event is recorded once per tenant and id: a redelivery is accepted
// without a second message, a failed dispatch records nothing, and an id
// reused for other data is a conflict. Acceptances are audited under the
// tenant, without the data.
func TestInboundEventsOnPostgres(t *testing.T) {
	e := newEventsEnv(t)
	ctx := e.serviceCtx()
	id := uuid.NewString()
	in := inbound.In{Transport: inbound.TransportHTTP, Event: resetEvent(id, e.tenant)}

	e.disp.fail = apperrors.Unavailable("smtp down")
	if _, err := e.svc.Dispatch(ctx, in); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("failed dispatch: %v", err)
	}
	e.disp.fail = nil

	first, err := e.svc.Dispatch(ctx, in)
	if err != nil || first.Duplicate || first.DeliveryID == "" {
		t.Fatalf("first: %+v %v (a failed dispatch left a record?)", first, err)
	}
	again, err := e.svc.Dispatch(ctx, in)
	if err != nil || !again.Duplicate || again.DeliveryID != first.DeliveryID {
		t.Fatalf("redelivery: %+v %v", again, err)
	}
	if e.disp.count() != 1 {
		t.Fatalf("dispatched %d times", e.disp.count())
	}
	other := resetEvent(id, e.tenant)
	other.Data = json.RawMessage(`{"email":"x@example.com","reset_link":"https://iam.example.com/r/2"}`)
	if _, err := e.svc.Dispatch(ctx, inbound.In{Transport: inbound.TransportHTTP, Event: other}); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("reused id: %v", err)
	}

	accepted := e.actions(t, inbound.AuditAccepted)
	if len(accepted) != 2 || accepted[0].ActorType != audit.ActorService || accepted[0].Metadata["client_id"] != "iam" {
		t.Fatalf("accepted audit %+v", accepted)
	}
	if _, ok := accepted[0].Metadata["data"]; ok {
		t.Fatal("the audit row carries the event data")
	}

	// A refusal is audited under the tenant the event named.
	foreign := resetEvent(uuid.NewString(), uuid.NewString())
	if _, err := e.svc.Dispatch(ctx, inbound.In{Transport: inbound.TransportHTTP, Event: foreign}); apperrors.KindOf(err) != apperrors.KindForbidden {
		t.Fatalf("foreign tenant: %v", err)
	}
	if refused := e.actions(t, inbound.AuditRefused); len(refused) != 1 || refused[0].Metadata["reason"] != "tenant_mismatch" {
		t.Fatalf("refused audit %+v", refused)
	}
}

// Concurrent deliveries of one event make one message.
func TestConcurrentDuplicateEventsDispatchOnce(t *testing.T) {
	e := newEventsEnv(t)
	in := inbound.In{Transport: inbound.TransportGRPC, Event: resetEvent(uuid.NewString(), e.tenant)}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Dispatch(e.serviceCtx(), in)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
	}
	if e.disp.count() != 1 {
		t.Fatalf("dispatched %d messages for one event", e.disp.count())
	}
}

// A signed IAM event on Kafka is verified with the Redis replay guard and
// recorded in Postgres; the same message published again is rejected as a
// replay and audited under the tenant as an Alert.
func TestSignedKafkaEventsOnTheStack(t *testing.T) {
	e := newEventsEnv(t)
	rdb := connectRedis(t)
	iam, _ := fakeiam.NewServer(t)
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, template.TopicPasswordReset))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cluster.Close)
	cfg := config.Kafka{Brokers: cluster.ListenAddrs(), GroupID: "mailos-events-" + uuid.NewString()}

	verifier, err := msgsig.NewVerifier(jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}), msgsig.NewStoreReplayGuard(rdb))
	if err != nil {
		t.Fatal(err)
	}
	handler := pubsub.NewHandler(verifier, e.grants, e.svc, e.writer)

	id := uuid.NewString()
	value, _ := json.Marshal(resetEvent(id, e.tenant))
	sum := sha256.Sum256(value)
	now := time.Now()
	sig := iam.Sign(iam.Keys[0], msgsig.Type, map[string]any{
		"iss": iam.Issuer, "sub": "iam", "aud": "mailos", "iat": now.Unix(), "exp": now.Add(msgsig.Lifetime).Unix(),
		"jti": id, "topic": template.TopicPasswordReset, "body_sha256": base64.RawURLEncoding.EncodeToString(sum[:]),
	})
	p, err := kafka.NewProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for range 2 {
		if err := p.Publish(context.Background(), template.TopicPasswordReset, id, value, map[string]string{msgsig.Header: sig}); err != nil {
			t.Fatal(err)
		}
	}

	c, err := kafka.NewConsumer(cfg, []string{template.TopicPasswordReset}, handler.Handle, kafka.WithBackoff(10*time.Millisecond, 50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Run(context.Background()) }()
	t.Cleanup(c.Close)

	deadline := time.Now().Add(30 * time.Second)
	for e.disp.count() < 1 || len(e.actions(t, event.AuditMessageRejected)) < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("dispatched %d, rejections %d", e.disp.count(), len(e.actions(t, event.AuditMessageRejected)))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e.disp.count() != 1 {
		t.Fatalf("dispatched %d", e.disp.count())
	}
	rej := e.actions(t, event.AuditMessageRejected)[0]
	if rej.Metadata["reason"] != string(event.ReasonReplay) || rej.Severity != audit.SeverityAlert || rej.Metadata["event_id"] != id {
		t.Fatalf("rejection %+v", rej)
	}
	if acc := e.actions(t, inbound.AuditAccepted); len(acc) != 1 || acc[0].Metadata["transport"] != inbound.TransportKafka {
		t.Fatalf("accepted %+v", acc)
	}
}
