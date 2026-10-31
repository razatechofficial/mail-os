package pubsub

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/infrastructure/kafka"
	"github.com/razatechofficial/mail-os/infrastructure/msgsig"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

const tenant = "8d3b1f7a-2c4e-4f6a-9b1d-3e5f7a9c1b2d"

// claimStore is an in-memory Redis SET NX.
type claimStore struct {
	mu   sync.Mutex
	keys map[string]bool
}

func (c *claimStore) ClaimOnce(_ context.Context, key string, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys[key] {
		return false, nil
	}
	c.keys[key] = true
	return true, nil
}

type records struct {
	mu   sync.Mutex
	rows map[string]inbound.Record
}

func (s *records) Claim(_ context.Context, r inbound.Record) (inbound.Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.rows[r.TenantID+r.EventID]; ok {
		return p, false, nil
	}
	s.rows[r.TenantID+r.EventID] = r
	return inbound.Record{}, true, nil
}

func (s *records) Complete(context.Context, string, string, string) error { return nil }

type tx struct{}

func (tx) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

type tenants struct{}

func (tenants) Ensure(context.Context, string) error { return nil }

type dispatcher struct {
	mu   sync.Mutex
	sent []inbound.Delivery
}

func (d *dispatcher) Dispatch(_ context.Context, del inbound.Delivery) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, del)
	return "msg-" + del.EventID, nil
}

func (d *dispatcher) eventIDs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, s := range d.sent {
		out = append(out, s.EventID)
	}
	return out
}

type entry struct {
	action string
	tenant string
	meta   map[string]any
}

type auditLog struct {
	mu      sync.Mutex
	entries []entry
}

func (a *auditLog) Append(ctx context.Context, _, _, action string, meta map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, _ := access.FromContext(ctx)
	a.entries = append(a.entries, entry{action: action, tenant: p.TenantID, meta: meta})
	return nil
}

func (a *auditLog) rejections() map[string]entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]entry{}
	for _, e := range a.entries {
		if e.action == event.AuditMessageRejected {
			out[e.meta["reason"].(string)] = e
		}
	}
	return out
}

type stack struct {
	iam   *fakeiam.IAM
	cfg   config.Kafka
	h     *Handler
	disp  *dispatcher
	audit *auditLog
}

const (
	resetTopic = template.TopicPasswordReset
	magicTopic = template.TopicMagicLink
)

func newStack(t *testing.T) *stack {
	t.Helper()
	iam, _ := fakeiam.NewServer(t)
	c, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, resetTopic, magicTopic))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	verifier, err := msgsig.NewVerifier(jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}),
		msgsig.NewStoreReplayGuard(&claimStore{keys: map[string]bool{}}))
	if err != nil {
		t.Fatal(err)
	}
	apps := appstest.New(appstest.Server("iam", tenant, "iam.*"))
	disp, log := &dispatcher{}, &auditLog{}
	svc := inbound.NewService(apps, tenants{}, &records{rows: map[string]inbound.Record{}}, tx{}, disp, log)
	return &stack{iam: iam, cfg: config.Kafka{Brokers: c.ListenAddrs(), GroupID: "mailos-events"},
		h: NewHandler(verifier, svc, log), disp: disp, audit: log}
}

// value is an IAM event on topic, as IAM's SignedPublisher marshals it; the
// same arguments give the same bytes.
func value(id, topic string) []byte {
	b, _ := json.Marshal(event.Event{ID: id, Type: topic, Source: "iam", Timestamp: time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC), TenantUUID: tenant,
		Data: json.RawMessage(`{"email":"amna@example.com","reset_link":"https://iam.example.com/reset/x","link":"https://iam.example.com/m/x"}`)})
	return b
}

// sign is IAM's iam-msg-sig: jti is the event id.
func (s *stack) sign(key fakeiam.Key, client, topic, jti string, v []byte) string {
	sum := sha256.Sum256(v)
	now := time.Now()
	return s.iam.Sign(key, msgsig.Type, map[string]any{
		"iss": s.iam.Issuer, "sub": client, "aud": "mailos", "iat": now.Unix(), "exp": now.Add(msgsig.Lifetime).Unix(),
		"jti": jti, "topic": topic, "body_sha256": base64.RawURLEncoding.EncodeToString(sum[:]),
	})
}

func (s *stack) publish(t *testing.T, topic, key string, v []byte, sig string) {
	t.Helper()
	p, err := kafka.NewProducer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	headers := map[string]string{"event_type": topic, "source": "iam"}
	if sig != "" {
		headers[msgsig.Header] = sig
	}
	if err := p.Publish(context.Background(), topic, key, v, headers); err != nil {
		t.Fatal(err)
	}
}

func (s *stack) consume(t *testing.T) *kafka.Consumer {
	t.Helper()
	c, err := kafka.NewConsumer(s.cfg, []string{resetTopic, magicTopic}, s.h.Handle, kafka.WithBackoff(5*time.Millisecond, 20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Run(context.Background()) }()
	t.Cleanup(c.Close)
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSignedEventsEndToEnd(t *testing.T) {
	s := newStack(t)
	good := uuid.NewString()
	goodValue := value(good, resetTopic)
	goodSig := s.sign(s.iam.Keys[0], "iam", resetTopic, good, goodValue)
	s.publish(t, resetTopic, good, goodValue, goodSig)

	forged := uuid.NewString()
	s.publish(t, resetTopic, forged, value(forged, resetTopic), s.sign(s.iam.Unpublished, "iam", resetTopic, forged, value(forged, resetTopic)))
	s.publish(t, resetTopic, good, goodValue, goodSig) // the same message again: a replay

	moved := uuid.NewString()
	movedValue := value(moved, resetTopic)
	s.publish(t, magicTopic, moved, movedValue, s.sign(s.iam.Keys[0], "iam", resetTopic, moved, movedValue))

	crm := uuid.NewString()
	s.publish(t, resetTopic, crm, value(crm, resetTopic), s.sign(s.iam.Keys[0], "crm", resetTopic, crm, value(crm, resetTopic)))

	tampered := uuid.NewString()
	s.publish(t, resetTopic, tampered, value(tampered, magicTopic), s.sign(s.iam.Keys[0], "iam", resetTopic, tampered, value(tampered, resetTopic)))

	unsigned := uuid.NewString()
	s.publish(t, resetTopic, unsigned, value(unsigned, resetTopic), "")

	second := uuid.NewString()
	s.publish(t, magicTopic, second, value(second, magicTopic), s.sign(s.iam.Keys[1], "iam", magicTopic, second, value(second, magicTopic)))

	c := s.consume(t)
	want := []string{"unknown_key", "replay", "topic", "unknown_client", "body_hash", "malformed"}
	waitFor(t, "every record", func() bool { return len(s.disp.eventIDs()) == 2 && len(s.audit.rejections()) == len(want) })

	ids := s.disp.eventIDs()
	if !slices.Contains(ids, good) || !slices.Contains(ids, second) {
		t.Fatalf("dispatched %v", ids)
	}
	rej := s.audit.rejections()
	for _, reason := range want {
		e, ok := rej[reason]
		if !ok {
			t.Fatalf("no %s rejection audited: %+v", reason, rej)
		}
		for _, k := range []string{"topic", "partition", "offset"} {
			if _, ok := e.meta[k]; !ok {
				t.Errorf("%s rejection has no %s", reason, k)
			}
		}
		if _, ok := e.meta["data"]; ok {
			t.Errorf("%s rejection carries the body", reason)
		}
	}
	if e := rej["unknown_client"]; e.meta["client_id"] != "crm" || e.tenant != tenant || e.meta["event_id"] != crm {
		t.Fatalf("unknown client rejection %+v", e)
	}
	if e := rej["unknown_key"]; e.meta["client_id"] != nil || e.tenant != "" {
		t.Fatalf("an unverified message was attributed: %+v", e)
	}

	// Every record was committed: a new member starts after them.
	c.Close()
	last := uuid.NewString()
	s.publish(t, resetTopic, last, value(last, resetTopic), s.sign(s.iam.Keys[0], "iam", resetTopic, last, value(last, resetTopic)))
	s.consume(t)
	waitFor(t, "the next record", func() bool { return len(s.disp.eventIDs()) == 3 })
	if got := s.disp.eventIDs(); got[2] != last || len(s.audit.rejections()) != len(want) {
		t.Fatalf("after restart dispatched %v, rejections %v", got, s.audit.rejections())
	}
}

// A transient replay-guard outage is audited once and the record retried
// until the guard answers; the message is then accepted.
func TestReplayGuardOutageRetriesAndAuditsOnce(t *testing.T) {
	s := newStack(t)
	guard := &flakyClaims{claimStore: claimStore{keys: map[string]bool{}}, fail: 3}
	verifier, _ := msgsig.NewVerifier(jwt.NewVerifier(jwt.Config{Issuer: s.iam.Issuer, Audience: "mailos"}), msgsig.NewStoreReplayGuard(guard))
	s.h.verifier = verifier
	id := uuid.NewString()
	v := value(id, resetTopic)
	s.publish(t, resetTopic, id, v, s.sign(s.iam.Keys[0], "iam", resetTopic, id, v))
	s.consume(t)
	waitFor(t, "the event", func() bool { return len(s.disp.eventIDs()) == 1 })
	rej := 0
	s.audit.mu.Lock()
	for _, e := range s.audit.entries {
		if e.action == event.AuditMessageRejected {
			rej++
			if e.meta["reason"] != string(event.ReasonReplayGuardUnavailable) || e.tenant != "" && e.tenant != tenant {
				t.Errorf("rejection %+v", e)
			}
		}
	}
	s.audit.mu.Unlock()
	if rej != 1 {
		t.Fatalf("audited %d replay_guard_unavailable rejections, want 1", rej)
	}
}

type flakyClaims struct {
	claimStore
	mu   sync.Mutex
	fail int
}

func (f *flakyClaims) ClaimOnce(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	if f.fail > 0 {
		f.fail--
		f.mu.Unlock()
		return false, context.DeadlineExceeded
	}
	f.mu.Unlock()
	return f.claimStore.ClaimOnce(ctx, key, ttl)
}

// The envelope must match its signature: the event type is the record's
// topic and the event id is the jti. Invalid data is malformed. Each is a
// permanent, audited rejection.
func TestHandleChecksTheEnvelope(t *testing.T) {
	s := newStack(t)
	record := func(offset int64, v []byte, sig string) kafka.Record {
		return kafka.Record{Topic: resetTopic, Value: v, Offset: offset, Headers: map[string][]byte{msgsig.Header: []byte(sig)}}
	}
	other := uuid.NewString()
	otherType := value(other, magicTopic)
	jti := uuid.NewString()
	jtiValue := value(jti, resetTopic)
	bad := uuid.NewString()
	badData, _ := json.Marshal(event.Event{ID: bad, Type: resetTopic, TenantUUID: tenant, Data: json.RawMessage(`{"email":"amna@example.com"}`)})
	for name, tc := range map[string]struct {
		rec  kafka.Record
		want event.Reason
	}{
		"type is not the topic": {record(1, otherType, s.sign(s.iam.Keys[0], "iam", resetTopic, other, otherType)), event.ReasonTopic},
		"jti is not the id":     {record(2, jtiValue, s.sign(s.iam.Keys[0], "iam", resetTopic, "another", jtiValue)), event.ReasonMalformed},
		"data invalid":          {record(3, badData, s.sign(s.iam.Keys[0], "iam", resetTopic, bad, badData)), event.ReasonMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			err := s.h.Handle(context.Background(), tc.rec)
			if got, ok := event.ReasonOf(err); !ok || got != tc.want || !kafka.IsPermanent(err) {
				t.Fatalf("err = %v, want permanent %s", err, tc.want)
			}
		})
	}
	if len(s.disp.eventIDs()) != 0 || len(s.audit.rejections()) != 2 {
		t.Fatalf("dispatched %v, rejections %v", s.disp.eventIDs(), s.audit.rejections())
	}
}
