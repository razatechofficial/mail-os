package msgsig

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/domain/event"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

const (
	testClient = "iam-service"
	testTopic  = "iam.auth.password_reset_requested"
)

var testValue = []byte(`{"id":"e1","type":"iam.auth.password_reset_requested","source":"iam","data":{"email":"a@example.com"}}`)

// memStore is an in-memory Claimer: SET NX with a TTL, and an outage switch.
type memStore struct {
	mu   sync.Mutex
	keys map[string]time.Duration
	down bool
}

func newMemStore() *memStore { return &memStore{keys: map[string]time.Duration{}} }

func (m *memStore) ClaimOnce(_ context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return false, errors.New("connection refused")
	}
	if _, ok := m.keys[key]; ok {
		return false, nil
	}
	m.keys[key] = ttl
	return true, nil
}

func (m *memStore) ttl(key string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[key]
}

type fixture struct {
	iam      *fakeiam.IAM
	verifier *Verifier
	store    *memStore
	// offset moves the verifier's clock.
	offset time.Duration
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	iam, srv := fakeiam.NewServer(t)
	f.iam = iam
	f.store = newMemStore()
	keys := jwt.NewVerifier(jwt.Config{
		Issuer:   srv.URL,
		Audience: "mailos",
		Now:      func() time.Time { return time.Now().Add(f.offset) },
	})
	v, err := NewVerifier(keys, NewStoreReplayGuard(f.store))
	if err != nil {
		t.Fatal(err)
	}
	f.verifier = v
	return f
}

// claims are the claims IAM signs for testValue on testTopic.
func (f *fixture) claims() map[string]any {
	now := time.Now()
	sum := sha256.Sum256(testValue)
	return map[string]any{
		"iss": f.iam.Issuer, "aud": "mailos", "sub": testClient,
		"iat": now.Unix(), "exp": now.Add(Lifetime).Unix(), "jti": uuid.NewString(),
		"topic": testTopic, "body_sha256": base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

func (f *fixture) sign(mutate func(map[string]any)) string {
	c := f.claims()
	if mutate != nil {
		mutate(c)
	}
	return f.iam.Sign(f.iam.Keys[0], Type, c)
}

func wantReason(t *testing.T, err error, want event.Reason) {
	t.Helper()
	got, ok := event.ReasonOf(err)
	if !ok || got != want {
		t.Fatalf("err = %v, want rejection %q", err, want)
	}
	if IsUnavailable(err) {
		t.Fatalf("a rejection is also reported transient: %v", err)
	}
	if strings.Contains(err.Error(), "a@example.com") {
		t.Fatalf("the rejection quotes the body: %v", err)
	}
}

func TestVerifyAcceptsIAMSignature(t *testing.T) {
	f := newFixture(t)
	header := f.iam.MessageSignature(testClient, testTopic, testValue)
	c, err := f.verifier.Verify(context.Background(), header, testTopic, testValue)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.ClientID != testClient || c.Topic != testTopic || c.Issuer != f.iam.Issuer || c.JTI == "" {
		t.Fatalf("claims = %+v", c)
	}
	if got := c.ExpiresAt.Sub(c.IssuedAt); got != Lifetime {
		t.Fatalf("lifetime = %s", got)
	}
}

func TestVerifyAcceptsEveryPublishedKey(t *testing.T) {
	f := newFixture(t)
	header := f.iam.Sign(f.iam.Keys[1], Type, f.claims()) // ES256
	if _, err := f.verifier.Verify(context.Background(), header, testTopic, testValue); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		header func() string
		topic  string
		value  []byte
		want   event.Reason
	}{
		{"missing", func() string { return "" }, testTopic, testValue, event.ReasonMalformed},
		{"not a JWS", func() string { return "not-a-jws" }, testTopic, testValue, event.ReasonMalformed},
		{"JWS JSON serialisation", func() string { return `{"payload":"e30","signatures":[]}` }, testTopic, testValue, event.ReasonMalformed},
		{"unpublished key", func() string { return f.iam.Sign(f.iam.Unpublished, Type, f.claims()) }, testTopic, testValue, event.ReasonUnknownKey},
		{"wrong typ", func() string { return f.iam.Sign(f.iam.Keys[0], "JWT", f.claims()) }, testTopic, testValue, event.ReasonType},
		{"access token", func() string { return f.iam.ServiceToken(testClient, "") }, testTopic, testValue, event.ReasonType},
		{"forged signature", func() string {
			h := f.sign(nil)
			other := f.sign(func(c map[string]any) { c["topic"] = "iam.auth.login" })
			return h[:strings.LastIndex(h, ".")] + other[strings.LastIndex(other, "."):]
		}, testTopic, testValue, event.ReasonSignature},
		{"wrong issuer", func() string { return f.sign(func(c map[string]any) { c["iss"] = "https://evil.example" }) }, testTopic, testValue, event.ReasonIssuer},
		{"wrong audience", func() string { return f.sign(func(c map[string]any) { c["aud"] = "other" }) }, testTopic, testValue, event.ReasonAudience},
		{"one-element audience array", func() string { return f.sign(func(c map[string]any) { c["aud"] = []string{"other"} }) }, testTopic, testValue, event.ReasonAudience},
		{"two audiences", func() string { return f.sign(func(c map[string]any) { c["aud"] = []string{"mailos", "other"} }) }, testTopic, testValue, event.ReasonMalformed},
		{"string iat", func() string { return f.sign(func(c map[string]any) { c["iat"] = "now" }) }, testTopic, testValue, event.ReasonMalformed},
		{"no exp", func() string { return f.sign(func(c map[string]any) { delete(c, "exp") }) }, testTopic, testValue, event.ReasonMalformed},
		{"lifetime over five minutes", func() string {
			return f.sign(func(c map[string]any) { c["exp"] = time.Now().Add(time.Hour).Unix() })
		}, testTopic, testValue, event.ReasonLifetime},
		{"expired beyond skew", func() string {
			iat := time.Now().Add(-Lifetime - 2*time.Minute)
			return f.sign(func(c map[string]any) { c["iat"], c["exp"] = iat.Unix(), iat.Add(Lifetime).Unix() })
		}, testTopic, testValue, event.ReasonExpired},
		{"issued in the future beyond skew", func() string {
			iat := time.Now().Add(2 * time.Minute)
			return f.sign(func(c map[string]any) { c["iat"], c["exp"] = iat.Unix(), iat.Add(Lifetime).Unix() })
		}, testTopic, testValue, event.ReasonNotYetValid},
		{"topic mismatch", func() string { return f.sign(nil) }, "iam.auth.login", testValue, event.ReasonTopic},
		{"no topic claim", func() string { return f.sign(func(c map[string]any) { delete(c, "topic") }) }, testTopic, testValue, event.ReasonMalformed},
		{"body tampered", func() string { return f.sign(nil) }, testTopic, []byte(strings.Replace(string(testValue), "a@example.com", "b@example.com", 1)), event.ReasonBodyHash},
		{"body hash missing", func() string { return f.sign(func(c map[string]any) { delete(c, "body_sha256") }) }, testTopic, testValue, event.ReasonMalformed},
		{"no sub", func() string { return f.sign(func(c map[string]any) { delete(c, "sub") }) }, testTopic, testValue, event.ReasonMalformed},
		{"no jti", func() string { return f.sign(func(c map[string]any) { delete(c, "jti") }) }, testTopic, testValue, event.ReasonMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.verifier.Verify(context.Background(), tc.header(), tc.topic, tc.value)
			wantReason(t, err, tc.want)
		})
	}
}

func TestVerifyAllowsClockSkew(t *testing.T) {
	f := newFixture(t)
	header := f.iam.MessageSignature(testClient, testTopic, testValue)
	f.offset = Lifetime + 30*time.Second // past exp, within the 60 s skew
	if _, err := f.verifier.Verify(context.Background(), header, testTopic, testValue); err != nil {
		t.Fatalf("within skew: %v", err)
	}

	header = f.iam.MessageSignature(testClient, testTopic, testValue)
	f.offset = Lifetime + time.Minute // exactly exp + skew
	_, err := f.verifier.Verify(context.Background(), header, testTopic, testValue)
	wantReason(t, err, event.ReasonExpired)

	header = f.sign(func(c map[string]any) {
		iat := time.Now().Add(30 * time.Second)
		c["iat"], c["exp"] = iat.Unix(), iat.Add(Lifetime).Unix()
	})
	f.offset = 0
	if _, err := f.verifier.Verify(context.Background(), header, testTopic, testValue); err != nil {
		t.Fatalf("iat ahead within skew: %v", err)
	}
}

func TestVerifyRejectsReplayedJTI(t *testing.T) {
	f := newFixture(t)
	header := f.iam.MessageSignature(testClient, testTopic, testValue)
	ctx := context.Background()
	c, err := f.verifier.Verify(ctx, header, testTopic, testValue)
	if err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err = f.verifier.Verify(ctx, header, testTopic, testValue)
	wantReason(t, err, event.ReasonReplay)

	// The record lives until exp + skew.
	ttl := f.store.ttl(ReplayKeyPrefix + c.JTI)
	if want := time.Until(c.ExpiresAt.Add(time.Minute)); ttl <= 0 || ttl > want+time.Second {
		t.Fatalf("replay record TTL = %s, want about %s", ttl, want)
	}
}

func TestVerifyAllowsRedeliveryOfTheSameRecord(t *testing.T) {
	f := newFixture(t)
	header := f.iam.MessageSignature(testClient, testTopic, testValue)
	ctx := context.Background()
	first := Delivery(testTopic + "/0/41")
	if _, err := f.verifier.Verify(ctx, header, testTopic, testValue, first); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if _, err := f.verifier.Verify(ctx, header, testTopic, testValue, first); err != nil {
		t.Fatalf("redelivery of the same record: %v", err)
	}
	_, err := f.verifier.Verify(ctx, header, testTopic, testValue, Delivery(testTopic+"/0/42"))
	wantReason(t, err, event.ReasonReplay)
	_, err = f.verifier.Verify(ctx, header, testTopic, testValue)
	wantReason(t, err, event.ReasonReplay)
}

func TestVerifyJWKSDownIsTransient(t *testing.T) {
	iam, srv := fakeiam.NewServer(t)
	header := iam.MessageSignature(testClient, testTopic, testValue)
	srv.Close()
	keys := jwt.NewVerifier(jwt.Config{Issuer: srv.URL, Audience: "mailos"})
	v, err := NewVerifier(keys, NewStoreReplayGuard(newMemStore()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), header, testTopic, testValue)
	if !IsUnavailable(err) || !errors.Is(err, jwt.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if _, ok := event.ReasonOf(err); ok {
		t.Fatalf("an unreachable JWKS is reported as a rejection: %v", err)
	}
}

func TestVerifyReplayStoreDownIsTransient(t *testing.T) {
	f := newFixture(t)
	f.store.down = true
	header := f.iam.MessageSignature(testClient, testTopic, testValue)
	_, err := f.verifier.Verify(context.Background(), header, testTopic, testValue)
	if !IsUnavailable(err) {
		t.Fatalf("err = %v, want ErrUnavailable (fail closed)", err)
	}
	// IAM names it a rejection; it is transient so the message is retried.
	var r *event.Rejection
	if !errors.As(err, &r) || r.Reason != event.ReasonReplayGuardUnavailable || r.Permanent() {
		t.Fatalf("err = %v, want a transient replay_guard_unavailable rejection", err)
	}
}

func TestNewVerifierRequiresDependencies(t *testing.T) {
	if _, err := NewVerifier(nil, NewStoreReplayGuard(nil)); err == nil {
		t.Fatal("NewVerifier accepted no key verifier")
	}
	if _, err := NewVerifier(jwt.NewVerifier(jwt.Config{Issuer: "https://iam.example"}), nil); err == nil {
		t.Fatal("NewVerifier accepted no replay guard")
	}
	if _, err := NewStoreReplayGuard(nil).Use(context.Background(), "j", "", time.Now()); err == nil {
		t.Fatal("a guard without a store did not fail closed")
	}
}

func TestReplayGuardRedeliveryAfterCrashBetweenClaims(t *testing.T) {
	store := newMemStore()
	g := NewStoreReplayGuard(store)
	ctx := context.Background()
	exp := time.Now().Add(Lifetime)
	// The delivery was claimed, then the process stopped before the jti was.
	if _, err := store.ClaimOnce(ctx, ReplayKeyPrefix+"j1@t/0/7", time.Minute); err != nil {
		t.Fatal(err)
	}
	if replayed, err := g.Use(ctx, "j1", "t/0/7", exp); err != nil || replayed {
		t.Fatalf("redelivery = %v, %v; want accepted", replayed, err)
	}
	if replayed, err := g.Use(ctx, "j1", "t/0/8", exp); err != nil || !replayed {
		t.Fatalf("copy at another offset = %v, %v; want replayed", replayed, err)
	}
}
