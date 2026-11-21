package acs_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/infrastructure/acs"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeacs"
)

var platform = acs.Object{Type: "mailos/platform", ID: "global"}

const alice = "0d6f3a7e-5b1c-4c55-9f61-2f8f1c9b6a11"

func newClient(t *testing.T) (*fakeacs.ACS, *acs.Client) {
	t.Helper()
	f, conn := fakeacs.Dial(t)
	return f, acs.New(conn, time.Second)
}

// A write with an expiry grants until the expiry and no longer; a delete
// takes it away; every call is in the platform scope.
func TestWriteCheckExpiryAndDelete(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	now := time.Now()
	f.Now = func() time.Time { return now }
	if err := c.Write(ctx, acs.PlatformTenant, []acs.Update{
		acs.Touch(platform, "eligible_platform_auditor", acs.User(alice), time.Time{}),
		acs.Touch(platform, "platform_auditor", acs.User(alice), now.Add(time.Hour)),
	}, "k1"); err != nil {
		t.Fatal(err)
	}
	ok, err := c.Check(ctx, acs.PlatformTenant, platform, "view_audit", acs.User(alice))
	if err != nil || !ok {
		t.Fatalf("active auditor: %v %v", ok, err)
	}
	if ok, _ := c.Check(ctx, acs.PlatformTenant, platform, "manage_keys", acs.User(alice)); ok {
		t.Fatal("auditor can manage keys")
	}
	got, err := c.CheckEach(ctx, acs.PlatformTenant, platform, []string{"view_overview", "manage_keys", "view_tenants"}, acs.User(alice))
	if err != nil || !slices.Equal(got, []bool{true, false, true}) {
		t.Fatalf("bulk: %v %v", got, err)
	}
	rels, err := c.Read(ctx, acs.PlatformTenant, acs.Filter{ResourceType: platform.Type, ResourceID: platform.ID, Subject: acs.User(alice)})
	if err != nil || len(rels) != 2 {
		t.Fatalf("read: %+v %v", rels, err)
	}
	for _, r := range rels {
		if r.Relation == "platform_auditor" && !r.ExpiresAt.Equal(now.Add(time.Hour).Truncate(time.Nanosecond)) {
			t.Fatalf("expiry read back as %s", r.ExpiresAt)
		}
		if r.Relation == "eligible_platform_auditor" && !r.ExpiresAt.IsZero() {
			t.Fatalf("eligibility expires: %+v", r)
		}
	}

	now = now.Add(time.Hour + time.Second)
	if ok, _ := c.Check(ctx, acs.PlatformTenant, platform, "view_audit", acs.User(alice)); ok {
		t.Fatal("an expired activation still grants")
	}
	now = now.Add(-2 * time.Second)
	if err := c.Write(ctx, acs.PlatformTenant, []acs.Update{acs.Delete(platform, "platform_auditor", acs.User(alice))}, ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Check(ctx, acs.PlatformTenant, platform, "view_audit", acs.User(alice)); ok {
		t.Fatal("a deleted activation still grants")
	}
	for _, call := range f.Calls() {
		if call[len(call)-len(" platform"):] != " platform" {
			t.Errorf("call %q is not in the platform scope", call)
		}
	}
}

// ACS's refusals come back as RefusedError with ACS's reason; an ACS that
// does not answer is ErrUnavailable.
func TestErrors(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	_, err := c.Check(ctx, "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10", platform, "view_overview", acs.User(alice))
	if acs.Reason(err) != "TENANT_NOT_BOUND" || errors.Is(err, acs.ErrUnavailable) {
		t.Fatalf("tenant scope: %v", err)
	}
	err = c.Write(ctx, acs.PlatformTenant, []acs.Update{acs.Touch(platform, "platform_owner", acs.User(alice), time.Time{})}, "")
	if acs.Reason(err) != "EXPIRY_REQUIRED" {
		t.Fatalf("activation without expiry: %v", err)
	}
	err = c.Write(ctx, acs.PlatformTenant, []acs.Update{acs.Touch(platform, "platform_owner", acs.User(alice), time.Now().Add(9*time.Hour))}, "")
	if acs.Reason(err) != "EXPIRY_OUT_OF_RANGE" {
		t.Fatalf("activation past the horizon: %v", err)
	}
	err = c.Write(ctx, acs.PlatformTenant, []acs.Update{acs.Touch(platform, "eligible_platform_owner", acs.Subject{Type: "service_account", ID: "s"}, time.Time{})}, "")
	if acs.Reason(err) != "SUBJECT_NOT_PLATFORM" {
		t.Fatalf("service account subject: %v", err)
	}
	f.SetUnavailable(true)
	if _, err := c.Check(ctx, acs.PlatformTenant, platform, "view_overview", acs.User(alice)); !errors.Is(err, acs.ErrUnavailable) || acs.Reason(err) != "" {
		t.Fatalf("down: %v", err)
	}
	if _, err := c.CheckEach(ctx, acs.PlatformTenant, platform, []string{"view_overview"}, acs.User(alice)); !errors.Is(err, acs.ErrUnavailable) {
		t.Fatalf("down, bulk: %v", err)
	}
	if err := c.Write(ctx, acs.PlatformTenant, []acs.Update{acs.Delete(platform, "platform_owner", acs.User(alice))}, ""); !errors.Is(err, acs.ErrUnavailable) {
		t.Fatalf("down, write: %v", err)
	}
}

// A call that outlasts the timeout is ErrUnavailable, not a hang.
func TestUnreachable(t *testing.T) {
	c, err := acs.Dial(acs.Config{Endpoint: "127.0.0.1:1", TokenURL: "http://127.0.0.1:1/token", ClientID: "mailos", Insecure: true, Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Check(context.Background(), acs.PlatformTenant, platform, "view_overview", acs.User(alice)); !errors.Is(err, acs.ErrUnavailable) {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestDialNeedsCredentials(t *testing.T) {
	for _, cfg := range []acs.Config{
		{TokenURL: "https://iam/token", ClientID: "mailos"},
		{Endpoint: "acs:9090", ClientID: "mailos"},
		{Endpoint: "acs:9090", TokenURL: "https://iam/token"},
		{Endpoint: "acs:9090", TokenURL: "https://iam/token", ClientID: "mailos"}, // TLS without a certificate
	} {
		if _, err := acs.Dial(cfg); err == nil {
			t.Errorf("%+v dialled", cfg)
		}
	}
}

// The token source asks for client credentials for api://acs, caches the
// token until shortly before it expires, and sends it as a bearer.
func TestTokenSource(t *testing.T) {
	var fetched atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "mailos" || r.PostForm.Get("resource") != acs.Resource {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
			return
		}
		n := fetched.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t" + string(rune('0'+n)), "expires_in": 120})
	}))
	defer srv.Close()
	now := time.Now()
	ts := &acs.TokenSource{URL: srv.URL, ClientID: "mailos", Insecure: true, Now: func() time.Time { return now }}
	md, err := ts.GetRequestMetadata(context.Background())
	if err != nil || md["authorization"] != "Bearer t1" {
		t.Fatalf("%v %v", md, err)
	}
	if tok, _ := ts.Token(context.Background()); tok != "t1" || fetched.Load() != 1 {
		t.Fatal("token not cached")
	}
	now = now.Add(100 * time.Second)
	if tok, _ := ts.Token(context.Background()); tok != "t2" {
		t.Fatalf("token not refreshed before expiry: %s", tok)
	}
	if ts.RequireTransportSecurity() {
		t.Fatal("insecure source requires TLS")
	}
	bad := &acs.TokenSource{URL: srv.URL, ClientID: "other"}
	if _, err := bad.Token(context.Background()); !errors.Is(err, acs.ErrUnavailable) || !bad.RequireTransportSecurity() {
		t.Fatalf("refused token: %v", err)
	}
}

// The fake verifies tokens when asked: a call carries the bearer token.
func TestBearerSent(t *testing.T) {
	f, conn := fakeacs.Dial(t)
	var seen atomic.Value
	f.Authenticate = func(_ context.Context, tok string) error {
		seen.Store(tok)
		return nil
	}
	c := acs.New(conn, time.Second)
	if _, err := c.Check(context.Background(), acs.PlatformTenant, platform, "view_overview", acs.User(alice)); err != nil {
		t.Fatal(err)
	}
	if seen.Load() != "" {
		t.Fatalf("no per-RPC credential configured, yet a token arrived: %v", seen.Load())
	}
	f.Authenticate = func(context.Context, string) error { return errors.New("bad token") }
	if _, err := c.Check(context.Background(), acs.PlatformTenant, platform, "view_overview", acs.User(alice)); !errors.Is(err, acs.ErrUnavailable) {
		t.Fatalf("MailOS's credential refused: %v", err)
	}
}
