package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/platform"
	"github.com/razatechofficial/mail-os/application/platformroles"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/domain/platformrole"
	"github.com/razatechofficial/mail-os/infrastructure/acs"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeacs"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

const platformSubject = "0d6f3a7e-5b1c-4c55-9f61-2f8f1c9b6a11"

type aggregates struct{ items []platform.TenantAggregate }

func (a aggregates) TenantAggregates(context.Context, time.Time, string, int, time.Time) ([]platform.TenantAggregate, error) {
	return a.items, nil
}
func (aggregates) ProviderKindsInUse(context.Context) ([]string, error) { return nil, nil }

type nopReplay map[string]bool

func (n nopReplay) ClaimOnce(_ context.Context, k string, _ time.Duration) (bool, error) {
	if n[k] {
		return false, nil
	}
	n[k] = true
	return true, nil
}
func (n nopReplay) Forget(_ context.Context, k string) error       { delete(n, k); return nil }
func (n nopReplay) Seen(_ context.Context, k string) (bool, error) { return n[k], nil }

type platformEnv struct {
	iam   *fakeiam.IAM
	acs   *fakeacs.ACS
	roles acs.Platform
	r     *gin.Engine
}

// platformEngine mounts the platform API as the router does, with the
// principal set to a platform account, a fake ACS and the IAM's approval
// keys.
func platformEngine(t *testing.T, items []platform.TenantAggregate) *platformEnv {
	t.Helper()
	_ = logger.InitSimple("fatal", "console")
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	f, conn := fakeacs.Dial(t)
	roles := acs.Platform{Client: acs.New(conn, time.Second)}
	r := gin.New()
	api := r.Group("/api/platform/v1", func(c *gin.Context) {
		p := access.Principal{Kind: access.KindPlatform, Subject: platformSubject, Email: "ops@example.com"}
		c.Request = c.Request.WithContext(access.WithPrincipal(c.Request.Context(), p))
	})
	NewPlatformHandler(platform.New(aggregates{items}, false), roles).MountPlatform(api, middleware.PlatformGuard{ACS: roles})
	v := jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, JWKSURL: iam.ApprovalJWKSURL()})
	NewPlatformRolesHandler(platformroles.New(v, roles, nopReplay{}, nil)).MountPublic(r)
	return &platformEnv{iam: iam, acs: f, roles: roles, r: r}
}

func (e *platformEnv) deliver(t *testing.T, claims map[string]any) int {
	t.Helper()
	return do(e.r, http.MethodPost, RoleAttestationsPath, map[string]string{"attestation": e.iam.Attestation(claims)}).Code
}

// The IAM's attestations make a person eligible, then active; the guarded
// routes answer while the role is active, and /me reports it.
func TestPlatformRoutesFollowAttestations(t *testing.T) {
	e := platformEngine(t, nil)
	if w := do(e.r, http.MethodGet, "/api/platform/v1/tenants", nil); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), middleware.PlatformRoleMessage) {
		t.Fatalf("no role: %d %s", w.Code, w.Body)
	}
	if code := e.deliver(t, map[string]any{"op": platformroles.OpEligibility, "action": "add", "sub": platformSubject,
		"role": "platform_auditor", "eligibility_id": uuid.NewString()}); code != http.StatusNoContent {
		t.Fatalf("eligibility: %d", code)
	}
	until := time.Now().Add(2 * time.Hour).Unix()
	act := map[string]any{"op": platformroles.OpActivation, "action": "activate", "sub": platformSubject, "role": "platform_auditor",
		"active_until": until, "activation_id": uuid.NewString(), "requested_by": platformSubject}
	raw := e.iam.Attestation(act)
	if w := do(e.r, http.MethodPost, RoleAttestationsPath, map[string]string{"attestation": raw}); w.Code != http.StatusNoContent {
		t.Fatalf("activation: %d %s", w.Code, w.Body)
	}
	if w := do(e.r, http.MethodPost, RoleAttestationsPath, map[string]string{"attestation": raw}); w.Code != http.StatusNoContent {
		t.Fatalf("redelivery: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/api/platform/v1/tenants", "/api/platform/v1/connectors", "/api/platform/v1/templates",
		"/api/platform/v1/templates/iam.auth.password_reset_requested"} {
		if w := do(e.r, http.MethodGet, path, nil); w.Code != http.StatusOK {
			t.Errorf("auditor %s: %d %s", path, w.Code, w.Body)
		}
	}
	w := do(e.r, http.MethodGet, "/api/platform/v1/me", nil)
	var me struct {
		Data struct {
			Subject, Email string
			Roles          []struct {
				Role      string    `json:"role"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			Eligible    []string
			Permissions []string
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil || w.Code != 200 {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	d := me.Data
	sort.Strings(d.Permissions)
	if d.Subject != platformSubject || d.Email != "ops@example.com" || len(d.Roles) != 1 || d.Roles[0].Role != "platform_auditor" ||
		d.Roles[0].ExpiresAt.Unix() != until || len(d.Eligible) != 1 ||
		strings.Join(d.Permissions, ",") != "view_audit,view_config,view_connectors,view_overview,view_templates,view_tenants" {
		t.Fatalf("me: %+v", d)
	}
	e.acs.SetUnavailable(true)
	if w := do(e.r, http.MethodGet, "/api/platform/v1/me", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("me with ACS down: %d", w.Code)
	}
	if w := do(e.r, http.MethodGet, "/api/platform/v1/tenants", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("tenants with ACS down: %d", w.Code)
	}
}

func TestRoleAttestationRefusals(t *testing.T) {
	e := platformEngine(t, nil)
	cases := []struct {
		body any
		want int
	}{
		{map[string]string{}, http.StatusBadRequest},
		{map[string]string{"attestation": "x.y.z"}, http.StatusUnauthorized},
		{map[string]string{"attestation": e.iam.Sign(e.iam.Keys[0], fakeiam.AttestationType, map[string]any{"iss": e.iam.Issuer, "aud": "mailos",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "j"})}, http.StatusUnauthorized},
		{map[string]string{"attestation": e.iam.Attestation(map[string]any{"op": "mailos.lockbox_grant", "action": "add", "sub": platformSubject,
			"role": "platform_support", "eligibility_id": uuid.NewString()})}, http.StatusBadRequest},
		{map[string]string{"attestation": e.iam.Attestation(map[string]any{"op": platformroles.OpActivation, "action": "activate", "sub": platformSubject,
			"role": "platform_support", "activation_id": uuid.NewString(), "requested_by": platformSubject,
			"active_until": time.Now().Add(time.Hour).Unix()})}, http.StatusForbidden},
		{map[string]string{"attestation": strings.Repeat("a", 17<<10)}, http.StatusRequestEntityTooLarge},
	}
	for i, c := range cases {
		w := do(e.r, http.MethodPost, RoleAttestationsPath, c.body)
		if w.Code != c.want {
			t.Errorf("case %d: %d %s, want %d", i, w.Code, w.Body, c.want)
		}
		if w.Code == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("case %d: no challenge", i)
		}
	}
	if rels := e.acs.Relationships(); len(rels) != 0 {
		t.Fatalf("written: %v", rels)
	}
	off := gin.New()
	NewPlatformRolesHandler(nil).MountPublic(off)
	if w := do(off, http.MethodPost, RoleAttestationsPath, map[string]string{"attestation": "x"}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("not configured: %d", w.Code)
	}
}

// The tenants list carries counts only: each item has exactly the
// contract's fields, so no subject, recipient, body or template data can
// appear in it.
func TestPlatformTenantsAreAggregatesOnly(t *testing.T) {
	items := []platform.TenantAggregate{{ID: uuid.NewString(), Active: true, CreatedAt: time.Now(), Applications: 2, Domains: 1, Messages30d: 7}}
	e := platformEngine(t, items)
	if err := e.roles.AddEligibility(context.Background(), platformSubject, platformrole.Support); err != nil {
		t.Fatal(err)
	}
	if err := e.roles.Activate(context.Background(), platformSubject, platformrole.Support, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	w := do(e.r, http.MethodGet, "/api/platform/v1/tenants?limit=10", nil)
	var body struct {
		Data struct {
			Items      []map[string]any `json:"items"`
			NextCursor *string          `json:"next_cursor"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || len(body.Data.Items) != 1 || body.Data.NextCursor == nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var keys []string
	for k := range body.Data.Items[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !slices.Equal(keys, []string{"active", "applications", "created_at", "domains", "id", "messages_30d"}) {
		t.Fatalf("tenant item fields %v", keys)
	}
	if w := do(e.r, http.MethodGet, "/api/platform/v1/tenants?limit=500", nil); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("limit 500: %d", w.Code)
	}
	// Support may not see connectors or templates.
	for _, path := range []string{"/api/platform/v1/connectors", "/api/platform/v1/templates"} {
		if w := do(e.r, http.MethodGet, path, nil); w.Code != http.StatusForbidden {
			t.Errorf("support %s: %d", path, w.Code)
		}
	}
}
