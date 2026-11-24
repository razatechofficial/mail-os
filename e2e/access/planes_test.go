//go:build e2e

package access

// The planes from outside (ADR 0001 §3.3, contract C2-C6): a platform token
// is refused on every tenant route and a tenant-plane token on every
// platform route; the IAM's signed attestation activates a platform role in
// ACS and the guarded routes answer while it is active and stop when it
// ends or expires; the tenants list carries counts, never a message.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

const platformRoleMessage = "Your platform role does not allow this. Activate a MailOS platform role in the IAM."

var platformRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/platform/v1/me"},
	{http.MethodGet, "/api/platform/v1/tenants"},
	{http.MethodGet, "/api/platform/v1/connectors"},
	{http.MethodGet, "/api/platform/v1/templates"},
	{http.MethodGet, "/api/platform/v1/templates/iam.auth.password_reset_requested"},
}

// A platform token, however privileged its holder, is refused (401) on
// every /api/v1 route.
func TestPlatformTokenRefusedOnTenantRoutes(t *testing.T) {
	sub := uuid.NewString()
	if s := fx.Env.PlatformRole(t, sub, "platform_owner", "add", 0); s != http.StatusNoContent {
		t.Fatalf("eligibility: %d", s)
	}
	if s := fx.Env.PlatformRole(t, sub, "platform_owner", "activate", 600); s != http.StatusNoContent {
		t.Fatalf("activation: %d", s)
	}
	c := fx.Env.Platform(t, sub)
	for _, r := range routes() {
		if res := c.Do(t, r.method, r.path, body(r)); res.Status != http.StatusUnauthorized {
			t.Errorf("platform token on %s %s = %s, want 401", r.method, r.path, res)
		}
	}
	// The platform token does reach its own plane.
	c.Expect(t, http.StatusOK, http.MethodGet, "/api/platform/v1/tenants", nil)
}

// Every tenant-plane token is refused (401) on every platform route: a
// tenant administrator, a service, a delegated token, and platform-audience
// tokens carrying a tenant or an act.
func TestTenantTokensRefusedOnPlatformRoutes(t *testing.T) {
	tenantAdmin := fx.Admin(t)
	service := fx.Service(t, fx.Env.IAMClient)
	delegated := fx.As(t, harness.User{Roles: []string{admin}, Extra: map[string]any{"act": map[string]any{"sub": uuid.NewString()}}})
	platformAud := fx.As(t, harness.User{Roles: []string{admin}, Audience: "mailos-platform"})
	sub := uuid.NewString()
	withTenant := fx.Env.NewClient().WithBearer(fx.Env.PlatformToken(t, sub, map[string]any{"tid": fx.TenantID}))
	withAct := fx.Env.NewClient().WithBearer(fx.Env.PlatformToken(t, sub, map[string]any{"act": map[string]any{"sub": uuid.NewString()}}))
	twoAudiences := fx.Env.NewClient().WithBearer(fx.Env.PlatformToken(t, sub, map[string]any{"aud": []string{"mailos-platform", "mailos"}}))
	for name, c := range map[string]*harness.Client{"tenant admin": tenantAdmin, "service": service, "delegated": delegated,
		"tenant user for the platform audience": platformAud, "platform token with tid": withTenant, "platform token with act": withAct,
		"platform and tenant audiences": twoAudiences} {
		for _, r := range platformRoutes {
			if res := c.Do(t, r.method, r.path, nil); res.Status != http.StatusUnauthorized {
				t.Errorf("%s on %s %s = %s, want 401", name, r.method, r.path, res)
			}
		}
	}
	// And they keep working on their own plane.
	tenantAdmin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/me", nil)
}

// The IAM's attestations drive access: no role, 403 with the contract's
// message; eligible only, still 403; activated, the routes answer and /me
// shows the role and its end; ended, 403 again; an activation that expires
// stops answering by itself; an activation for a person not eligible is
// refused.
func TestAttestationActivatesPlatformRole(t *testing.T) {
	sub := uuid.NewString()
	c := fx.Env.Platform(t, sub)
	res := c.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/platform/v1/connectors", nil)
	if res.Envelope().Error.Message != platformRoleMessage {
		t.Fatalf("no role message: %s", res)
	}
	if s := fx.Env.PlatformRole(t, sub, "platform_operator", "activate", 600); s != http.StatusForbidden {
		t.Fatalf("activation without eligibility = %d, want 403", s)
	}
	if s := fx.Env.PlatformRole(t, sub, "platform_operator", "add", 0); s != http.StatusNoContent {
		t.Fatalf("eligibility: %d", s)
	}
	c.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/platform/v1/connectors", nil)
	if s := fx.Env.PlatformRole(t, sub, "platform_operator", "activate", 600); s != http.StatusNoContent {
		t.Fatalf("activation: %d", s)
	}
	for _, r := range platformRoutes {
		c.Expect(t, http.StatusOK, r.method, r.path, nil)
	}
	var me struct {
		Subject string `json:"subject"`
		Roles   []struct {
			Role      string    `json:"role"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"roles"`
		Eligible    []string `json:"eligible"`
		Permissions []string `json:"permissions"`
	}
	c.Expect(t, http.StatusOK, http.MethodGet, "/api/platform/v1/me", nil).Decode(t, &me)
	if me.Subject != sub || len(me.Roles) != 1 || me.Roles[0].Role != "platform_operator" ||
		me.Roles[0].ExpiresAt.Before(time.Now().Add(9*time.Minute)) || me.Roles[0].ExpiresAt.After(time.Now().Add(11*time.Minute)) ||
		len(me.Eligible) != 1 || !strings.Contains(strings.Join(me.Permissions, ","), "manage_tenants") ||
		strings.Contains(strings.Join(me.Permissions, ","), "manage_keys") {
		t.Fatalf("me: %+v", me)
	}
	tpl := c.Expect(t, http.StatusOK, http.MethodGet, "/api/platform/v1/templates/iam.auth.password_reset_requested", nil).Data()
	if harness.Str(tpl, "subject") == "" || !strings.Contains(harness.Str(tpl, "html"), "{{reset_link}}") {
		t.Fatalf("platform default: %v", tpl)
	}

	if s := fx.Env.PlatformRole(t, sub, "platform_operator", "end", 0); s != http.StatusNoContent {
		t.Fatalf("end: %d", s)
	}
	c.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/platform/v1/connectors", nil)

	// A short activation answers, then stops answering when it expires.
	if s := fx.Env.PlatformRole(t, sub, "platform_operator", "activate", 4); s != http.StatusNoContent {
		t.Fatalf("short activation: %d", s)
	}
	c.Expect(t, http.StatusOK, http.MethodGet, "/api/platform/v1/connectors", nil)
	harness.Eventually(t, "the activation expires", 20*time.Second, func() bool {
		return c.Do(t, http.MethodGet, "/api/platform/v1/connectors", nil).Status == http.StatusForbidden
	})
	c.Expect(t, http.StatusOK, http.MethodGet, "/api/platform/v1/me", nil).Decode(t, &me)
	if len(me.Roles) != 0 || len(me.Permissions) != 0 {
		t.Fatalf("me after expiry: %+v", me)
	}
}

// A replayed attestation changes nothing, a forged one is refused, and
// none needs a bearer token.
func TestRoleAttestationDelivery(t *testing.T) {
	sub := uuid.NewString()
	anon := fx.Env.NewClient()
	add := fx.Env.Attestation(t, map[string]any{"op": "mailos.role_eligibility", "action": "add", "sub": sub,
		"role": "platform_auditor", "eligibility_id": uuid.NewString()})
	anon.Expect(t, http.StatusNoContent, http.MethodPost, "/api/platform/v1/role-attestations", map[string]any{"attestation": add})
	anon.Expect(t, http.StatusNoContent, http.MethodPost, "/api/platform/v1/role-attestations", map[string]any{"attestation": add})
	forged := add[:strings.LastIndex(add, ".")+1] + "AAAA"
	anon.ExpectError(t, http.StatusUnauthorized, "", http.MethodPost, "/api/platform/v1/role-attestations", map[string]any{"attestation": forged})
	wrongAud := fx.Env.Attestation(t, map[string]any{"aud": "acs", "op": "mailos.role_eligibility", "action": "add", "sub": sub,
		"role": "platform_auditor", "eligibility_id": uuid.NewString()})
	anon.ExpectError(t, http.StatusUnauthorized, "", http.MethodPost, "/api/platform/v1/role-attestations", map[string]any{"attestation": wrongAud})
	tooLong := fx.Env.Attestation(t, map[string]any{"op": "mailos.role_activation", "action": "activate", "sub": sub, "role": "platform_auditor",
		"activation_id": uuid.NewString(), "requested_by": sub, "active_until": time.Now().Add(9 * time.Hour).Unix()})
	anon.ExpectError(t, http.StatusBadRequest, "", http.MethodPost, "/api/platform/v1/role-attestations", map[string]any{"attestation": tooLong})
}

// The tenants list counts a tenant's messages and never shows one: no
// subject, recipient or body of a message sent in the tenant appears.
func TestPlatformTenantsAreAggregatesOnly(t *testing.T) {
	op, _ := fx.NewUser(t, operator)
	box := fx.Env.NewMailbox("planes")
	subject := "Planes secret subject " + harness.Unique()
	bodyText := "planes body " + harness.Unique()
	op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", map[string]any{"to_email": box.Address,
		"subject": subject, "html_body": "<p>" + bodyText + "</p>", "text_body": bodyText})

	sub := uuid.NewString()
	for _, a := range []string{"add", "activate"} {
		if s := fx.Env.PlatformRole(t, sub, "platform_support", a, 600); s != http.StatusNoContent {
			t.Fatalf("%s: %d", a, s)
		}
	}
	c := fx.Env.Platform(t, sub)
	var found map[string]any
	cursor := ""
	for range 50 {
		res := c.Expect(t, http.StatusOK, http.MethodGet, "/api/platform/v1/tenants?limit=200&cursor="+cursor, nil)
		for _, needle := range []string{subject, bodyText, box.Address} {
			if strings.Contains(string(res.Body), needle) {
				t.Fatalf("the tenants list shows %q", needle)
			}
		}
		data := res.Data()
		items, _ := data["items"].([]any)
		for _, it := range items {
			m, _ := it.(map[string]any)
			if len(m) != 6 {
				t.Fatalf("tenant item fields: %v", m)
			}
			if m["id"] == fx.TenantID {
				found = m
			}
		}
		if cursor = harness.Str(data, "next_cursor"); cursor == "" {
			break
		}
	}
	if found == nil {
		t.Fatalf("tenant %s not listed", fx.TenantID)
	}
	if n, _ := found["messages_30d"].(float64); n < 1 {
		t.Fatalf("tenant aggregates: %v", found)
	}
	// Support sees tenants, not connectors or templates.
	c.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/platform/v1/templates", nil)
}

// The platform sign-in rule (contract C2): the running server accepts only
// the platform console's tokens (azp), from a passkey sign-in (acr) no
// older than 8 hours (auth_time). A weak or old sign-in gets 401 with the
// RFC 9470 challenge, so the console signs in to the platform again; a
// token for another client is invalid.
func TestPlatformSignInRule(t *testing.T) {
	sub := uuid.NewString()
	for _, a := range []string{"add", "activate"} {
		if s := fx.Env.PlatformRole(t, sub, "platform_auditor", a, 600); s != http.StatusNoContent {
			t.Fatalf("%s: %d", a, s)
		}
	}
	with := func(extra map[string]any) *harness.Client {
		return fx.Env.NewClient().WithBearer(fx.Env.PlatformToken(t, sub, extra))
	}
	with(map[string]any{"auth_time": time.Now().Add(-7 * time.Hour).Unix()}).
		Expect(t, http.StatusOK, http.MethodGet, "/api/platform/v1/connectors", nil)

	for name, extra := range map[string]map[string]any{
		"authenticator app sign-in": {"acr": "urn:iam:acr:mfa", "amr": []string{"otp", "mfa"}},
		"password sign-in":          {"acr": "urn:iam:acr:password", "amr": []string{"pwd"}},
		"no acr":                    {"acr": nil},
		"9-hour-old sign-in":        {"auth_time": time.Now().Add(-9 * time.Hour).Unix()},
		"no auth_time":              {"auth_time": nil},
	} {
		c := with(extra)
		for _, r := range platformRoutes {
			res := c.ExpectError(t, http.StatusUnauthorized, "INSUFFICIENT_USER_AUTHENTICATION", r.method, r.path, nil)
			ch := res.Header.Get("WWW-Authenticate")
			if !strings.Contains(ch, `error="insufficient_user_authentication"`) ||
				!strings.Contains(ch, `acr_values="urn:iam:acr:phishing-resistant"`) || !strings.Contains(ch, `max_age="28800"`) {
				t.Errorf("%s on %s %s: challenge %q", name, r.method, r.path, ch)
			}
		}
	}
	for name, extra := range map[string]map[string]any{
		"another platform application": {"azp": "another-platform-app", "client_id": "another-platform-app"},
		"no azp":                       {"azp": nil},
		"client_id not its azp":        {"client_id": "another-platform-app"},
	} {
		c := with(extra)
		for _, r := range platformRoutes {
			res := c.ExpectError(t, http.StatusUnauthorized, "UNAUTHORIZED", r.method, r.path, nil)
			if ch := res.Header.Get("WWW-Authenticate"); !strings.Contains(ch, `error="invalid_token"`) {
				t.Errorf("%s on %s %s: challenge %q", name, r.method, r.path, ch)
			}
		}
	}
}

// ADR 0001 rule A4 (until the lockbox ships): no platform route returns
// tenant content. A message sent in a tenant, with a unique subject, body
// and recipient, appears on no platform route, whatever role reads it.
func TestPlatformRoutesReturnNoTenantContent(t *testing.T) {
	op, _ := fx.NewUser(t, operator)
	box := fx.Env.NewMailbox("a4")
	subject := "A4 secret subject " + harness.Unique()
	bodyText := "a4 secret body " + harness.Unique()
	op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", map[string]any{"to_email": box.Address,
		"subject": subject, "html_body": "<p>" + bodyText + "</p>", "text_body": bodyText})

	sub := uuid.NewString()
	for _, a := range []string{"add", "activate"} {
		if s := fx.Env.PlatformRole(t, sub, "platform_owner", a, 600); s != http.StatusNoContent {
			t.Fatalf("%s: %d", a, s)
		}
	}
	c := fx.Env.Platform(t, sub)
	for _, r := range platformRoutes {
		res := c.Expect(t, http.StatusOK, r.method, r.path, nil)
		for _, needle := range []string{subject, bodyText, box.Address} {
			if strings.Contains(string(res.Body), needle) {
				t.Errorf("%s %s shows tenant content %q", r.method, r.path, needle)
			}
		}
	}
}
