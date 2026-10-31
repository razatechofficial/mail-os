//go:build e2e

// Package access proves the API's authorization from outside: every route
// against every MailOS role (contract §5), no role, refused tokens, step-up
// on the sensitive permissions with the RFC 9470 challenge, and that each
// refusal is audited.
package access

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "access", &fx) }

const (
	admin     = harness.RoleAdmin
	editor    = harness.RoleTemplateEditor
	publisher = harness.RoleTemplatePublisher
	operator  = harness.RoleOperator
	auditor   = harness.RoleAuditor
	viewer    = harness.RoleViewer
)

var allRoles = []string{admin, editor, publisher, operator, auditor, viewer}

// route is one API route, the roles the contract lets call it, and whether
// it needs step-up. The ids are random: a permitted call answers 404 or 422,
// a refused one 403, because the guard runs before the handler.
type route struct {
	method, path string
	roles        []string
	stepUp       bool
}

func routes() []route {
	id := harness.NewID()
	p := func(s string) string { return strings.ReplaceAll(s, "{id}", id) }
	all, adm := allRoles, []string{admin}
	ops := []string{admin, operator}
	return []route{
		{http.MethodGet, "/api/v1/me", all, false},
		{http.MethodGet, "/api/v1/organizations", all, false},
		{http.MethodGet, p("/api/v1/organizations/{id}"), all, false},
		{http.MethodGet, "/api/v1/tenant/settings", all, false},
		{http.MethodPut, "/api/v1/tenant/settings", adm, true},
		{http.MethodGet, "/api/v1/keys/encryption", adm, true},
		{http.MethodPost, "/api/v1/keys/encryption/nonexistent/rotate", adm, true},

		{http.MethodGet, "/api/v1/templates", all, false},
		{http.MethodPost, "/api/v1/templates", []string{admin, editor}, false},
		{http.MethodGet, p("/api/v1/templates/{id}"), all, false},
		{http.MethodPut, p("/api/v1/templates/{id}"), []string{admin, editor}, false},
		{http.MethodDelete, p("/api/v1/templates/{id}"), adm, false},
		{http.MethodGet, "/api/v1/template-topics", all, false},
		{http.MethodGet, p("/api/v1/templates/{id}/draft"), all, false},
		{http.MethodPut, p("/api/v1/templates/{id}/draft"), []string{admin, editor}, false},
		{http.MethodPost, p("/api/v1/templates/{id}/publish"), []string{admin, publisher}, true},
		{http.MethodGet, p("/api/v1/templates/{id}/versions"), all, false},
		{http.MethodGet, p("/api/v1/templates/{id}/active-version"), all, false},
		{http.MethodPost, p("/api/v1/templates/{id}/versions/1/restore"), []string{admin, editor}, false},
		{http.MethodPost, p("/api/v1/templates/{id}/preview"), []string{admin, editor}, false},
		{http.MethodPost, p("/api/v1/templates/{id}/test-send"), []string{admin, editor}, false},
		{http.MethodGet, "/api/v1/template-branding", all, false},
		{http.MethodPut, "/api/v1/template-branding", adm, false},

		{http.MethodGet, "/api/v1/providers", all, false},
		{http.MethodGet, p("/api/v1/providers/{id}"), all, false},
		{http.MethodPost, "/api/v1/providers", adm, true},
		{http.MethodPut, p("/api/v1/providers/{id}"), adm, true},
		{http.MethodDelete, p("/api/v1/providers/{id}"), adm, true},

		{http.MethodGet, "/api/v1/sending-domains", all, false},
		{http.MethodGet, p("/api/v1/sending-domains/{id}"), all, false},
		{http.MethodPost, "/api/v1/sending-domains", adm, true},
		{http.MethodPost, p("/api/v1/sending-domains/{id}/verify"), adm, true},
		{http.MethodDelete, p("/api/v1/sending-domains/{id}"), adm, true},

		{http.MethodGet, "/api/v1/webhooks", all, false},
		{http.MethodGet, p("/api/v1/webhooks/{id}"), all, false},
		{http.MethodPost, "/api/v1/webhooks", adm, true},
		{http.MethodPut, p("/api/v1/webhooks/{id}"), adm, true},
		{http.MethodDelete, p("/api/v1/webhooks/{id}"), adm, true},

		{http.MethodGet, "/api/v1/suppressions", all, false},
		{http.MethodPost, "/api/v1/suppressions", ops, false},
		{http.MethodDelete, "/api/v1/suppressions", ops, false},

		{http.MethodPost, "/api/v1/messages/send", ops, false},
		{http.MethodPost, "/api/v1/messages/batch", ops, false},
		{http.MethodGet, "/api/v1/messages", all, false},
		{http.MethodGet, p("/api/v1/messages/{id}"), all, false},
		{http.MethodGet, p("/api/v1/messages/{id}/body"), []string{admin, operator, auditor}, true},
		{http.MethodPost, p("/api/v1/messages/{id}/cancel"), ops, false},
		{http.MethodPost, p("/api/v1/messages/{id}/resend"), ops, false},

		{http.MethodPost, "/api/v1/events", nil, false},

		{http.MethodGet, "/api/v1/analytics/stats", all, false},
		{http.MethodGet, "/api/v1/analytics/audit-logs", []string{admin, auditor}, false},
		{http.MethodGet, "/api/v1/analytics/audit-logs/export", []string{admin, auditor}, true},

		{http.MethodGet, "/api/v1/contacts", all, false},
		{http.MethodPost, "/api/v1/contacts", ops, false},
		{http.MethodPost, "/api/v1/contacts/batch", ops, false},
		{http.MethodGet, p("/api/v1/contacts/{id}"), all, false},
		{http.MethodPut, p("/api/v1/contacts/{id}"), ops, false},
		{http.MethodDelete, p("/api/v1/contacts/{id}"), ops, false},
		{http.MethodGet, "/api/v1/contact-lists", all, false},
		{http.MethodPost, "/api/v1/contact-lists", ops, false},
		{http.MethodGet, p("/api/v1/contact-lists/{id}"), all, false},
		{http.MethodPut, p("/api/v1/contact-lists/{id}"), ops, false},
		{http.MethodDelete, p("/api/v1/contact-lists/{id}"), ops, false},
		{http.MethodGet, p("/api/v1/contact-lists/{id}/members"), all, false},
		{http.MethodPost, p("/api/v1/contact-lists/{id}/members"), ops, false},
		{http.MethodDelete, p("/api/v1/contact-lists/{id}/members"), ops, false},

		{http.MethodGet, "/api/v1/campaigns", all, false},
		{http.MethodPost, "/api/v1/campaigns", ops, false},
		{http.MethodGet, p("/api/v1/campaigns/{id}"), all, false},
		{http.MethodPut, p("/api/v1/campaigns/{id}"), ops, false},
		{http.MethodDelete, p("/api/v1/campaigns/{id}"), ops, false},
		{http.MethodPost, p("/api/v1/campaigns/{id}/launch"), ops, false},
		{http.MethodPost, p("/api/v1/campaigns/{id}/pause"), ops, false},
		{http.MethodPost, p("/api/v1/campaigns/{id}/resume"), ops, false},
		{http.MethodPost, p("/api/v1/campaigns/{id}/cancel"), ops, false},
	}
}

// body is a request body no handler accepts, so a permitted write changes
// nothing: it fails validation or finds nothing.
func body(r route) any {
	switch {
	case r.method == http.MethodGet:
		return nil
	case strings.HasSuffix(r.path, "/tenant/settings"):
		return map[string]any{"message_retention_days": -1}
	case strings.HasSuffix(r.path, "/template-branding"):
		return map[string]any{"primary_color": "not a colour"}
	case r.path == "/api/v1/suppressions" && r.method == http.MethodDelete:
		return map[string]any{"email": "not-suppressed-" + harness.Unique() + "@" + harness.EmailDomain}
	}
	return map[string]any{"name": ""}
}

func TestEveryRouteAgainstEveryRole(t *testing.T) {
	for _, role := range allRoles {
		t.Run(role, func(t *testing.T) {
			c, _ := fx.NewUser(t, role)
			for _, r := range routes() {
				res := c.Do(t, r.method, r.path, body(r))
				allowed := slices.Contains(r.roles, role)
				switch {
				case allowed && (res.Status == http.StatusForbidden || res.Status == http.StatusUnauthorized):
					t.Errorf("%s %s as %s = %s, want it permitted", r.method, r.path, role, res)
				case !allowed && (res.Status != http.StatusForbidden || res.ErrorCode() != "FORBIDDEN"):
					t.Errorf("%s %s as %s = %s, want 403 FORBIDDEN", r.method, r.path, role, res)
				case allowed && res.Status >= 500:
					t.Errorf("%s %s as %s = %s, want no server error", r.method, r.path, role, res)
				}
			}
		})
	}
}

func TestRolesCombine(t *testing.T) {
	c, _ := fx.NewUser(t, viewer, editor)
	c.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/templates", map[string]any{"name": ""})
	c.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/messages/send", map[string]any{})
}

func TestNoMailOSRoleIsRefusedEverywhere(t *testing.T) {
	for _, roles := range [][]string{nil, {}, {"iam_admin", "MAILOS_ADMIN", "mailos-admin"}} {
		c := fx.As(t, harness.User{Roles: roles})
		for _, r := range routes() {
			res := c.Do(t, r.method, r.path, body(r))
			if res.Status != http.StatusForbidden {
				t.Errorf("roles %q: %s %s = %s, want 403", roles, r.method, r.path, res)
			}
		}
		me := c.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/v1/me", nil)
		if !strings.Contains(me.Envelope().Error.Message, "no MailOS role") {
			t.Errorf("no-role message: %s", me)
		}
	}
}

func TestRefusedTokens(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	cases := map[string]harness.User{
		"expired":                   {Roles: []string{admin}, Extra: map[string]any{"exp": past}},
		"not yet valid":             {Roles: []string{admin}, Extra: map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}},
		"another audience":          {Roles: []string{admin}, Audience: "xdr"},
		"another issuer":            {Roles: []string{admin}, Extra: map[string]any{"iss": "https://evil.example.com"}},
		"no tenant":                 {Roles: []string{admin}, Tenant: "-"},
		"DPoP-bound sent as Bearer": {Roles: []string{admin}, JKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"},
		"no subject":                {Roles: []string{admin}, Extra: map[string]any{"sub": ""}},
		"far-future issued-at":      {Roles: []string{admin}, Extra: map[string]any{"iat": time.Now().Add(24 * time.Hour).Unix()}},
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			tok, _ := fx.Env.UserToken(t, withTenant(u))
			res := fx.Env.NewClient().WithBearer(tok).Do(t, http.MethodGet, "/api/v1/templates", nil)
			if res.Status != http.StatusUnauthorized && res.Status != http.StatusForbidden {
				t.Fatalf("token %s = %s, want 401 or 403", name, res)
			}
			if res.Status == http.StatusUnauthorized && !strings.Contains(res.Header.Get("WWW-Authenticate"), "error=") {
				t.Errorf("401 without a WWW-Authenticate error: %q", res.Header.Get("WWW-Authenticate"))
			}
		})
	}
}

// withTenant puts the token in the package's tenant; "-" means no tid.
func withTenant(u harness.User) harness.User {
	switch u.Tenant {
	case "":
		u.Tenant = fx.TenantID
	case "-":
		u.Tenant = ""
	}
	return u
}

func TestUnsignedAndMalformedTokens(t *testing.T) {
	tok, _ := fx.Env.UserToken(t, harness.User{Tenant: fx.TenantID, Roles: []string{admin}})
	parts := strings.Split(tok, ".")
	none := "eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0." + parts[1] + "."
	for name, raw := range map[string]string{
		"alg none": none, "no signature": parts[0] + "." + parts[1] + ".", "garbage": "abc.def.ghi", "two parts": parts[0] + "." + parts[1],
	} {
		res := fx.Env.NewClient().WithBearer(raw).Do(t, http.MethodGet, "/api/v1/templates", nil)
		if res.Status != http.StatusUnauthorized {
			t.Errorf("%s = %s, want 401", name, res)
		}
	}
	res := fx.Env.NewClient().Do(t, http.MethodGet, "/api/v1/templates", nil, http.Header{"Authorization": {"Basic " + tok}})
	if res.Status != http.StatusUnauthorized {
		t.Errorf("Basic scheme = %s, want 401", res)
	}
}

func TestStepUpOnSensitiveRoutes(t *testing.T) {
	for _, r := range routes() {
		if !r.stepUp {
			continue
		}
		role := r.roles[0]
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			stale := fx.As(t, harness.User{Roles: []string{role}, AuthAge: 10 * time.Minute})
			res := stale.ExpectError(t, http.StatusForbidden, "STEP_UP_REQUIRED", r.method, r.path, body(r))
			h := res.Header.Get("WWW-Authenticate")
			if !strings.Contains(h, `error="insufficient_user_authentication"`) || !strings.Contains(h, "max_age=") {
				t.Errorf("stale challenge = %q", h)
			}
			weak := fx.As(t, harness.User{Roles: []string{role}, ACR: "urn:iam:acr:password"})
			res = weak.ExpectError(t, http.StatusForbidden, "STEP_UP_REQUIRED", r.method, r.path, body(r))
			if h := res.Header.Get("WWW-Authenticate"); !strings.Contains(h, "acr_values=") {
				t.Errorf("weak sign-in challenge has no acr_values: %q", h)
			}
			unknown := fx.As(t, harness.User{Roles: []string{role}, ACR: "0"})
			unknown.ExpectError(t, http.StatusForbidden, "STEP_UP_REQUIRED", r.method, r.path, body(r))
			delegated := fx.As(t, harness.User{Roles: []string{role}, Extra: map[string]any{"act": map[string]any{"sub": harness.NewID()}}})
			res = delegated.Expect(t, http.StatusForbidden, r.method, r.path, body(r))
			if res.ErrorCode() == "STEP_UP_REQUIRED" {
				t.Errorf("a delegated token was offered step-up: %s", res)
			}
			fresh := fx.As(t, harness.User{Roles: []string{role}})
			if res := fresh.Do(t, r.method, r.path, body(r)); res.Status == http.StatusForbidden {
				t.Errorf("fresh MFA sign-in refused: %s", res)
			}
		})
	}
}

func TestStaleSignInStillReads(t *testing.T) {
	stale := fx.As(t, harness.User{Roles: []string{admin}, AuthAge: 2 * time.Hour})
	for _, path := range []string{"/api/v1/templates", "/api/v1/messages", "/api/v1/providers", "/api/v1/analytics/audit-logs"} {
		stale.Expect(t, http.StatusOK, http.MethodGet, path, nil)
	}
}

func TestRefusalsAreAudited(t *testing.T) {
	v, sub := fx.NewUser(t, viewer)
	v.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/providers", map[string]any{})
	stale := fx.As(t, harness.User{Subject: harness.NewID(), Roles: []string{admin}, AuthAge: 10 * time.Minute})
	stale.ExpectError(t, http.StatusForbidden, "STEP_UP_REQUIRED", http.MethodGet, "/api/v1/analytics/audit-logs/export", nil)

	harness.Eventually(t, "the refusals in the audit log", 10*time.Second, func() bool {
		log := fx.Admin(t).Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs?limit=100", nil).String()
		return strings.Contains(log, "access_denied") && strings.Contains(log, "step_up_required") && strings.Contains(log, sub)
	})
}
