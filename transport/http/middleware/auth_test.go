package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	"github.com/razatechofficial/mail-os/pkg/stepup"
)

const tenant = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"

type tenants struct{ ensured []string }

func (t *tenants) Ensure(_ context.Context, id string) error {
	t.ensured = append(t.ensured, id)
	return nil
}

type auditLog struct {
	actions []string
	reasons []string
}

func (a *auditLog) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	a.actions = append(a.actions, action)
	r, _ := meta["reason"].(string)
	a.reasons = append(a.reasons, r)
	return nil
}

// spaApp is a browser application of the tenant.
func spaApp() domainapp.Application {
	a := appstest.Server("portal-web", tenant, "verify-email")
	a.Kind, a.System = domainapp.KindSPA, false
	return a
}

type noReplay struct{}

func (noReplay) ClaimOnce(context.Context, string, time.Duration) (bool, error) { return true, nil }

func router(t *testing.T) (*fakeiam.IAM, *gin.Engine, *tenants, *auditLog) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	ten, log := &tenants{}, &auditLog{}
	auth := &Auth{
		Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}),
		DPoP:     dpop.NewVerifier(noReplay{}, time.Minute),
		Tenants:  ten, Audit: log,
		Apps:     appstest.New(appstest.Server("mailos-iam", tenant, "iam.*"), appstest.Server("core-banking", tenant, "bank.*"), spaApp()),
	}
	g := Guard{StepUp: access.StepUpPolicy{MaxAge: 5 * time.Minute, ACR: access.ACRMFA}, Audit: log}
	r := gin.New()
	api := r.Group("/api/v1", RequestID(), auth.Required())
	ok := func(c *gin.Context) { c.JSON(200, gin.H{"success": true}) }
	api.GET("/templates", g.Require(access.PermTemplatesRead), ok)
	api.POST("/templates/:id/publish", g.Require(access.PermTemplatesPublish), ok)
	api.POST("/messages/send", g.Require(access.PermMessagesSend), func(c *gin.Context) {
		p := PrincipalFrom(c)
		c.JSON(200, gin.H{"tenant": p.TenantID, "application_id": p.ApplicationID})
	})
	api.POST("/messages/self", g.Require(access.PermMessagesSendSelf), ok)
	return iam, r, ten, log
}

func call(r *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r.ServeHTTP(w, req)
	return w
}

func code(w *httptest.ResponseRecorder) string {
	var b struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return b.Error.Code
}

func TestAuthentication(t *testing.T) {
	iam, r, ten, log := router(t)
	if w := call(r, "GET", "/api/v1/templates", ""); w.Code != 401 || !strings.Contains(w.Body.String(), MissingTokenMessage) {
		t.Fatalf("no token: %d %s", w.Code, w.Body)
	}
	forged := iam.Sign(iam.Unpublished, "at+jwt", map[string]any{"iss": iam.Issuer, "sub": "u", "aud": "mailos", "tid": tenant,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{"mailos_admin"}})
	if w := call(r, "GET", "/api/v1/templates", forged); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("forged token: %d", w.Code)
	}
	noRole := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"tenant_admin"}})
	if w := call(r, "GET", "/api/v1/templates", noRole); w.Code != 403 || !strings.Contains(w.Body.String(), "no MailOS role") {
		t.Fatalf("no MailOS role: %d %s", w.Code, w.Body)
	}
	viewer := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_viewer"}})
	if w := call(r, "GET", "/api/v1/templates", viewer); w.Code != 200 {
		t.Fatalf("viewer read: %d %s", w.Code, w.Body)
	}
	if len(ten.ensured) != 1 || ten.ensured[0] != tenant {
		t.Fatalf("tenant not provisioned: %v", ten.ensured)
	}
	if w := call(r, "POST", "/api/v1/templates/t1/publish", viewer); w.Code != 403 || code(w) != "FORBIDDEN" {
		t.Fatalf("viewer publishing: %d %s", w.Code, w.Body)
	}
	svc := iam.ServiceToken("mailos-iam", tenant)
	if w := call(r, "GET", "/api/v1/templates", svc); w.Code != 403 {
		t.Fatalf("service token on a console route: %d", w.Code)
	}
	if !contains(log.actions, "access_denied") {
		t.Fatalf("refusals not audited: %v", log.actions)
	}
}

// Service and browser tokens are resolved to their application: the
// application decides the tenant, an unknown or foreign client is refused
// with its reason audited, and a spa user keeps only self-send.
func TestApplicationCallers(t *testing.T) {
	iam, r, _, log := router(t)
	other := "0b6c1c3e-6a38-4a8f-9a59-2b9d3b6a8a11"

	w := call(r, "POST", "/api/v1/messages/send", iam.ServiceToken("core-banking", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), tenant) {
		t.Fatalf("server application without tid: %d %s", w.Code, w.Body)
	}
	for name, c := range map[string]struct {
		token, reason string
	}{
		"unknown client": {iam.ServiceToken("intruder", tenant), "unknown_client"},
		"other tenant":   {iam.ServiceToken("core-banking", other), "tenant_mismatch"},
		"spa as service": {iam.ServiceToken("portal-web", tenant), "kind_mismatch"},
		"server user":    {iam.UserToken(fakeiam.User{Tenant: tenant, ClientID: "core-banking", Roles: []string{"mailos_admin"}}), "kind_mismatch"},
		"spa no scope":   {iam.UserToken(fakeiam.User{Tenant: tenant, ClientID: "portal-web"}), "scope_missing"},
	} {
		w := call(r, "POST", "/api/v1/messages/send", c.token)
		if w.Code != 403 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
			continue
		}
		if got := log.reasons[len(log.reasons)-1]; got != c.reason {
			t.Errorf("%s: audited %q, want %q", name, got, c.reason)
		}
	}
	if w := call(r, "POST", "/api/v1/messages/send", iam.ServiceToken("intruder", tenant)); strings.Contains(w.Body.String(), "not a MailOS application") {
		t.Fatal("an identity refusal names its reason to the caller")
	}

	spa := iam.UserToken(fakeiam.User{Tenant: tenant, ClientID: "portal-web", Roles: []string{"mailos_admin"},
		Extra: map[string]any{"scope": "openid mailos.send.self"}})
	if w := call(r, "POST", "/api/v1/messages/self", spa); w.Code != 200 {
		t.Fatalf("spa self-send: %d %s", w.Code, w.Body)
	}
	if w := call(r, "GET", "/api/v1/templates", spa); w.Code != 403 {
		t.Fatalf("a spa user kept its console role: %d", w.Code)
	}
	if w := call(r, "POST", "/api/v1/messages/send", spa); w.Code != 403 {
		t.Fatalf("a spa user sent to anyone: %d", w.Code)
	}
	console := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_operator"}})
	if w := call(r, "POST", "/api/v1/messages/self", console); w.Code != 403 {
		t.Fatalf("a console user used self-send: %d", w.Code)
	}
}

func TestStepUp(t *testing.T) {
	iam, r, _, log := router(t)
	fresh := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_template_publisher"}})
	if w := call(r, "POST", "/api/v1/templates/t1/publish", fresh); w.Code != 200 {
		t.Fatalf("fresh MFA publish: %d %s", w.Code, w.Body)
	}
	stale := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_template_publisher"}, AuthAge: 10 * time.Minute})
	w := call(r, "POST", "/api/v1/templates/t1/publish", stale)
	if w.Code != 403 || code(w) != "STEP_UP_REQUIRED" {
		t.Fatalf("stale sign-in: %d %s", w.Code, w.Body)
	}
	scheme, ch, ok := stepup.Parse(w.Header().Get("WWW-Authenticate"))
	if !ok || scheme != "Bearer" || ch.MaxAge != 5*time.Minute {
		t.Fatalf("challenge %q", w.Header().Get("WWW-Authenticate"))
	}
	weak := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_template_publisher"}, ACR: access.ACRPassword})
	w = call(r, "POST", "/api/v1/templates/t1/publish", weak)
	if _, ch, _ := stepup.Parse(w.Header().Get("WWW-Authenticate")); w.Code != 403 || len(ch.ACRValues) != 1 || ch.ACRValues[0] != access.ACRMFA {
		t.Fatalf("password-only sign-in: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if !contains(log.actions, "step_up_required") {
		t.Fatal("step-up refusal not audited")
	}
}

func TestBoundTokenNeedsProof(t *testing.T) {
	iam, r, _, _ := router(t)
	bound := iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_viewer"}, JKT: "some-thumbprint"})
	w := call(r, "GET", "/api/v1/templates", bound)
	if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "DPoP") {
		t.Fatalf("bound token without proof: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
