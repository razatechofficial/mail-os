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

	"github.com/razatechofficial/mail-os/domain/access"
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

type auditLog struct{ actions []string }

func (a *auditLog) Append(_ context.Context, _, _, action string, _ map[string]any) error {
	a.actions = append(a.actions, action)
	return nil
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
	}
	g := Guard{StepUp: access.StepUpPolicy{MaxAge: 5 * time.Minute, ACR: access.ACRMFA}, Audit: log}
	r := gin.New()
	api := r.Group("/api/v1", RequestID(), auth.Required())
	ok := func(c *gin.Context) { c.JSON(200, gin.H{"success": true}) }
	api.GET("/templates", g.Require(access.PermTemplatesRead), ok)
	api.POST("/templates/:id/publish", g.Require(access.PermTemplatesPublish), ok)
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
