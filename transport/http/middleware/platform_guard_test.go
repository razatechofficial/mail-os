package middleware

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/platformrole"
	"github.com/razatechofficial/mail-os/infrastructure/acs"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeacs"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

func guarded(t *testing.T) (*fakeiam.IAM, *fakeacs.ACS, acs.Platform, *gin.Engine, *auditLog) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	f, conn := fakeacs.Dial(t)
	roles := acs.Platform{Client: acs.New(conn, time.Second)}
	log := &auditLog{}
	g := PlatformGuard{ACS: roles, Audit: log}
	r := gin.New()
	api := r.Group("/api/platform/v1", (&PlatformAuth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}), SignIn: consoleSignIn}).Required())
	ok := func(c *gin.Context) { c.JSON(200, gin.H{"success": true}) }
	api.GET("/tenants", g.Require(platformrole.ViewTenants), ok)
	api.GET("/keys", g.Require(platformrole.ManageKeys), ok)
	return iam, f, roles, r, log
}

// Each request is checked in ACS: denied without an active role (403 with
// the contract's message, audited), allowed while the role is active,
// denied again once it expires; ACS down is 503.
func TestPlatformGuard(t *testing.T) {
	iam, f, roles, r, log := guarded(t)
	sub := "0d6f3a7e-5b1c-4c55-9f61-2f8f1c9b6a11"
	tok := iam.PlatformToken(fakeiam.PlatformUser{Subject: sub})
	now := time.Now()
	f.Now = func() time.Time { return now }

	w := call(r, "GET", "/api/platform/v1/tenants", tok)
	if w.Code != 403 || code(w) != "FORBIDDEN" || !strings.Contains(w.Body.String(), PlatformRoleMessage) {
		t.Fatalf("no role: %d %s", w.Code, w.Body)
	}
	if len(log.actions) != 1 || log.actions[0] != "access_denied" || log.reasons[0] != "platform_permission" {
		t.Fatalf("refusal not audited: %v %v", log.actions, log.reasons)
	}
	ctx := context.Background()
	if err := roles.AddEligibility(ctx, sub, platformrole.Support); err != nil {
		t.Fatal(err)
	}
	if w := call(r, "GET", "/api/platform/v1/tenants", tok); w.Code != 403 {
		t.Fatalf("eligible, not active: %d", w.Code)
	}
	if err := roles.Activate(ctx, sub, platformrole.Support, now.Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	if w := call(r, "GET", "/api/platform/v1/tenants", tok); w.Code != 200 {
		t.Fatalf("active support: %d %s", w.Code, w.Body)
	}
	if w := call(r, "GET", "/api/platform/v1/keys", tok); w.Code != 403 {
		t.Fatalf("support managing keys: %d", w.Code)
	}
	now = now.Add(time.Hour + time.Second)
	if w := call(r, "GET", "/api/platform/v1/tenants", tok); w.Code != 403 {
		t.Fatalf("expired activation: %d", w.Code)
	}
	f.SetUnavailable(true)
	if w := call(r, "GET", "/api/platform/v1/tenants", tok); w.Code != 503 {
		t.Fatalf("ACS down: %d %s", w.Code, w.Body)
	}
}

// Without ACS the platform API answers 503; a non-platform principal never
// reaches the check.
func TestPlatformGuardFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	r := gin.New()
	r.Group("/api/platform/v1", (&PlatformAuth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}), SignIn: consoleSignIn}).Required()).
		GET("/tenants", PlatformGuard{}.Require(platformrole.ViewTenants), func(c *gin.Context) { c.Status(200) })
	if w := call(r, "GET", "/api/platform/v1/tenants", iam.PlatformToken(fakeiam.PlatformUser{})); w.Code != 503 {
		t.Fatalf("no ACS: %d", w.Code)
	}
	r2 := gin.New()
	r2.GET("/x", PlatformGuard{}.Require(platformrole.ViewTenants), func(c *gin.Context) { c.Status(200) })
	if w := call(r2, "GET", "/x", ""); w.Code != 401 {
		t.Fatalf("no principal: %d", w.Code)
	}
}
