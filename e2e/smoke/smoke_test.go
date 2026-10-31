//go:build e2e

// Package smoke proves the harness and the stack: the server is live and
// ready, the API refuses a call without a token, and the fake IAM mints a
// token the server accepts.
package smoke

import (
	"net/http"
	"testing"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "smoke", &fx) }

func TestHealthAndReadiness(t *testing.T) {
	c := fx.Env.NewClient()
	c.Expect(t, http.StatusOK, http.MethodGet, "/health", nil)
	c.Expect(t, http.StatusOK, http.MethodGet, "/ready", nil)
}

func TestAPIRefusesCallWithoutToken(t *testing.T) {
	fx.Env.NewClient().ExpectError(t, http.StatusUnauthorized, "", http.MethodGet, "/api/v1/templates", nil)
}

func TestAPIRefusesForgedToken(t *testing.T) {
	tok, _ := fx.Env.UserToken(t, harness.User{Tenant: fx.TenantID, Roles: []string{harness.RoleAdmin}})
	forged := tok[:len(tok)-4] + "AAAA"
	fx.Env.NewClient().WithBearer(forged).ExpectError(t, http.StatusUnauthorized, "", http.MethodGet, "/api/v1/templates", nil)
}

func TestAdminTokenIsAccepted(t *testing.T) {
	fx.Admin(t).Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates", nil)
}
