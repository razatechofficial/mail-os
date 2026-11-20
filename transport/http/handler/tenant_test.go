package handler

import (
	"net/http"
	"testing"

	"github.com/razatechofficial/mail-os/domain/access"
)

// The deployment's encryption keys are not on the tenant API: no tenant
// role reaches a key route (ADR 0001 §3.9, plan 0.18).
func TestNoKeyRoutesOnTheTenantAPI(t *testing.T) {
	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/keys/encryption"},
		{http.MethodPost, "/api/v1/keys/encryption/provider/rotate"},
		{http.MethodGet, "/api/v1/keys/kek"},
		{http.MethodPost, "/api/v1/keys/kek/rotate"},
	}
	r := engine(t, NewTenantHandler(nil, nil), []access.Role{access.RoleAdmin}, 0, access.ACRMFA)
	for _, rt := range routes {
		if w := do(r, rt.method, rt.path, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", rt.method, rt.path, w.Code)
		}
	}
}
