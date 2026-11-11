package handler

import (
	"net/http"
	"testing"

	"github.com/razatechofficial/mail-os/domain/access"
)

// The encryption keys belong to the deployment, so only the operator
// tenant's administrators reach the key routes; with no operator tenant
// configured nobody does. The refusal comes before the handler runs.
func TestKeyRoutesAreTheOperatorTenantsOnly(t *testing.T) {
	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/keys/encryption"},
		{http.MethodPost, "/api/v1/keys/encryption/provider/rotate"},
		{http.MethodGet, "/api/v1/keys/kek"},
		{http.MethodPost, "/api/v1/keys/kek/rotate"},
	}
	for _, operator := range []string{"", "0192f0c4-0000-7000-8000-0000000000ff"} {
		h := NewTenantHandler(nil, nil, nil).WithOperatorTenant(operator)
		r := engine(t, h, []access.Role{access.RoleAdmin}, 0, access.ACRMFA)
		for _, rt := range routes {
			if w := do(r, rt.method, rt.path, nil); w.Code != http.StatusForbidden {
				t.Errorf("operator %q: %s %s = %d, want 403", operator, rt.method, rt.path, w.Code)
			}
		}
	}
}
