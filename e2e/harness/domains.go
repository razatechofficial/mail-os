//go:build e2e

package harness

import (
	"net/http"
	"strings"
)

// PublishDNS sets the TXT values at name in the server's stand-in DNS zone
// (the e2e hook), as a domain's owner publishes records.
func (e *Env) PublishDNS(t T, name string, values ...string) {
	t.Helper()
	e.NewClient().WithBearer(e.HookToken).Expect(t, http.StatusNoContent, http.MethodPut, "/e2e/v1/dns",
		map[string]any{"name": name, "values": values})
}

// VerifiedDomain adds a sending domain to the package's tenant, publishes
// the SPF, DKIM and DMARC records it asks for, verifies it, and returns
// its name.
func (f *Fixture) VerifiedDomain(t T) string {
	t.Helper()
	admin := f.Admin(t)
	name := "send-" + strings.ToLower(Unique()) + ".mailos.test"
	d := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/sending-domains", map[string]any{"domain": name}).Data()
	records, _ := d["records"].([]any)
	for _, r := range records {
		rec, _ := r.(map[string]any)
		f.Env.PublishDNS(t, Str(rec, "name"), Str(rec, "value"))
	}
	v := admin.Expect(t, http.StatusOK, http.MethodPost, "/api/v1/sending-domains/"+Str(d, "id")+"/verify", nil).Data()
	if Str(v, "status") != "verified" {
		t.Fatalf("domain %s not verified: %v", name, v)
	}
	return name
}
