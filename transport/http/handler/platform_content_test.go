package handler

// ADR 0001 rule A4: until the lockbox ships, the platform plane never
// returns tenant content (a message's subject, recipients, body or
// attachments, a mailbox's contents, a tenant's templates or provider
// credentials, personal data beyond tenant metadata). These tests pin
// what each platform route may answer. A new route, a new response field
// or a new import fails here until it is reviewed against the rule and
// added on purpose.

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/platform"
	"github.com/razatechofficial/mail-os/domain/platformrole"
)

// platformResponseFields is every route of /api/platform/v1 behind a
// platform token and the JSON paths its data may carry ("[]" an array's
// elements). None is tenant content: tenants are an id, a state and
// counts; connectors and templates are MailOS's own catalogue and platform
// defaults; /me is the caller's own account.
var platformResponseFields = map[string][]string{
	"GET /api/platform/v1/me": {"subject", "email", "roles", "roles[]", "roles[].role", "roles[].expires_at",
		"eligible", "eligible[]", "permissions", "permissions[]"},
	"GET /api/platform/v1/tenants": {"items", "items[]", "items[].id", "items[].active", "items[].created_at",
		"items[].applications", "items[].domains", "items[].messages_30d", "next_cursor"},
	"GET /api/platform/v1/connectors": {"items", "items[]", "items[].kind", "items[].name",
		"items[].tracking_off_supported", "items[].platform_relay", "items[].configured"},
	"GET /api/platform/v1/templates": {"items", "items[]", "items[].topic", "items[].name", "items[].auth_class",
		"items[].variables", "items[].variables[]", "items[].variables[].name", "items[].variables[].kind"},
	// The platform default of an IAM topic, from MailOS's code: never a
	// tenant's override.
	"GET /api/platform/v1/templates/:topic": {"topic", "name", "auth_class", "variables", "variables[]",
		"variables[].name", "variables[].kind", "subject", "html", "text"},
}

// jsonPaths lists every key path in v.
func jsonPaths(prefix string, v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			out[p] = true
			jsonPaths(p, child, out)
		}
	case []any:
		for _, child := range x {
			out[prefix+"[]"] = true
			jsonPaths(prefix+"[]", child, out)
		}
	}
}

// Every platform route is in the allowlist, and every one answers only
// allowlisted fields, with an owner (every view permission) reading a
// tenant that has applications, domains and messages.
func TestPlatformRoutesReturnOnlyAllowlistedFields(t *testing.T) {
	items := []platform.TenantAggregate{{ID: uuid.NewString(), Active: true, CreatedAt: time.Now(), Applications: 2, Domains: 1, Messages30d: 7}}
	e := platformEngine(t, items)
	ctx := context.Background()
	if err := e.roles.AddEligibility(ctx, platformSubject, platformrole.Owner); err != nil {
		t.Fatal(err)
	}
	if err := e.roles.Activate(ctx, platformSubject, platformrole.Owner, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}

	var mounted []string
	for _, rt := range e.r.Routes() {
		if strings.HasPrefix(rt.Path, "/api/platform/v1/") && rt.Path != RoleAttestationsPath {
			mounted = append(mounted, rt.Method+" "+rt.Path)
		}
	}
	sort.Strings(mounted)
	var allowed []string
	for k := range platformResponseFields {
		allowed = append(allowed, k)
	}
	sort.Strings(allowed)
	if !slices.Equal(mounted, allowed) {
		t.Fatalf("platform routes %v, allowlisted %v: review a new route against ADR 0001 rule A4 (no tenant content) "+
			"and list its response fields here", mounted, allowed)
	}

	for route, fields := range platformResponseFields {
		method, path, _ := strings.Cut(route, " ")
		path = strings.Replace(path, ":topic", "iam.auth.password_reset_requested", 1)
		w := do(e.r, method, path, nil)
		var body struct {
			Data any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK || body.Data == nil {
			t.Fatalf("%s: %d %s", route, w.Code, w.Body)
		}
		got := map[string]bool{}
		jsonPaths("", body.Data, got)
		if len(got) == 0 {
			t.Fatalf("%s: no fields in %s", route, w.Body)
		}
		for p := range got {
			if !slices.Contains(fields, p) {
				t.Errorf("%s answers %q, which is not allowlisted: is it tenant content (ADR 0001 rule A4)?", route, p)
			}
		}
	}
}

// The platform handler reaches data only through the platform read service
// and ACS: its imports are pinned, so it cannot start reading a tenant's
// messages, attachments, templates or providers without this test
// changing.
func TestPlatformHandlerImportsNoTenantStore(t *testing.T) {
	allowed := []string{
		"context", "time", "github.com/gin-gonic/gin",
		"github.com/razatechofficial/mail-os/application/platform",
		"github.com/razatechofficial/mail-os/domain/platformrole",
		"github.com/razatechofficial/mail-os/pkg/errors",
		"github.com/razatechofficial/mail-os/transport/http/middleware",
		"github.com/razatechofficial/mail-os/transport/http/response",
	}
	f, err := parser.ParseFile(token.NewFileSet(), "platform.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if !slices.Contains(allowed, path) {
			t.Errorf("platform.go imports %s: review it against ADR 0001 rule A4 (no tenant content) before allowing it", path)
		}
	}
}
