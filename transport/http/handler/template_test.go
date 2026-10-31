package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/application/template/templatetest"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

const (
	tenantA = "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"
	tenantB = "7a2d4d4f-7b49-4b9a-8b6a-3c0e4c7b9b21"
)

type okTenants struct{}

func (okTenants) Ensure(context.Context, string) error { return nil }

type noAudit struct{}

func (noAudit) Append(context.Context, string, string, string, map[string]any) error { return nil }

type noReplay struct{}

func (noReplay) ClaimOnce(context.Context, string, time.Duration) (bool, error) { return true, nil }

// counter is an in-memory WindowCounter.
type counter struct {
	mu sync.Mutex
	n  map[string]int64
}

func (c *counter) CountWindow(_ context.Context, key string, _ time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[key]++
	return c.n[key], nil
}

type templateAPI struct {
	t        *testing.T
	iam      *fakeiam.IAM
	r        *gin.Engine
	settings *templatetest.Settings
	audit    *templatetest.Audit
}

func newTemplateAPI(t *testing.T, rawHTML bool) *templateAPI {
	t.Helper()
	gin.SetMode(gin.TestMode)
	iam, _ := fakeiam.NewServer(t)
	settings, audit := &templatetest.Settings{}, &templatetest.Audit{}
	svc := apptemplate.New(apptemplate.Deps{Repo: templatetest.NewRepository(), Settings: settings, Audit: audit, RawHTMLBlocks: rawHTML})
	auth := &middleware.Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"}),
		DPoP: dpop.NewVerifier(noReplay{}, time.Minute), Tenants: okTenants{}, Audit: noAudit{}}
	g := middleware.Guard{StepUp: access.StepUpPolicy{MaxAge: 5 * time.Minute, ACR: access.ACRMFA}, Audit: noAudit{}}
	r := gin.New()
	api := r.Group("/api/v1", middleware.RequestID(), auth.Required())
	NewTemplateHandler(svc, &counter{n: map[string]int64{}}, TemplateLimits{PreviewPerMinute: 2, TestSendPerHour: 1}).Mount(api, g)
	return &templateAPI{t: t, iam: iam, r: r, settings: settings, audit: audit}
}

func (a *templateAPI) token(tenant, subject string, roles ...string) string {
	return a.iam.UserToken(fakeiam.User{Tenant: tenant, Subject: subject, Roles: roles})
}

type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Meta    json.RawMessage `json:"meta"`
	Error   struct {
		Code    string                         `json:"code"`
		Details []struct{ Field, Code string } `json:"details"`
	} `json:"error"`
}

func (a *templateAPI) do(method, path, token string, body any) (int, envelope) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.r.ServeHTTP(w, req)
	var env envelope
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	return w.Code, env
}

func (a *templateAPI) expect(method, path, token string, body any, status int, code string) envelope {
	a.t.Helper()
	got, env := a.do(method, path, token, body)
	if got != status || env.Error.Code != code {
		a.t.Fatalf("%s %s: %d %q, want %d %q (%+v)", method, path, got, env.Error.Code, status, code, env.Error)
	}
	return env
}

func decode[T any](t *testing.T, raw json.RawMessage) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

const (
	editorID    = "0b6c1c3e-6a38-4a8f-9a59-2b9d3b6a8a11"
	publisherID = "1c7d2d4f-7b49-4b9a-8b6a-3c0e4c7b9b22"
)

var draftBody = map[string]any{"locale": "en", "revision": 0, "subject": "Notice for {{user.name}}",
	"html_body": "<p>Hello {{user.name}}</p>", "text_body": "Hello {{user.name}}", "variables": []string{"user.name", "order.id"}, "design": nil}

func TestTemplateRolesAndStepUp(t *testing.T) {
	a := newTemplateAPI(t, false)
	viewer := a.token(tenantA, "", "mailos_viewer")
	ed := a.token(tenantA, editorID, "mailos_template_editor")
	pub := a.token(tenantA, publisherID, "mailos_template_publisher")
	admin := a.token(tenantA, "", "mailos_admin")

	a.expect("POST", "/api/v1/templates", viewer, map[string]any{"name": "x", "slug": "x"}, 403, "FORBIDDEN")
	env := a.expect("POST", "/api/v1/templates", ed, map[string]any{"name": "Notice", "slug": "notice", "topic": "iam.account.security_notice"}, 201, "")
	tpl := decode[map[string]any](t, env.Data)
	id := tpl["id"].(string)
	if tpl["default_locale"] != "en" || tpl["org_id"] != tenantA || tpl["topic"] != "iam.account.security_notice" {
		t.Fatalf("template: %v", tpl)
	}
	a.expect("GET", "/api/v1/templates/"+id, viewer, nil, 200, "")
	list := a.expect("GET", "/api/v1/templates?page=1&limit=10", viewer, nil, 200, "")
	if meta := decode[map[string]any](t, list.Meta); meta["total_items"] != float64(1) {
		t.Fatalf("list meta: %s", list.Meta)
	}
	a.expect("PUT", "/api/v1/templates/"+id+"/draft", viewer, draftBody, 403, "FORBIDDEN")
	a.expect("PUT", "/api/v1/templates/"+id+"/draft", pub, draftBody, 403, "FORBIDDEN")
	env = a.expect("PUT", "/api/v1/templates/"+id+"/draft", ed, draftBody, 200, "")
	d := decode[map[string]any](t, env.Data)
	if d["revision"] != float64(1) || d["design"] != nil || d["updated_by"] != editorID {
		t.Fatalf("draft: %v", d)
	}
	if w := decode[map[string][]map[string]string](t, env.Meta)["warnings"]; len(w) != 1 || w[0]["code"] != "unknown_variable" {
		t.Fatalf("warnings: %s", env.Meta)
	}
	a.expect("PUT", "/api/v1/templates/"+id+"/draft", ed, draftBody, 409, "CONFLICT")

	publish := map[string]any{"locale": "en", "revision": 1}
	a.expect("POST", "/api/v1/templates/"+id+"/publish", ed, publish, 403, "FORBIDDEN")
	stale := a.iam.UserToken(fakeiam.User{Tenant: tenantA, Subject: publisherID, Roles: []string{"mailos_template_publisher"}, AuthAge: 10 * time.Minute})
	a.expect("POST", "/api/v1/templates/"+id+"/publish", stale, publish, 403, "STEP_UP_REQUIRED")

	a.settings.FourEyes = true
	ownAdmin := a.token(tenantA, editorID, "mailos_admin")
	a.expect("POST", "/api/v1/templates/"+id+"/publish", ownAdmin, publish, 403, "FOUR_EYES_REQUIRED")
	a.expect("POST", "/api/v1/templates/"+id+"/publish", pub, map[string]any{"locale": "en", "revision": 7}, 409, "CONFLICT")
	env = a.expect("POST", "/api/v1/templates/"+id+"/publish", pub, publish, 201, "")
	v := decode[map[string]any](t, env.Data)
	if v["version"] != float64(1) || v["status"] != "published" || v["is_active"] != true || v["published_by"] != publisherID {
		t.Fatalf("version: %v", v)
	}
	if action, meta := a.audit.Last(); action != "template.published" || meta["locale"] != "en" {
		t.Fatalf("audit: %s %v", action, meta)
	}
	a.expect("GET", "/api/v1/templates/"+id+"/active-version", viewer, nil, 200, "")
	a.expect("GET", "/api/v1/templates/"+id+"/active-version?locale=ur", viewer, nil, 404, "NOT_FOUND")
	versions := decode[[]map[string]any](t, a.expect("GET", "/api/v1/templates/"+id+"/versions?locale=en", viewer, nil, 200, "").Data)
	if len(versions) != 1 {
		t.Fatalf("versions: %v", versions)
	}
	env = a.expect("POST", "/api/v1/templates/"+id+"/versions/1/restore", ed, map[string]any{"locale": "en", "revision": 1}, 200, "")
	if decode[map[string]any](t, env.Data)["revision"] != float64(2) {
		t.Fatalf("restore: %s", env.Data)
	}
	a.expect("POST", "/api/v1/templates/"+id+"/versions/x/restore", ed, map[string]any{"revision": 2}, 404, "NOT_FOUND")

	a.expect("DELETE", "/api/v1/templates/"+id, ed, nil, 403, "FORBIDDEN")
	a.expect("DELETE", "/api/v1/templates/"+id, admin, nil, 204, "")
	a.expect("GET", "/api/v1/templates/"+id, viewer, nil, 404, "NOT_FOUND")
}

func TestTemplateOtherTenantIsNotFound(t *testing.T) {
	a := newTemplateAPI(t, false)
	ed := a.token(tenantA, editorID, "mailos_template_editor")
	id := decode[map[string]any](t, a.expect("POST", "/api/v1/templates", ed, map[string]any{"name": "N", "slug": "n"}, 201, "").Data)["id"].(string)
	b := a.token(tenantB, "", "mailos_admin")
	for _, c := range []struct{ method, path string }{
		{"GET", "/templates/" + id}, {"PUT", "/templates/" + id}, {"DELETE", "/templates/" + id},
		{"GET", "/templates/" + id + "/draft"}, {"PUT", "/templates/" + id + "/draft"}, {"GET", "/templates/" + id + "/versions"},
		{"GET", "/templates/" + id + "/active-version"}, {"POST", "/templates/" + id + "/preview"},
	} {
		body := map[string]any{}
		if c.path == "/templates/"+id+"/draft" && c.method == "PUT" {
			body = draftBody
		}
		if c.path == "/templates/"+id+"/preview" {
			body = map[string]any{"subject": "s", "html_body": "<p>x</p>", "text_body": "x"}
		}
		a.expect(c.method, "/api/v1"+c.path, b, body, 404, "NOT_FOUND")
	}
}

func TestTemplateRawHTMLNeedsAdminAndFlag(t *testing.T) {
	body := map[string]any{"locale": "en", "revision": 0, "subject": "s", "html_body": "<p>x</p>", "text_body": "x",
		"design": map[string]any{"type": "email", "content": []any{map[string]any{"type": "html", "attrs": map[string]any{"html": "<b>x</b>"}}}}}
	a := newTemplateAPI(t, true)
	ed := a.token(tenantA, editorID, "mailos_template_editor")
	admin := a.token(tenantA, "", "mailos_admin")
	id := decode[map[string]any](t, a.expect("POST", "/api/v1/templates", admin, map[string]any{"name": "N", "slug": "n"}, 201, "").Data)["id"].(string)
	env := a.expect("PUT", "/api/v1/templates/"+id+"/draft", ed, body, 422, "VALIDATION")
	if len(env.Error.Details) != 1 || env.Error.Details[0].Code != "raw_html_not_allowed" || env.Error.Details[0].Field != "design.content[0]" {
		t.Fatalf("editor raw html: %+v", env.Error)
	}
	a.expect("PUT", "/api/v1/templates/"+id+"/draft", admin, body, 200, "")

	off := newTemplateAPI(t, false)
	admin = off.token(tenantA, "", "mailos_admin")
	id = decode[map[string]any](t, off.expect("POST", "/api/v1/templates", admin, map[string]any{"name": "N", "slug": "n"}, 201, "").Data)["id"].(string)
	off.expect("PUT", "/api/v1/templates/"+id+"/draft", admin, body, 422, "VALIDATION")
}

func TestTemplatePreviewAndTestSendLimits(t *testing.T) {
	a := newTemplateAPI(t, false)
	ed := a.token(tenantA, editorID, "mailos_template_editor")
	id := decode[map[string]any](t, a.expect("POST", "/api/v1/templates", ed, map[string]any{"name": "N", "slug": "n", "topic": "iam.auth.mfa_email_code_requested"}, 201, "").Data)["id"].(string)
	preview := map[string]any{"subject": "Code {{code}}", "html_body": "<p>{{code}} {{email}}</p>", "text_body": "{{code}}"}
	out := decode[map[string]string](t, a.expect("POST", "/api/v1/templates/"+id+"/preview", ed, preview, 200, "").Data)
	if out["html"] != "<p>•••••• amna@example.com</p>" || out["subject"] != "Code ••••••" {
		t.Fatalf("preview: %v", out)
	}
	a.expect("POST", "/api/v1/templates/"+id+"/preview", ed, preview, 200, "")
	a.expect("POST", "/api/v1/templates/"+id+"/preview", ed, preview, 429, "RATE_LIMITED")
	// The limit is per user.
	other := a.token(tenantA, publisherID, "mailos_template_editor")
	a.expect("POST", "/api/v1/templates/"+id+"/preview", other, preview, 200, "")

	send := map[string]any{"locale": "en", "to_email": "qa@example.com", "from_name": "A", "from_email": "a@example.com"}
	a.expect("POST", "/api/v1/templates/"+id+"/test-send", ed, send, 503, "SERVICE_UNAVAILABLE")
	a.expect("POST", "/api/v1/templates/"+id+"/test-send", ed, send, 429, "RATE_LIMITED")
}

func TestTemplateTopicsAndBranding(t *testing.T) {
	a := newTemplateAPI(t, false)
	viewer := a.token(tenantA, "", "mailos_viewer")
	ed := a.token(tenantA, editorID, "mailos_template_editor")
	admin := a.token(tenantA, "", "mailos_admin")
	topics := decode[[]map[string]any](t, a.expect("GET", "/api/v1/template-topics", viewer, nil, 200, "").Data)
	if len(topics) < 12 || topics[0]["topic"] == "" || topics[0]["source"] != "iam" {
		t.Fatalf("topics: %v", topics[0])
	}
	b := decode[map[string]any](t, a.expect("GET", "/api/v1/template-branding", viewer, nil, 200, "").Data)
	if b["primary_color"] != "#2563eb" || b["updated_at"] != nil {
		t.Fatalf("default branding: %v", b)
	}
	in := map[string]any{"company_name": "Averox", "primary_color": "#111111", "font_family": "Georgia"}
	a.expect("PUT", "/api/v1/template-branding", ed, in, 403, "FORBIDDEN")
	b = decode[map[string]any](t, a.expect("PUT", "/api/v1/template-branding", admin, in, 200, "").Data)
	if b["company_name"] != "Averox" || b["background_color"] != "#f1f5f9" || b["updated_at"] == nil {
		t.Fatalf("saved branding: %v", b)
	}
	env := a.expect("PUT", "/api/v1/template-branding", admin, map[string]any{"primary_color": "red", "logo_url": "http://x"}, 422, "VALIDATION")
	if len(env.Error.Details) != 2 {
		t.Fatalf("branding validation: %+v", env.Error)
	}
	if _, env := a.do("PUT", "/api/v1/template-branding", admin, nil); env.Error.Code != "BAD_REQUEST" {
		t.Fatalf("empty body: %+v", env.Error)
	}
}
