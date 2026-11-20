package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	appprovider "github.com/razatechofficial/mail-os/application/provider"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domainprovider "github.com/razatechofficial/mail-os/domain/provider"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

const testTenant = "0192f0c4-0000-7000-8000-000000000001"

// fakeMsgRepo serves one message; other methods are not used here.
type fakeMsgRepo struct {
	appmsg.Repository
	m domainmsg.Message
}

func (r fakeMsgRepo) Get(_ context.Context, tenantID, id string) (domainmsg.Message, error) {
	if id != r.m.ID || tenantID != r.m.OrgID {
		return domainmsg.Message{}, apperrors.NotFound("message not found")
	}
	return r.m, nil
}

func (r fakeMsgRepo) List(context.Context, appmsg.Filter) ([]domainmsg.Message, int, error) {
	return []domainmsg.Message{r.m}, 1, nil
}

type recAudit struct{ actions []string }

func (a *recAudit) Append(_ context.Context, _, _, action string, _ map[string]any) error {
	a.actions = append(a.actions, action)
	return nil
}

func (a *recAudit) Change(_ context.Context, _, _, action string, _, _ any, _ map[string]any) error {
	a.actions = append(a.actions, action)
	return nil
}

type nopTenants struct{}

func (nopTenants) Ensure(context.Context, string) error { return nil }
func (nopTenants) Settings(context.Context, string) (domaintenant.Settings, error) {
	return domaintenant.Settings{}, nil
}

// engine mounts routes behind a principal with roles, signed in authAge ago
// with acr.
func engine(t *testing.T, routes interface {
	Mount(*gin.RouterGroup, middleware.Guard)
}, roles []access.Role, authAge time.Duration, acr string) *gin.Engine {
	t.Helper()
	_ = logger.InitSimple("fatal", "console")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := r.Group("/api/v1", func(c *gin.Context) {
		p := access.Principal{Kind: access.KindUser, Subject: "0192f0c4-0000-7000-8000-0000000000aa", TenantID: testTenant,
			Roles: roles, ACR: acr, AuthTime: time.Now().Add(-authAge)}
		c.Request = c.Request.WithContext(access.WithPrincipal(c.Request.Context(), p))
	})
	routes.Mount(api, middleware.Guard{StepUp: access.StepUpPolicy{MaxAge: 5 * time.Minute, ACR: access.ACRMFA}})
	return r
}

func do(r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// redactedCode is how a stored authentication message holds its code.
const redactedCode = "[redacted: code, 6 characters]"

func otpMessage() domainmsg.Message {
	return domainmsg.Message{ID: "m1", OrgID: testTenant, ToEmail: "ana@example.com", Subject: "Code " + redactedCode,
		HTMLBody: "<p>" + redactedCode + "</p>", Type: domainmsg.TypeTransactional, Status: domainmsg.StatusSent,
		Topic: domaintemplate.TopicMFAEmailCode, TemplateData: map[string]any{"code": redactedCode}, SecretKeys: []string{"code"},
		CreatedAt: time.Now()}
}

func messageHandler(a *recAudit) *MessageHandler {
	return NewMessageHandler(appmsg.NewService(appmsg.Deps{Repo: fakeMsgRepo{m: otpMessage()}, Tenants: nopTenants{}, Audit: a}, appmsg.Config{}), nil, nil)
}

func TestBodyNeedsRoleAndStepUp(t *testing.T) {
	a := &recAudit{}
	h := messageHandler(a)
	// A viewer never reads bodies, however fresh the sign-in.
	if w := do(engine(t, h, []access.Role{access.RoleViewer}, time.Minute, access.ACRMFA), "GET", "/api/v1/messages/m1/body", nil); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "STEP_UP") {
		t.Fatalf("viewer: %d %s", w.Code, w.Body)
	}
	// An auditor with an old sign-in is asked to step up.
	w := do(engine(t, h, []access.Role{access.RoleAuditor}, time.Hour, access.ACRMFA), "GET", "/api/v1/messages/m1/body", nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "STEP_UP_REQUIRED") || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("stale auditor: %d %s", w.Code, w.Body)
	}
	if len(a.actions) != 0 {
		t.Fatal("a refused read was audited as viewed")
	}
	w = do(engine(t, h, []access.Role{access.RoleAuditor}, time.Minute, access.ACRMFA), "GET", "/api/v1/messages/m1/body", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "[redacted: code") || a.actions[0] != "message.body_viewed" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("fresh auditor: %d %s %v", w.Code, w.Body, a.actions)
	}
}

func TestMessageGetAndListHideBodiesAndSecrets(t *testing.T) {
	r := engine(t, messageHandler(&recAudit{}), []access.Role{access.RoleViewer}, time.Hour, access.ACRPassword)
	for _, path := range []string{"/api/v1/messages/m1", "/api/v1/messages"} {
		w := do(r, "GET", path, nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"auth_class":true`) ||
			!strings.Contains(w.Body.String(), "[redacted: code") || strings.Contains(w.Body.String(), "html_body") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	// Authentication mail is never resent, by any role.
	op := engine(t, messageHandler(&recAudit{}), []access.Role{access.RoleAdmin}, time.Minute, access.ACRMFA)
	if w := do(op, "POST", "/api/v1/messages/m1/resend", nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "fresh code") {
		t.Fatalf("resend: %d %s", w.Code, w.Body)
	}
	if w := do(r, "POST", "/api/v1/messages/send", map[string]any{"to_email": "a@example.com"}); w.Code != http.StatusForbidden {
		t.Fatalf("viewer sent mail: %d", w.Code)
	}
}

// fakeProviderRepo keeps one provider.
type fakeProviderRepo struct {
	appprovider.Repository
	rows map[string]appprovider.Stored
}

func (r *fakeProviderRepo) Create(_ context.Context, s appprovider.Stored) error {
	r.rows[s.Provider.ID] = s
	return nil
}

func (r *fakeProviderRepo) Get(_ context.Context, _, id string) (appprovider.Stored, error) {
	return r.rows[id], nil
}

func (r *fakeProviderRepo) SetLastTest(_ context.Context, _, id string, t domainprovider.LastTest) error {
	s := r.rows[id]
	s.Provider.LastTest = &t
	r.rows[id] = s
	return nil
}

// okTester passes every test.
type okTester struct{}

func (okTester) Test(context.Context, domainprovider.Provider, domainprovider.Credentials) domainprovider.Diagnosis {
	return domainprovider.Diagnosis{OK: true, Kind: domainprovider.TestConnection, Steps: []domainprovider.Step{{Name: "auth", OK: true}}}
}

func (okTester) Send(context.Context, domainprovider.Provider, domainprovider.Credentials, domainmsg.Outgoing) domainprovider.Diagnosis {
	return domainprovider.Diagnosis{OK: true, Kind: domainprovider.TestSend}
}

type nopRecorder struct{}

func (nopRecorder) RecordProviderTest(context.Context, appprovider.TestMessage) error { return nil }

func TestProviderSchemaAndTests(t *testing.T) {
	repo := &fakeProviderRepo{rows: map[string]appprovider.Stored{}}
	svc := appprovider.NewService(repo, prefixCipher{}, &recAudit{}, appprovider.Config{})
	svc.SetTesting(okTester{}, nopRecorder{})
	h := NewProviderHandler(svc)
	viewer := engine(t, h, []access.Role{access.RoleViewer}, time.Hour, access.ACRPassword)
	w := do(viewer, "GET", "/api/v1/providers/schema", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"type":"msgraph"`) || strings.Contains(w.Body.String(), "None, plaintext (local and test only)") {
		t.Fatalf("schema: %d %.300s", w.Code, w.Body)
	}
	repo.rows["p1"] = appprovider.Stored{Provider: domainprovider.Provider{ID: "p1", Name: "SG", Kind: domainprovider.KindSendGrid,
		Settings: domainprovider.Settings{FromEmail: "noreply@bank.example"}}}
	if w := do(viewer, "POST", "/api/v1/providers/p1/test-connection", map[string]any{}); w.Code != http.StatusForbidden {
		t.Fatalf("viewer tested a provider: %d", w.Code)
	}
	// Testing a stored provider needs no step-up; testing a draft does.
	admin := engine(t, h, []access.Role{access.RoleAdmin}, time.Hour, access.ACRMFA)
	if w := do(admin, "POST", "/api/v1/providers/p1/test-connection", map[string]any{}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("test: %d %s", w.Code, w.Body)
	}
	if w := do(admin, "POST", "/api/v1/providers/p1/send-test", map[string]any{"to_email": "ops@bank.example"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"message_id"`) {
		t.Fatalf("send test: %d %s", w.Code, w.Body)
	}
	draft := map[string]any{"type": "sendgrid", "settings": map[string]any{}, "credentials": map[string]any{"api_key": "SG.draft-key"}}
	if w := do(admin, "POST", "/api/v1/providers/test-connection", draft); w.Code != http.StatusForbidden {
		t.Fatalf("draft tested without step-up: %d", w.Code)
	}
	fresh := engine(t, h, []access.Role{access.RoleAdmin}, time.Minute, access.ACRMFA)
	if w := do(fresh, "POST", "/api/v1/providers/test-connection", draft); w.Code != http.StatusOK {
		t.Fatalf("draft: %d %s", w.Code, w.Body)
	}
	draft["settings"] = map[string]any{"port": "587"}
	if w := do(fresh, "POST", "/api/v1/providers/test-connection", draft); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "settings.port") {
		t.Fatalf("bad draft: %d %s", w.Code, w.Body)
	}
}

type prefixCipher struct{}

func (prefixCipher) Seal(_ context.Context, p []byte) (string, error) {
	return "km1.kid00000.sealed", nil
}
func (prefixCipher) Open(context.Context, string) ([]byte, error) { return []byte(`{}`), nil }

func TestProviderCredentialsNeverReturnedAndStepUp(t *testing.T) {
	repo := &fakeProviderRepo{rows: map[string]appprovider.Stored{}}
	h := NewProviderHandler(appprovider.NewService(repo, prefixCipher{}, &recAudit{}, appprovider.Config{}))
	body := map[string]any{"name": "SG", "type": "sendgrid", "settings": map[string]any{}, "credentials": map[string]any{"api_key": "SG.very-secret-api-key-9876"}}
	if w := do(engine(t, h, []access.Role{access.RoleAdmin}, time.Hour, access.ACRMFA), "POST", "/api/v1/providers", body); w.Code != http.StatusForbidden {
		t.Fatalf("provider created without step-up: %d", w.Code)
	}
	if w := do(engine(t, h, []access.Role{access.RoleOperator}, time.Minute, access.ACRMFA), "POST", "/api/v1/providers", body); w.Code != http.StatusForbidden {
		t.Fatalf("operator created a provider: %d", w.Code)
	}
	w := do(engine(t, h, []access.Role{access.RoleAdmin}, time.Minute, access.ACRMFA), "POST", "/api/v1/providers", body)
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "very-secret") || !strings.Contains(w.Body.String(), `"has_credentials":true`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, s := range repo.rows {
		if s.Sealed != "km1.kid00000.sealed" || s.Provider.Settings != (domainprovider.Settings{Region: domainprovider.RegionGlobal}) {
			t.Fatalf("stored %+v", s)
		}
		w := do(engine(t, h, []access.Role{access.RoleViewer}, time.Hour, access.ACRPassword), "GET", "/api/v1/providers/"+s.Provider.ID, nil)
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "very-secret") || !strings.Contains(w.Body.String(), "…9876") {
			t.Fatalf("get: %d %s", w.Code, w.Body)
		}
	}
}
