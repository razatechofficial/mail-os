//go:build e2e

// Package flows drives MailOS end to end through the real server and worker
// binaries: a template is designed and published by console users, IAM
// publishes an event with a service token, the worker renders the published
// version and the mail arrives; OTPs stay masked in console views, bodies
// need step-up, four-eyes holds, and service callers are scoped.
package flows

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "flows", &fx) }

const (
	iamClient = "mailos-iam"
	otpTopic  = "iam.auth.mfa_email_code_requested"
)

// publishTemplate creates a template for topic, saves an en draft and
// publishes it as admin, and returns the template id.
func publishTemplate(t *testing.T, topic, slug string) string {
	t.Helper()
	admin := fx.Admin(t)
	tpl := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{
		"name": "Sign-in code", "slug": slug, "topic": topic, "default_locale": "en",
	}).Data()
	id := harness.Str(tpl, "id")
	draft := admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": 0, "subject": "Your sign-in code",
		"html_body": `<!doctype html><html><body><p>Your code is <strong>{{ code }}</strong></p><script>alert(1)</script></body></html>`,
		"text_body": "Your code is {{code}}", "variables": []string{"code"}, "design": nil,
	}).Data()
	if strings.Contains(harness.Str(draft, "html_body"), "<script") {
		t.Fatal("stored HTML was not sanitised")
	}
	admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{
		"locale": "en", "revision": draft["revision"],
	})
	return id
}

func TestEventRendersPublishedTemplateAndMasksOTP(t *testing.T) {
	publishTemplate(t, otpTopic, "otp-"+harness.Unique())
	box := fx.Env.NewMailbox("otp")
	res := fx.Service(t, iamClient).Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", map[string]any{
		"id": harness.NewID(), "type": otpTopic, "source": "iam",
		"data": map[string]any{"email": box.Address, "code": "482913", "purpose": "sign_in", "expires_in_minutes": 10},
	}).Data()
	msgID := harness.Str(res, "delivery_id")
	mail := box.WaitSubject(t, "Your sign-in code")
	if !strings.Contains(mail.HTML, "482913") || !strings.Contains(mail.Text, "482913") || strings.Contains(mail.HTML, "<script") {
		t.Fatalf("delivered mail: %s", mail.JSON())
	}

	operator, _ := fx.NewUser(t, harness.RoleOperator)
	view := operator.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+msgID, nil)
	if strings.Contains(view.String(), "482913") {
		t.Fatalf("console view shows the OTP: %s", view)
	}
	viewer, _ := fx.NewUser(t, harness.RoleViewer)
	viewer.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodGet, "/api/v1/messages/"+msgID+"/body", nil)
	stale := fx.As(t, harness.User{Roles: []string{harness.RoleOperator}, AuthAge: 10 * time.Minute})
	r := stale.ExpectError(t, http.StatusForbidden, "STEP_UP_REQUIRED", http.MethodGet, "/api/v1/messages/"+msgID+"/body", nil)
	if !strings.Contains(r.Header.Get("WWW-Authenticate"), `error="insufficient_user_authentication"`) {
		t.Fatalf("no RFC 9470 challenge: %q", r.Header.Get("WWW-Authenticate"))
	}
	body := operator.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+msgID+"/body", nil)
	if strings.Contains(body.String(), "482913") || !strings.Contains(body.String(), "Your code is") {
		t.Fatalf("body view: %s", body)
	}
	audit := fx.Admin(t).Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs?resource=message", nil)
	if !strings.Contains(audit.String(), "message.body_viewed") {
		t.Fatalf("body read not audited: %s", audit)
	}
}

func TestDuplicateEventSendsOnce(t *testing.T) {
	topic := "iam.auth.magic_link_requested"
	publishTemplate(t, topic, "link-"+harness.Unique())
	box := fx.Env.NewMailbox("link")
	ev := map[string]any{"id": harness.NewID(), "type": topic, "source": "iam",
		"data": map[string]any{"email": box.Address, "link": "https://iam.example.com/m/abc"}}
	svc := fx.Service(t, iamClient)
	svc.Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", ev)
	dup := svc.Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", ev).Data()
	if dup["duplicate"] != true {
		t.Fatalf("second delivery not a duplicate: %v", dup)
	}
	box.WaitSubject(t, "Your sign-in code")
	time.Sleep(2 * time.Second)
	if n := len(box.Messages(t)); n != 1 {
		t.Fatalf("%d messages for one event", n)
	}
}

func TestServiceCallersAreScoped(t *testing.T) {
	ev := func(tenant string) map[string]any {
		return map[string]any{"id": harness.NewID(), "type": otpTopic, "tenant_uuid": tenant,
			"data": map[string]any{"email": harness.NewEmail("x"), "code": "1", "purpose": "sign_in", "expires_in_minutes": 1}}
	}
	fx.Service(t, "intruder").ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/events", ev(""))
	fx.Service(t, iamClient).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/events", ev(harness.NewID()))
	fx.Admin(t).ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/events", ev(""))
	fx.Service(t, iamClient).ExpectError(t, http.StatusForbidden, "", http.MethodGet, "/api/v1/templates", nil)
}

func TestFourEyesPublishing(t *testing.T) {
	admin := fx.Admin(t)
	admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/tenant/settings", map[string]any{"four_eyes_publish": true})
	defer fx.Admin(t).Expect(t, http.StatusOK, http.MethodPut, "/api/v1/tenant/settings", map[string]any{"four_eyes_publish": false})

	tpl := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{"name": "Notice", "slug": "notice-" + harness.Unique()}).Data()
	id := harness.Str(tpl, "id")
	both, _ := fx.NewUser(t, harness.RoleTemplateEditor, harness.RoleTemplatePublisher)
	draft := both.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": 0, "subject": "Notice", "html_body": "<p>Hello</p>", "text_body": "Hello", "design": nil,
	}).Data()
	publish := map[string]any{"locale": "en", "revision": draft["revision"]}
	both.ExpectError(t, http.StatusForbidden, "FOUR_EYES_REQUIRED", http.MethodPost, "/api/v1/templates/"+id+"/publish", publish)
	other, _ := fx.NewUser(t, harness.RoleTemplatePublisher)
	other.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", publish)
	editor, _ := fx.NewUser(t, harness.RoleTemplateEditor)
	editor.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/templates/"+id+"/publish", publish)
}
