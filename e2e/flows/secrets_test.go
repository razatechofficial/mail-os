//go:build e2e

package flows

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

// canaryHookAddr is where the canary's webhook receiver listens.
const canaryHookAddr = "127.0.0.1:19885"

// e2eSinkKey is the e2e sink's Redis list: it holds the mail as sent, on
// purpose, so the test can read it, and is the only place a secret may be.
const e2eSinkKey = "mailos:e2e:captured"

// ensureTemplate publishes a template for topic with the given bodies
// unless the tenant already has one.
func ensureTemplate(t *testing.T, topic, subject, html, text string) {
	t.Helper()
	admin := fx.Admin(t)
	for _, it := range admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/templates?limit=100", nil).Items() {
		if harness.Str(it, "topic") == topic {
			return
		}
	}
	tpl := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates", map[string]any{
		"name": subject, "slug": "canary-" + harness.Unique(), "topic": topic, "default_locale": "en",
	}).Data()
	id := harness.Str(tpl, "id")
	draft := admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/templates/"+id+"/draft", map[string]any{
		"locale": "en", "revision": 0, "subject": subject, "html_body": html, "text_body": text, "design": nil,
	}).Data()
	admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/templates/"+id+"/publish", map[string]any{
		"locale": "en", "revision": draft["revision"],
	})
}

// TestNoLiveSecretAtRest is the persistence-masking canary (ADR 0001 §3.6,
// plan 0.21): IAM sends a sign-in code and a password-reset link; the
// recipient gets both in full, and afterwards no Postgres row, Redis key
// (but the test sink's), server or worker log line, or webhook payload
// holds either. The console sees the redaction descriptors, cannot resend,
// and the message carries its evidence digest.
func TestNoLiveSecretAtRest(t *testing.T) {
	code := "C0DE" + strings.ReplaceAll(harness.Unique(), "-", "")[:10]
	token := "tok-canary-" + harness.NewID()
	link := "https://iam.example.com/reset-password?token=" + token
	ensureTemplate(t, otpTopic, "Your sign-in code", `<p>Your code is <strong>{{code}}</strong></p>`, "Your code is {{code}}")
	ensureTemplate(t, "iam.auth.password_reset_requested", "Reset your password",
		`<p><a href="{{reset_link}}">Choose a new password</a></p>`, "Open {{reset_link}}")

	var mu sync.Mutex
	var payloads []string
	ln, err := net.Listen("tcp", canaryHookAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		payloads = append(payloads, string(raw))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	admin := fx.Admin(t)
	hook := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/webhooks", map[string]any{
		"url": "http://" + canaryHookAddr + "/hook", "events": []string{"message.sent", "message.failed", "message.delivered", "message.bounced"},
	}).Data()
	t.Cleanup(func() {
		fx.Admin(t).Do(t, http.MethodDelete, "/api/v1/webhooks/"+harness.Str(hook, "id"), nil)
	})

	svc := fx.Service(t, iamClient())
	codeBox, resetBox := fx.Env.NewMailbox("canary-code"), fx.Env.NewMailbox("canary-reset")
	codeID := harness.Str(svc.Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", map[string]any{
		"id": harness.NewID(), "type": otpTopic, "source": "iam",
		"data": map[string]any{"email": codeBox.Address, "code": code, "purpose": "sign_in", "expires_in_minutes": 10},
	}).Data(), "delivery_id")
	resetID := harness.Str(svc.Expect(t, http.StatusAccepted, http.MethodPost, "/api/v1/events", map[string]any{
		"id": harness.NewID(), "type": "iam.auth.password_reset_requested", "source": "iam",
		"data": map[string]any{"email": resetBox.Address, "reset_link": link},
	}).Data(), "delivery_id")

	// The recipients get the live code and link.
	if m := codeBox.WaitSubject(t, "Your sign-in code"); !strings.Contains(m.Text, code) || !strings.Contains(m.HTML, code) {
		t.Fatalf("code mail: %s", m.JSON())
	}
	if m := resetBox.WaitSubject(t, "Reset your password"); !strings.Contains(m.Text, link) {
		t.Fatalf("reset mail: %s", m.JSON())
	}
	harness.Eventually(t, "webhooks for both messages", 30*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		all := strings.Join(payloads, "\n")
		return strings.Contains(all, codeID) && strings.Contains(all, resetID)
	})

	// The console sees descriptors, the class and the evidence digest, and
	// cannot resend.
	operator, _ := fx.NewUser(t, harness.RoleOperator)
	for id, want := range map[string]string{codeID: "[redacted: code,", resetID: "https://iam.example.com/reset-password/[redacted]"} {
		view := operator.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+id, nil)
		if !strings.Contains(view.String(), want) || !strings.Contains(view.String(), `"auth_class":true`) ||
			!strings.HasPrefix(harness.Str(view.Data(), "sent_digest"), "hmac-sha256:") {
			t.Fatalf("view of %s: %s", id, view)
		}
		body := operator.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+id+"/body", nil)
		if !strings.Contains(body.String(), "[redacted") {
			t.Fatalf("body of %s: %s", id, body)
		}
		operator.ExpectError(t, http.StatusConflict, "", http.MethodPost, "/api/v1/messages/"+id+"/resend", nil)
	}

	needles := []string{code, token}
	if hits := fx.Env.SearchPostgres(t, needles...); len(hits) > 0 {
		t.Errorf("Postgres tables hold a live secret: %v", hits)
	}
	if hits := fx.Env.SearchRedis(t, []string{e2eSinkKey}, needles...); len(hits) > 0 {
		t.Errorf("Redis keys hold a live secret: %v", hits)
	}
	if hits := fx.Env.SearchLogs(t, needles...); len(hits) > 0 {
		t.Errorf("logs hold a live secret: %v", hits)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range payloads {
		for _, n := range needles {
			if strings.Contains(p, n) {
				t.Errorf("webhook payload holds a live secret: %s", p)
			}
		}
	}
}
