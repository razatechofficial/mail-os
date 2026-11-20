//go:build e2e

// Package messaging drives sends from outside: a direct send reaches the
// mailbox, an idempotency key sends once, batches report each entry,
// scheduled messages wait for the scheduler and can be cancelled, the
// suppression list holds mail back (unsubscribes for marketing only), and
// provider credentials are sealed and never returned.
package messaging

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/e2e/harness"
)

var fx *harness.Fixture

func TestMain(m *testing.M) { harness.Main(m, "messaging", &fx) }

func send(t *testing.T, c *harness.Client, body map[string]any) map[string]any {
	t.Helper()
	return c.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", body).Data()
}

func status(t *testing.T, id string) string {
	t.Helper()
	return harness.Str(fx.Admin(t).Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+id, nil).Data(), "status")
}

func waitStatus(t *testing.T, id, want string) {
	t.Helper()
	harness.Eventually(t, "message "+id+" "+want, 20*time.Second, func() bool { return status(t, id) == want })
}

func TestOperatorSendReachesMailbox(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	box := fx.Env.NewMailbox("direct")
	id := harness.Str(send(t, op, map[string]any{"to_email": box.Address, "subject": "Direct hello", "html_body": "<p>Hi</p>", "text_body": "Hi"}), "message_id")
	mail := box.WaitSubject(t, "Direct hello")
	if !strings.Contains(mail.HTML, "<p>Hi</p>") || mail.Text != "Hi" {
		t.Errorf("delivered: %s", mail.JSON())
	}
	waitStatus(t, id, "sent")
}

func TestIdempotencyKeySendsOnce(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	box := fx.Env.NewMailbox("idem")
	key := "order-" + harness.Unique()
	body := map[string]any{"to_email": box.Address, "subject": "Once only", "text_body": "x"}
	first := op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", body, http.Header{"Idempotency-Key": {key}}).Data()
	again := op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", body, http.Header{"Idempotency-Key": {key}}).Data()
	if first["message_id"] != again["message_id"] {
		t.Fatalf("same key, two messages: %v %v", first, again)
	}
	box.WaitSubject(t, "Once only")
	time.Sleep(2 * time.Second)
	if n := len(box.Messages(t)); n != 1 {
		t.Fatalf("%d mails for one idempotency key", n)
	}
	// Another tenant may use the same key for its own message.
	b := fx.As(t, harness.User{Tenant: harness.NewID(), Roles: []string{harness.RoleOperator}})
	theirs := b.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/send", body, http.Header{"Idempotency-Key": {key}}).Data()
	if theirs["message_id"] == first["message_id"] {
		t.Fatal("an idempotency key resolved to another tenant's message")
	}
}

func TestBatchReportsEachEntry(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	good := fx.Env.NewMailbox("batch")
	res := op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/batch", map[string]any{"messages": []map[string]any{
		{"to_email": good.Address, "subject": "Batch one", "text_body": "1"},
		{"to_email": "not-an-address", "subject": "Bad", "text_body": "2"},
	}}).Data()
	if res["success_count"] != float64(1) || res["fail_count"] != float64(1) {
		t.Fatalf("batch result: %v", res)
	}
	good.WaitSubject(t, "Batch one")
	tooMany := make([]map[string]any, 101)
	for i := range tooMany {
		tooMany[i] = map[string]any{"to_email": harness.NewEmail("n"), "subject": "s", "text_body": "t"}
	}
	op.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/messages/batch", map[string]any{"messages": tooMany})
}

func TestScheduledMessageWaitsAndCanBeCancelled(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	later := fx.Env.NewMailbox("later")
	at := time.Now().Add(4 * time.Second).UTC()
	id := harness.Str(send(t, op, map[string]any{"to_email": later.Address, "subject": "Scheduled", "text_body": "x", "schedule_at": at}), "message_id")
	if s := status(t, id); s != "scheduled" {
		t.Fatalf("status %q, want scheduled", s)
	}
	later.Empty(t, time.Second)
	later.WaitSubject(t, "Scheduled")

	never := fx.Env.NewMailbox("cancelled")
	id = harness.Str(send(t, op, map[string]any{"to_email": never.Address, "subject": "Cancelled", "text_body": "x",
		"schedule_at": time.Now().Add(time.Hour).UTC()}), "message_id")
	op.Expect(t, http.StatusOK, http.MethodPost, "/api/v1/messages/"+id+"/cancel", nil)
	if s := status(t, id); s != "cancelled" {
		t.Fatalf("status %q, want cancelled", s)
	}
	op.ExpectError(t, http.StatusConflict, "", http.MethodPost, "/api/v1/messages/"+id+"/cancel", nil)
	op.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/messages/send", map[string]any{
		"to_email": never.Address, "subject": "Too far", "text_body": "x", "schedule_at": time.Now().Add(31 * 24 * time.Hour).UTC()})
}

func TestResendSendsAgain(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	box := fx.Env.NewMailbox("resend")
	id := harness.Str(send(t, op, map[string]any{"to_email": box.Address, "subject": "Resend me", "text_body": "x"}), "message_id")
	box.WaitSubject(t, "Resend me")
	waitStatus(t, id, "sent")
	seen := box.Messages(t)
	again := harness.Str(op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/messages/"+id+"/resend", nil).Data(), "message_id")
	if again == "" || again == id {
		t.Fatalf("resend made no new message: %q", again)
	}
	box.WaitAfter(t, seen)
}

func TestSuppressionsHoldMailBack(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	blocked := fx.Env.NewMailbox("blocked")
	op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/suppressions", map[string]any{"email": strings.ToUpper(blocked.Address), "type": "manual", "reason": "asked"})
	id := harness.Str(send(t, op, map[string]any{"to_email": blocked.Address, "subject": "Held", "text_body": "x"}), "message_id")
	if s := status(t, id); s != "suppressed" {
		t.Fatalf("status %q, want suppressed", s)
	}
	blocked.Empty(t, 2*time.Second)
	op.Expect(t, http.StatusNoContent, http.MethodDelete, "/api/v1/suppressions?email="+blocked.Address, nil)
	send(t, op, map[string]any{"to_email": blocked.Address, "subject": "Allowed again", "text_body": "x"})
	blocked.WaitSubject(t, "Allowed again")

	// An unsubscribe stops marketing mail but not transactional mail.
	unsub := fx.Env.NewMailbox("unsub")
	op.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/suppressions", map[string]any{"email": unsub.Address, "type": "unsubscribe"})
	id = harness.Str(send(t, op, map[string]any{"to_email": unsub.Address, "subject": "Promo", "text_body": "x", "type": "marketing"}), "message_id")
	if s := status(t, id); s != "suppressed" {
		t.Fatalf("marketing to an unsubscribed address: status %q", s)
	}
	send(t, op, map[string]any{"to_email": unsub.Address, "subject": "Your receipt", "text_body": "x", "type": "transactional"})
	unsub.WaitSubject(t, "Your receipt")

	list := op.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/suppressions?type=unsubscribe", nil).Items()
	if len(list) != 1 || list[0]["email"] != unsub.Address {
		t.Fatalf("type filter: %v", list)
	}
	viewer, _ := fx.NewUser(t, harness.RoleViewer)
	viewer.ExpectError(t, http.StatusForbidden, "FORBIDDEN", http.MethodPost, "/api/v1/suppressions", map[string]any{"email": harness.NewEmail("v"), "type": "manual"})
}

func TestProviderCredentialsAreNeverReturned(t *testing.T) {
	admin := fx.Admin(t)
	secret := "SG.top-secret-" + harness.Unique()
	created := admin.Expect(t, http.StatusCreated, http.MethodPost, "/api/v1/providers", map[string]any{
		"name": "SendGrid", "type": "sendgrid", "is_active": false, "configuration": map[string]any{"api_key": secret, "from_email": "a@example.com"},
	})
	id := harness.Str(created.Data(), "id")
	if created.Data()["has_credentials"] != true {
		t.Fatalf("has_credentials: %s", created)
	}
	updated := admin.Expect(t, http.StatusOK, http.MethodPut, "/api/v1/providers/"+id, map[string]any{"name": "SendGrid EU"})
	for _, r := range []*harness.Response{created, updated,
		admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/providers/"+id, nil),
		admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/providers", nil),
		admin.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs?limit=100", nil)} {
		if strings.Contains(r.String(), secret) || strings.Contains(r.String(), secret[len(secret)-8:]) {
			t.Fatalf("the credential is returned: %s", r)
		}
	}
	if updated.Data()["has_credentials"] != true {
		t.Fatalf("a rename dropped the credentials: %s", updated)
	}
	admin.ExpectError(t, http.StatusUnprocessableEntity, "", http.MethodPost, "/api/v1/providers", map[string]any{
		"name": "Bad", "type": "sendgrid", "configuration": map[string]any{"api_key": 42}})
	admin.Expect(t, http.StatusNoContent, http.MethodDelete, "/api/v1/providers/"+id, nil)
	admin.ExpectError(t, http.StatusNotFound, "", http.MethodGet, "/api/v1/providers/"+id, nil)
}

func TestMessageViewsMaskAndBodyIsAudited(t *testing.T) {
	op, _ := fx.NewUser(t, harness.RoleOperator)
	box := fx.Env.NewMailbox("mask")
	id := harness.Str(send(t, op, map[string]any{"to_email": box.Address, "subject": "Statement inside", "text_body": "Your code is 739120"}), "message_id")
	box.WaitSubject(t, "inside")
	viewer, _ := fx.NewUser(t, harness.RoleViewer)
	for _, r := range []*harness.Response{
		viewer.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+id, nil),
		viewer.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages?limit=100", nil),
	} {
		if strings.Contains(r.String(), "739120") || strings.Contains(r.String(), "html_body") || strings.Contains(r.String(), "text_body") {
			t.Fatalf("console view shows the code or a body: %s", r)
		}
	}
	aud, sub := fx.NewUser(t, harness.RoleAuditor)
	aud.Expect(t, http.StatusOK, http.MethodGet, "/api/v1/messages/"+id+"/body", nil)
	harness.Eventually(t, "the body read in the audit log", 10*time.Second, func() bool {
		log := fx.Admin(t).Expect(t, http.StatusOK, http.MethodGet, "/api/v1/analytics/audit-logs?resource=message&limit=100", nil).String()
		return strings.Contains(log, "message.body_viewed") && strings.Contains(log, sub)
	})
}
