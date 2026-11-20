//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
)

// Rows stored before persistence masking (live code and reset link in the
// subject, bodies, template data and last error) lose every secret value
// to mailos-redact-auth-mail's job; a second run changes nothing, and other
// topics are untouched.
func TestRedactStoredAuthMail(t *testing.T) {
	e := newMsgEnv(t)
	ctx := context.Background()
	repo := postgres.NewMessageRepository(e.db)
	now := time.Now().UTC()
	code := "39" + e.tenant[:4] // unique per run, so other rows cannot match
	token := "tok-" + e.tenant[:8]
	link := "https://iam.example.com/reset-password?token=" + token + "&x=1"
	rows := []domainmsg.Message{
		{Topic: domaintemplate.TopicMFAEmailCode, Subject: "Code " + code, HTMLBody: "<b>" + code + "</b>", TextBody: code,
			TemplateData: map[string]any{"email": "a@example.com", "code": code, "purpose": "sign_in"}, Status: domainmsg.StatusSent},
		{Topic: domaintemplate.TopicPasswordReset, Subject: "Reset", HTMLBody: `<a href="` + strings.ReplaceAll(link, "&", "&amp;") + `">reset</a>`,
			TextBody: "Open " + link, TemplateData: map[string]any{"email": "a@example.com", "reset_link": link},
			Status: domainmsg.StatusFailed, LastError: "smtp: rejected " + token},
		{Topic: domaintemplate.TopicApprovalRequested, Subject: "Approve " + code, TextBody: "approve",
			TemplateData: map[string]any{"approval_link": "https://iam.example.com/approvals/" + code}, Status: domainmsg.StatusSent},
	}
	ids := make([]string, len(rows))
	for i, m := range rows {
		m.ID, m.OrgID, m.FromEmail, m.ToEmail, m.Type, m.Priority = uuid.NewString(), e.tenant, "noreply@bank.example",
			"a@example.com", domainmsg.TypeTransactional, domainmsg.PriorityNormal
		m.CreatedAt, m.UpdatedAt = now, now
		if err := repo.Create(ctx, m); err != nil {
			t.Fatal(err)
		}
		if m.LastError != "" {
			mustExec(t, e, `UPDATE messages SET last_error = $2 WHERE id = $1`, m.ID, m.LastError)
		}
		ids[i] = m.ID
	}
	row := func(id string) string {
		return e.raw(t, `SELECT row_to_json(m)::text FROM messages m WHERE id = $1`, id)
	}
	rep, err := appmessage.RedactStored(ctx, repo, 2)
	if err != nil || rep.Redacted < 2 {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, id := range ids[:2] {
		if r := row(id); strings.Contains(r, code) || strings.Contains(r, token) || !strings.Contains(r, "[redacted") {
			t.Fatalf("row %s after redaction: %s", id, r)
		}
	}
	if r := row(ids[2]); !strings.Contains(r, "approvals/"+code) {
		t.Fatalf("an approval mail was changed: %s", r)
	}
	if v := e.raw(t, `SELECT template_data->>'reset_link' FROM messages WHERE id = $1`, ids[1]); v != "https://iam.example.com/reset-password/[redacted]" {
		t.Fatalf("descriptor %q", v)
	}
	before := row(ids[0]) + row(ids[1])
	if rep, err := appmessage.RedactStored(ctx, repo, 500); err != nil || rep.Redacted != 0 {
		t.Fatalf("second run %+v %v", rep, err)
	}
	if after := row(ids[0]) + row(ids[1]); after != before {
		t.Fatal("second run changed the rows")
	}
}
