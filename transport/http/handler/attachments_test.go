package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
)

func TestSendRefusesAttachmentNotBase64(t *testing.T) {
	r := engine(t, messageHandler(&recAudit{}), []access.Role{access.RoleOperator}, time.Minute, access.ACRMFA)
	w := do(r, "POST", "/api/v1/messages/send", map[string]any{"to_email": "a@example.com", "subject": "s", "text_body": "t",
		"attachments": []map[string]any{{"filename": "a.pdf", "content": "%%% not base64"}}})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "attachments[0].content") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = do(r, "POST", "/api/v1/messages/batch", map[string]any{"messages": []map[string]any{{"to_email": "a@example.com",
		"attachments": []map[string]any{{"filename": "a.pdf", "content": "!!"}}}}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("batch: %d %s", w.Code, w.Body)
	}
}

func TestMessageViewDescribesAttachmentsWithoutContent(t *testing.T) {
	m := otpMessage()
	m.Attachments = []domainmsg.Attachment{{Filename: "statement.pdf", ContentType: "application/pdf", Data: []byte("SECRET-PDF")},
		{Filename: "logo.png", ContentType: "image/png", ContentID: "logo", Inline: true, Data: []byte("png")}}
	h := NewMessageHandler(appmsg.NewService(appmsg.Deps{Repo: fakeMsgRepo{m: m}, Tenants: nopTenants{}, Audit: &recAudit{}}, appmsg.Config{}), nil, nil)
	w := do(engine(t, h, []access.Role{access.RoleViewer}, time.Hour, access.ACRPassword), "GET", "/api/v1/messages/m1", nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `"filename":"statement.pdf"`) || !strings.Contains(body, `"size":10`) ||
		!strings.Contains(body, `"content_id":"logo"`) || strings.Contains(body, "SECRET-PDF") || strings.Contains(body, "U0VDUkVU") {
		t.Fatalf("%d %s", w.Code, body)
	}
}
