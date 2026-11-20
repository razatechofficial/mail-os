package message

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
)

// storedMail pages over memRepo's messages in id order.
type storedMail struct{ r *memRepo }

func (s storedMail) AuthMessagesAfter(_ context.Context, topics []string, after string, limit int) ([]domainmsg.Message, error) {
	list := s.r.filter(func(m domainmsg.Message) bool {
		return slices.Contains(topics, m.Topic) && m.BodyPurgedAt == nil && m.ID > after
	})
	slices.SortFunc(list, func(a, b domainmsg.Message) int { return strings.Compare(a.ID, b.ID) })
	if len(list) > limit {
		list = list[:limit]
	}
	return list, nil
}

func (s storedMail) SaveRedacted(_ context.Context, m domainmsg.Message) error {
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	s.r.msgs[m.ID] = m
	return nil
}

func TestRedactStored(t *testing.T) {
	r := newMemRepo()
	link := "https://iam.example.com/reset-password?token=tok-55&x=1"
	legacy := []domainmsg.Message{
		{ID: "a1", OrgID: tenant, Topic: domaintemplate.TopicMFAEmailCode, Subject: "Code 731904",
			HTMLBody: "<b>731904</b>", TextBody: "731904", TemplateData: map[string]any{"code": "731904", "purpose": "sign_in"},
			LastError: "smtp: rejected 731904"},
		{ID: "a2", OrgID: tenant, Topic: domaintemplate.TopicPasswordReset, Subject: "Reset",
			HTMLBody: `<a href="https://iam.example.com/reset-password?token=tok-55&amp;x=1">reset</a>`, TextBody: "Open " + link,
			TemplateData: map[string]any{"reset_link": link, "email": "a@example.com"}},
		{ID: "a3", OrgID: tenant, Topic: domaintemplate.TopicApprovalRequested, Subject: "Approve",
			TemplateData: map[string]any{"approval_link": "https://iam.example.com/approvals/1"}},
	}
	for _, m := range legacy {
		r.msgs[m.ID] = m
	}
	rep, err := RedactStored(context.Background(), storedMail{r}, 1)
	if err != nil || rep.Scanned != 2 || rep.Redacted != 2 {
		t.Fatalf("%+v %v", rep, err)
	}
	all, _ := json.Marshal(r.msgs)
	for _, leak := range []string{"731904", "tok-55"} {
		if strings.Contains(string(all), leak) {
			t.Fatalf("stored mail still holds %q: %s", leak, all)
		}
	}
	if r.msgs["a1"].TemplateData["code"] != "[redacted: code, 6 characters]" || r.msgs["a1"].TemplateData["purpose"] != "sign_in" ||
		r.msgs["a2"].TemplateData["reset_link"] != "https://iam.example.com/reset-password/[redacted]" {
		t.Fatalf("descriptors %v %v", r.msgs["a1"].TemplateData, r.msgs["a2"].TemplateData)
	}
	if r.msgs["a3"].TemplateData["approval_link"] != "https://iam.example.com/approvals/1" {
		t.Fatal("a non-authentication message changed")
	}
	// A second run changes nothing.
	before, _ := json.Marshal(r.msgs)
	rep, err = RedactStored(context.Background(), storedMail{r}, 10)
	after, _ := json.Marshal(r.msgs)
	if err != nil || rep.Redacted != 0 || string(before) != string(after) {
		t.Fatalf("second run %+v %v", rep, err)
	}
}
