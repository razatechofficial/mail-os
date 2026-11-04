package message

import (
	"context"
	"testing"

	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/application/unsubscribe"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
)

type memUnsub struct{ links []unsubscribe.Link }

func (u *memUnsub) URL(l unsubscribe.Link) (string, error) {
	u.links = append(u.links, l)
	return "https://mail.example.com/unsubscribe/tok-" + l.MessageID, nil
}

func (u *memUnsub) Headers(url string) map[string]string {
	return map[string]string{"List-Unsubscribe": "<" + url + ">", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}
}

// Broadcast mail gets the one-click headers and {{unsubscribe_url}};
// transactional mail gets neither, and a sender's own header is kept.
func TestDeliverAddsOneClickUnsubscribeToBroadcastOnly(t *testing.T) {
	f := newFixture(t)
	unsub := &memUnsub{}
	f.svc.d.Unsubscribe = unsub
	tpls := memTemplates{
		tpl: domaintemplate.Template{ID: "tpl-1", Slug: "news", Topic: domaintemplate.TopicCampaign, Category: domaintemplate.CategoryMarketing},
		ver: domaintemplate.Version{ID: "ver-3", TemplateID: "tpl-1", Locale: "en", Subject: "News",
			HTMLBody: `<a href="{{unsubscribe_url}}">Unsubscribe</a>`, TextBody: "Unsubscribe: {{unsubscribe_url}}"},
	}
	f.svc.d.Templates, f.svc.d.Versions = tpls, tpls
	ctx := context.Background()
	id, err := f.svc.SendCampaignMessage(ctx, campaign.CampaignMessage{TenantID: tenant, CampaignID: "c1", TemplateID: "tpl-1",
		To: "bob@example.com", FromEmail: "news@bank.example",
		Data: map[string]any{"contact": map[string]any{"email": "bob@example.com"}, "campaign": map[string]any{"name": "Autumn"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Deliver(ctx, tenant, id); err != nil {
		t.Fatal(err)
	}
	out := f.sender.sent[0]
	want := "https://mail.example.com/unsubscribe/tok-" + id
	if out.Headers["List-Unsubscribe"] != "<"+want+">" || out.Headers["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" {
		t.Fatalf("headers = %v", out.Headers)
	}
	if out.Text != "Unsubscribe: "+want {
		t.Fatalf("text = %q", out.Text)
	}
	if l := unsub.links[0]; l.TenantID != tenant || l.Email != "bob@example.com" || l.CampaignID != "c1" || l.MessageID != id {
		t.Fatalf("link = %+v", l)
	}

	// Transactional mail: no link.
	r, err := f.svc.Send(userCtx(), direct())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Deliver(ctx, tenant, r.MessageID); err != nil {
		t.Fatal(err)
	}
	if h := f.sender.sent[1].Headers; h["List-Unsubscribe"] != "" {
		t.Fatalf("transactional mail got %v", h)
	}

	// A marketing send with its own List-Unsubscribe keeps it.
	in := direct()
	in.Type = domainmsg.TypeMarketing
	in.Headers = map[string]string{"List-Unsubscribe": "<https://news.bank.example/u/1>"}
	r, err = f.svc.Send(userCtx(), in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Deliver(ctx, tenant, r.MessageID); err != nil {
		t.Fatal(err)
	}
	if h := f.sender.sent[2].Headers; h["List-Unsubscribe"] != "<https://news.bank.example/u/1>" || h["List-Unsubscribe-Post"] != "" {
		t.Fatalf("sender's header replaced: %v", h)
	}
}
