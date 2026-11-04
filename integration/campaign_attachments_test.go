//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/application/contact"
	domaincampaign "github.com/razatechofficial/mail-os/domain/campaign"
	domaincontact "github.com/razatechofficial/mail-os/domain/contact"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
)

// passChecker accepts every file (the messaging slice's checks have their
// own tests).
type passChecker struct{}

func (passChecker) CheckAttachments(context.Context, string, string, []domainmsg.Attachment) error {
	return nil
}

// A campaign's files are stored in campaign_attachments, replaced on
// update, and handed to the sender for every recipient.
func TestCampaignAttachmentsStoredAndFannedOut(t *testing.T) {
	m := newMarketing(t)
	ctx, tid, tpl := newTenant(t, m)
	_, _ = m.contacts.Import(ctx, tid, []domaincontact.Contact{{Email: "f1@example.com"}, {Email: "f2@example.com"}})
	cs, _, _ := m.contacts.List(ctx, tid, contact.Filter{Limit: 10})
	l, _ := m.contacts.CreateList(ctx, tid, domaincontact.List{Name: "Files"})
	if _, err := m.contacts.AddMembers(ctx, tid, l.ID, []string{cs[0].ID, cs[1].ID}); err != nil {
		t.Fatal(err)
	}
	cmp, err := m.campaigns.Create(ctx, tid, domaincampaign.Campaign{Name: "Files", Subject: "S", FromName: "A", FromEmail: "a@example.com",
		TemplateID: tpl, ContactListID: l.ID, Attachments: []domainmsg.Attachment{
			{Filename: "brochure.pdf", ContentType: "application/pdf", Data: []byte("%PDF-1.7 brochure")},
			{Filename: "logo.png", ContentType: "image/png", ContentID: "logo", Inline: true, Data: []byte("png")},
		}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.campaigns.Get(ctx, tid, cmp.ID)
	if err != nil || len(got.Attachments) != 2 || string(got.Attachments[0].Data) != "%PDF-1.7 brochure" ||
		got.Attachments[1].ContentID != "logo" || !got.Attachments[1].Inline {
		t.Fatalf("stored %+v %v", got.Attachments, err)
	}
	one := []domainmsg.Attachment{{Filename: "terms.txt", ContentType: "text/plain", Data: []byte("terms")}}
	if _, err := m.campaigns.Update(ctx, tid, cmp.ID, campaign.Update{Attachments: &one}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := m.db.QueryRow(ctx, `SELECT count(*) FROM campaign_attachments WHERE campaign_id = $1`, cmp.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after replace %d %v", n, err)
	}
	if _, err := m.campaigns.Launch(ctx, tid, cmp.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.campaigns.Fanout(ctx, tid, cmp.ID); err != nil {
		t.Fatal(err)
	}
	sent := 0
	for _, s := range m.sender.sent {
		if s.CampaignID != cmp.ID {
			continue
		}
		sent++
		if len(s.Attachments) != 1 || s.Attachments[0].Filename != "terms.txt" || string(s.Attachments[0].Data) != "terms" {
			t.Fatalf("%s got %+v", s.To, s.Attachments)
		}
	}
	if sent != 2 {
		t.Fatalf("sent %d", sent)
	}
}
