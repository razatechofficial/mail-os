package message

import (
	"context"
	"errors"
	"testing"

	"github.com/razatechofficial/mail-os/application/campaign"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// rejectScanner rejects files whose content is the EICAR marker and fails
// when err is set.
type rejectScanner struct {
	err     error
	scanned []string
}

func (s *rejectScanner) Scan(_ context.Context, name, _ string, data []byte) (Verdict, error) {
	s.scanned = append(s.scanned, name)
	if s.err != nil {
		return Verdict{}, s.err
	}
	if string(data) == "EICAR" {
		return Verdict{Reason: "Eicar-Test-Signature"}, nil
	}
	return Verdict{Clean: true}, nil
}

func withAttachments(f *fixture) *rejectScanner {
	sc := &rejectScanner{}
	f.svc.d.Scanner = sc
	f.svc.cfg.Attachments = domainmsg.AttachmentLimits{MaxBytes: 1 << 10, MaxTotalBytes: 2 << 10, MaxCount: 3}
	return sc
}

func TestSendWithAttachmentsIsScannedStoredAndDelivered(t *testing.T) {
	f := newFixture(t)
	sc := withAttachments(f)
	in := direct()
	in.Attachments = []domainmsg.Attachment{
		{Filename: "invoice.pdf", Data: []byte("%PDF-1.7")},
		{Filename: "logo.png", ContentID: "<logo>", Inline: true, Data: []byte("png")},
	}
	r, err := f.svc.Send(userCtx(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.scanned) != 2 {
		t.Fatalf("scanned %v", sc.scanned)
	}
	stored, _ := f.repo.Get(context.Background(), tenant, r.MessageID)
	if len(stored.Attachments) != 2 || stored.Attachments[0].ContentType != "application/pdf" || stored.Attachments[1].ContentID != "logo" {
		t.Fatalf("stored %+v", stored.Attachments)
	}
	if err := f.svc.Deliver(context.Background(), tenant, r.MessageID); err != nil {
		t.Fatal(err)
	}
	out := f.sender.sent[0]
	if len(out.Attachments) != 2 || string(out.Attachments[0].Data) != "%PDF-1.7" || !out.Attachments[1].Inline {
		t.Fatalf("outgoing %+v", out.Attachments)
	}
}

func TestAttachmentRefusals(t *testing.T) {
	f := newFixture(t)
	sc := withAttachments(f)
	send := func(a ...domainmsg.Attachment) error {
		in := direct()
		in.Attachments = a
		_, err := f.svc.Send(userCtx(), in)
		return err
	}
	field := func(err error) string {
		if d := apperrors.DetailsOf(err); len(d) > 0 {
			return d[0].Field + ":" + d[0].Code
		}
		return ""
	}
	if err := send(domainmsg.Attachment{Filename: "setup.exe", Data: []byte("MZ")}); field(err) != "attachments[0].filename:blocked_type" {
		t.Fatalf("exe: %v %s", err, field(err))
	}
	if err := send(domainmsg.Attachment{Filename: "a.txt", Data: []byte("ok")}, domainmsg.Attachment{Filename: "b.txt", Data: []byte("EICAR")}); field(err) != "attachments[1].content:rejected" {
		t.Fatalf("infected: %v %s", err, field(err))
	}
	if !f.audit.has("message.attachment_rejected") {
		t.Fatal("rejection not audited")
	}
	sc.err = errors.New("clamd down")
	if err := send(domainmsg.Attachment{Filename: "a.txt", Data: []byte("ok")}); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("scanner down: %v", err)
	}
	f.svc.cfg.Attachments = domainmsg.AttachmentLimits{}
	if err := send(domainmsg.Attachment{Filename: "a.txt", Data: []byte("ok")}); field(err) != "attachments:not_allowed" {
		t.Fatalf("turned off: %v", err)
	}
	if len(f.repo.msgs) != 0 {
		t.Fatalf("refused sends stored %d messages", len(f.repo.msgs))
	}
}

func TestTemplatedSendCarriesAttachments(t *testing.T) {
	f := newFixture(t)
	withAttachments(f)
	r, err := f.svc.Send(userCtx(), SendInput{TenantID: tenant, TemplateSlug: "mfa-code", ToEmail: "ana@example.com",
		FromEmail: "noreply@bank.example", TemplateData: map[string]any{"email": "ana@example.com", "code": "482913", "purpose": "sign_in", "expires_in_minutes": 10.0},
		Attachments: []domainmsg.Attachment{{Filename: "terms.txt", Data: []byte("terms")}}})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := f.repo.Get(context.Background(), tenant, r.MessageID)
	if len(m.Attachments) != 1 || m.Attachments[0].ContentType != "text/plain; charset=utf-8" && m.Attachments[0].ContentType != "text/plain" {
		t.Fatalf("%+v", m.Attachments)
	}
}

// A campaign's files are checked and scanned once when it is saved, then
// each recipient's message carries them to the provider unscanned again.
func TestCampaignAttachmentsAreCheckedOnceAndDelivered(t *testing.T) {
	f := newFixture(t)
	sc := withAttachments(f)
	files := []domainmsg.Attachment{{Filename: "brochure.pdf", Data: []byte("%PDF-1.7")}}
	if err := f.svc.CheckAttachments(context.Background(), "campaign", "c1", files); err != nil {
		t.Fatal(err)
	}
	if files[0].ContentType != "application/pdf" || len(sc.scanned) != 1 {
		t.Fatalf("checked %+v, scanned %v", files, sc.scanned)
	}
	for _, to := range []string{"bob@example.com", "eve@example.com"} {
		id, err := f.svc.SendCampaignMessage(context.Background(), campaign.CampaignMessage{TenantID: tenant, CampaignID: "c1",
			TemplateID: "tpl-1", To: to, FromEmail: "news@bank.example", Attachments: files,
			Data: map[string]any{"contact": map[string]any{"email": to}, "campaign": map[string]any{"name": "Autumn"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.svc.Deliver(context.Background(), tenant, id); err != nil {
			t.Fatal(err)
		}
	}
	if len(sc.scanned) != 1 {
		t.Fatalf("rescanned per recipient: %v", sc.scanned)
	}
	if len(f.sender.sent) != 2 {
		t.Fatalf("sent %d", len(f.sender.sent))
	}
	for _, out := range f.sender.sent {
		if len(out.Attachments) != 1 || out.Attachments[0].Filename != "brochure.pdf" || string(out.Attachments[0].Data) != "%PDF-1.7" {
			t.Fatalf("outgoing %+v", out.Attachments)
		}
	}

	err := f.svc.CheckAttachments(context.Background(), "campaign", "c2", []domainmsg.Attachment{{Filename: "x.txt", Data: []byte("EICAR")}})
	if d := apperrors.DetailsOf(err); len(d) != 1 || d[0].Field != "attachments[0].content" || d[0].Code != "rejected" {
		t.Fatalf("infected campaign file: %v", err)
	}
	if !f.audit.has("campaign.attachment_rejected") {
		t.Fatal("campaign rejection not audited")
	}
	big := []domainmsg.Attachment{{Filename: "big.pdf", Data: make([]byte, 2<<10)}}
	if d := apperrors.DetailsOf(f.svc.CheckAttachments(context.Background(), "campaign", "c3", big)); len(d) == 0 || d[0].Code != "too_large" {
		t.Fatalf("over the limit: %v", d)
	}
}
