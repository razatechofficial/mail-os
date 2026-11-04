package campaign

import (
	"context"
	"slices"
	"testing"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// memFiles is an in-memory Files.
type memFiles struct{ files map[string][]domainmsg.Attachment }

func (m *memFiles) Attachments(_ context.Context, _, id string) ([]domainmsg.Attachment, error) {
	return slices.Clone(m.files[id]), nil
}
func (m *memFiles) SetAttachments(_ context.Context, _, id string, files []domainmsg.Attachment) error {
	m.files[id] = slices.Clone(files)
	return nil
}

// checker fills the content type and rejects files named virus.txt.
type checker struct{ checked []string }

func (c *checker) CheckAttachments(_ context.Context, resourceType, id string, files []domainmsg.Attachment) error {
	for i := range files {
		c.checked = append(c.checked, resourceType+"/"+id+"/"+files[i].Filename)
		if files[i].Filename == "virus.txt" {
			return apperrors.Invalid("attachments[0].content", "rejected", "rejected by the virus scan")
		}
		files[i].ContentType = "application/pdf"
	}
	return nil
}

func withFiles(svc *Service) (*memFiles, *checker) {
	files, chk := &memFiles{files: map[string][]domainmsg.Attachment{}}, &checker{}
	svc.d.Files, svc.d.Checker = files, chk
	return files, chk
}

func TestCampaignAttachmentsReachEveryRecipient(t *testing.T) {
	svc, f, snd, _ := setup(true)
	files, chk := withFiles(svc)
	ctx := context.Background()
	f.members["l1"] = members(5) // three pages of two
	in := draft()
	in.Attachments = []domainmsg.Attachment{{Filename: "brochure.pdf", Data: []byte("%PDF")}}
	c, err := svc.Create(ctx, tenant, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(chk.checked) != 1 || chk.checked[0] != "campaign/"+c.ID+"/brochure.pdf" || files.files[c.ID][0].ContentType != "application/pdf" {
		t.Fatalf("checked %v stored %+v", chk.checked, files.files[c.ID])
	}
	if got, _ := svc.Get(ctx, tenant, c.ID); len(got.Attachments) != 1 {
		t.Fatalf("get %+v", got.Attachments)
	}
	if l, err := svc.Launch(ctx, tenant, c.ID); err != nil || len(l.Attachments) != 1 {
		t.Fatalf("launch %+v %v", l.Attachments, err)
	}
	if err := svc.Fanout(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
	if len(snd.sent) != 5 {
		t.Fatalf("sent %d", len(snd.sent))
	}
	for _, m := range snd.sent {
		if len(m.Attachments) != 1 || m.Attachments[0].Filename != "brochure.pdf" || string(m.Attachments[0].Data) != "%PDF" {
			t.Fatalf("%s got %+v", m.To, m.Attachments)
		}
	}
}

func TestCampaignAttachmentUpdates(t *testing.T) {
	svc, _, _, log := setup(true)
	files, _ := withFiles(svc)
	ctx := context.Background()
	in := draft()
	in.Attachments = []domainmsg.Attachment{{Filename: "a.pdf", Data: []byte("a")}}
	c, err := svc.Create(ctx, tenant, in)
	if err != nil {
		t.Fatal(err)
	}
	subject := "New subject"
	u, err := svc.Update(ctx, tenant, c.ID, Update{Subject: &subject})
	if err != nil || len(u.Attachments) != 1 || len(files.files[c.ID]) != 1 {
		t.Fatalf("an update without files dropped them: %+v %v", u.Attachments, err)
	}
	bad := []domainmsg.Attachment{{Filename: "virus.txt", Data: []byte("x")}}
	if _, err := svc.Update(ctx, tenant, c.ID, Update{Attachments: &bad}); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("rejected file accepted: %v", err)
	}
	if files.files[c.ID][0].Filename != "a.pdf" {
		t.Fatal("a rejected update replaced the files")
	}
	none := []domainmsg.Attachment{}
	if u, err := svc.Update(ctx, tenant, c.ID, Update{Attachments: &none}); err != nil || len(u.Attachments) != 0 || len(files.files[c.ID]) != 0 {
		t.Fatalf("clear: %+v %v", u.Attachments, err)
	}
	if n := len(log.actions); n != 3 || log.actions[n-1] != "campaign.updated" {
		t.Fatalf("audit %v", log.actions)
	}
	in.Attachments = bad
	if _, err := svc.Create(ctx, tenant, in); apperrors.KindOf(err) != apperrors.KindInvalidInput || len(files.files) != 1 {
		t.Fatalf("rejected create: %v, stored %d", err, len(files.files))
	}
}

func TestCampaignAttachmentsNeedTheStore(t *testing.T) {
	svc, _, _, _ := setup(true)
	in := draft()
	in.Attachments = []domainmsg.Attachment{{Filename: "a.pdf", Data: []byte("a")}}
	if _, err := svc.Create(context.Background(), tenant, in); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("no store: %v", err)
	}
}
