package message

import (
	"strings"
	"testing"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

var limits = AttachmentLimits{MaxBytes: 10, MaxTotalBytes: 15, MaxCount: 4}

func fields(err error) map[string]string {
	out := map[string]string{}
	for _, d := range apperrors.DetailsOf(err) {
		out[d.Field] = d.Code
	}
	return out
}

func TestNormalizeAttachments(t *testing.T) {
	list := []Attachment{
		{Filename: " report.pdf ", Data: []byte("x")},
		{Filename: "logo.png", ContentType: "Image/PNG; name=logo.png", ContentID: "<logo>", Inline: true, Data: []byte("x")},
		{Filename: "blob", Data: []byte("x")},
		{Filename: "notes.txt", ContentType: "text/plain; charset=UTF-8; name=notes.txt", Data: []byte("x")},
	}
	NormalizeAttachments(list)
	if list[0].Filename != "report.pdf" || list[0].ContentType != "application/pdf" {
		t.Fatalf("pdf: %+v", list[0])
	}
	if list[1].ContentType != "image/png" || list[1].ContentID != "logo" {
		t.Fatalf("png: %+v", list[1])
	}
	if list[2].ContentType != "application/octet-stream" {
		t.Fatalf("blob: %+v", list[2])
	}
	if list[3].ContentType != "text/plain; charset=UTF-8" {
		t.Fatalf("text: %+v", list[3])
	}
	if err := ValidateAttachments(list, limits); err != nil {
		t.Fatalf("valid list refused: %v", err)
	}
}

func TestValidateAttachmentsRefusals(t *testing.T) {
	cases := []struct {
		name  string
		list  []Attachment
		lim   AttachmentLimits
		field string
		code  string
	}{
		{"off", []Attachment{{Filename: "a.pdf", ContentType: "application/pdf", Data: []byte("x")}}, AttachmentLimits{}, "attachments", "not_allowed"},
		{"too many", make4(), limits, "attachments", "too_many"},
		{"no name", []Attachment{{ContentType: "text/plain", Data: []byte("x")}}, limits, "attachments[0].filename", "required"},
		{"path", []Attachment{{Filename: "../etc/passwd", ContentType: "text/plain", Data: []byte("x")}}, limits, "attachments[0].filename", "invalid"},
		{"exe", []Attachment{{Filename: "invoice.pdf.exe", ContentType: "application/pdf", Data: []byte("x")}}, limits, "attachments[0].filename", "blocked_type"},
		{"configured ext", []Attachment{{Filename: "a.zip", ContentType: "application/zip", Data: []byte("x")}},
			AttachmentLimits{MaxBytes: 10, MaxTotalBytes: 10, MaxCount: 1, BlockedExtensions: []string{".ZIP"}}, "attachments[0].filename", "blocked_type"},
		{"js type", []Attachment{{Filename: "a.txt", ContentType: "text/javascript", Data: []byte("x")}}, limits, "attachments[0].content_type", "blocked_type"},
		{"not allowed type", []Attachment{{Filename: "a.txt", ContentType: "text/plain", Data: []byte("x")}},
			AttachmentLimits{MaxBytes: 10, MaxTotalBytes: 10, MaxCount: 1, AllowedTypes: []string{"image/*", "application/pdf"}}, "attachments[0].content_type", "blocked_type"},
		{"bad type", []Attachment{{Filename: "a.txt", ContentType: "nonsense", Data: []byte("x")}}, limits, "attachments[0].content_type", "invalid"},
		{"empty", []Attachment{{Filename: "a.txt", ContentType: "text/plain"}}, limits, "attachments[0].content", "required"},
		{"large", []Attachment{{Filename: "a.txt", ContentType: "text/plain", Data: []byte(strings.Repeat("x", 11))}}, limits, "attachments[0].content", "too_large"},
		{"total", []Attachment{{Filename: "a.txt", ContentType: "text/plain", Data: []byte(strings.Repeat("x", 8))},
			{Filename: "b.txt", ContentType: "text/plain", Data: []byte(strings.Repeat("x", 8))}}, limits, "attachments", "too_large"},
		{"inline without cid", []Attachment{{Filename: "a.png", ContentType: "image/png", Inline: true, Data: []byte("x")}}, limits, "attachments[0].content_id", "required"},
		{"cid with space", []Attachment{{Filename: "a.png", ContentType: "image/png", ContentID: "a b", Data: []byte("x")}}, limits, "attachments[0].content_id", "invalid"},
		{"duplicate cid", []Attachment{{Filename: "a.png", ContentType: "image/png", ContentID: "x", Data: []byte("x")},
			{Filename: "b.png", ContentType: "image/png", ContentID: "x", Data: []byte("x")}}, limits, "attachments[1].content_id", "duplicate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateAttachments(c.list, c.lim)
			if apperrors.KindOf(err) != apperrors.KindInvalidInput {
				t.Fatalf("err = %v", err)
			}
			if got := fields(err)[c.field]; got != c.code {
				t.Fatalf("fields = %v, want %s=%s", fields(err), c.field, c.code)
			}
		})
	}
}

func make4() []Attachment {
	out := make([]Attachment, 5)
	for i := range out {
		out[i] = Attachment{Filename: "a.txt", ContentType: "text/plain", Data: []byte("x")}
	}
	return out
}

func TestAttachmentsTravelAndArePurged(t *testing.T) {
	m := Message{ID: "m1", OrgID: "t", FromEmail: "a@example.com", ToEmail: "b@example.com", Subject: "s", TextBody: "t",
		Attachments: []Attachment{{Filename: "a.txt", ContentType: "text/plain", Data: []byte("hello")}}}
	out, err := m.Outgoing()
	if err != nil || len(out.Attachments) != 1 || string(out.Attachments[0].Data) != "hello" {
		t.Fatalf("outgoing = %+v, %v", out.Attachments, err)
	}
	if AttachmentsSize(out.Attachments) != 5 {
		t.Fatal("size")
	}
	m.Status = StatusSent
	m.PurgeBody(time.Now())
	if m.Attachments != nil {
		t.Fatal("purge kept the attachments")
	}
}
