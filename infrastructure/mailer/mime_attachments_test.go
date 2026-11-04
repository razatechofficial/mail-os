package mailer

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/razatechofficial/mail-os/domain/message"
)

func withFiles(o message.Outgoing) message.Outgoing {
	o.Attachments = []message.Attachment{
		{Filename: "Kontoauszug März.pdf", ContentType: "application/pdf", Data: bytes.Repeat([]byte("%PDF"), 40)},
		{Filename: "logo.png", ContentType: "image/png", ContentID: "logo", Inline: true, Data: []byte("png-bytes")},
	}
	return o
}

// media returns a part's media type and its parameters.
func media(t *testing.T, h interface{ Get(string) string }) (string, map[string]string) {
	t.Helper()
	m, p, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	return m, p
}

// The structure is mixed(related(alternative(text, html), inline), file),
// the files decode to their bytes, and the DKIM signature verifies.
func TestBuildMIMEWithAttachments(t *testing.T) {
	o := withFiles(sampleOutgoing())
	raw, _ := buildMIME(o, time.Now())
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, p := media(t, msg.Header)
	if mt != "multipart/mixed" {
		t.Fatalf("top %s", mt)
	}
	mixed := multipart.NewReader(msg.Body, p["boundary"])
	related, err := mixed.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if mt, p = media(t, related.Header); mt != "multipart/related" {
		t.Fatalf("first part %s", mt)
	}
	rel := multipart.NewReader(related, p["boundary"])
	alt, _ := rel.NextPart()
	if mt, _ = media(t, alt.Header); mt != "multipart/alternative" {
		t.Fatalf("body %s", mt)
	}
	logo, _ := rel.NextPart()
	if logo.Header.Get("Content-Id") != "<logo>" || !strings.HasPrefix(logo.Header.Get("Content-Disposition"), "inline") {
		t.Fatalf("inline part %v", logo.Header)
	}
	file, err := mixed.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if file.FileName() != "Kontoauszug März.pdf" {
		t.Fatalf("file name %q (%s)", file.FileName(), file.Header.Get("Content-Disposition"))
	}
	// multipart.Reader undoes quoted-printable only: the part is base64.
	data, _ := io.ReadAll(file)
	if !strings.HasPrefix(string(data), "JVBERiVQREYl") || file.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatal("pdf not base64 encoded")
	}
	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("line over 998 characters: %d", len(line))
		}
	}

	key, lookup := signingKey(t, "bank.example")
	signed, err := signDKIM(raw, o.From.Email, *key)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(signed), &dkim.VerifyOptions{LookupTXT: lookup})
	if err != nil || len(vs) != 1 || vs[0].Err != nil {
		t.Fatalf("verify: %v %+v", err, vs)
	}
}

func TestBuildMIMETextWithOneAttachment(t *testing.T) {
	o := message.Outgoing{From: message.Address{Email: "a@bank.example"}, To: message.Address{Email: "b@example.com"},
		Subject: "s", Text: "see attached",
		Attachments: []message.Attachment{{Filename: "a.txt", ContentType: "text/plain; charset=utf-8", Data: []byte("hello")}}}
	raw, _ := buildMIME(o, time.Now())
	msg, _ := mail.ReadMessage(bytes.NewReader(raw))
	mt, p := media(t, msg.Header)
	if mt != "multipart/mixed" {
		t.Fatalf("top %s", mt)
	}
	r := multipart.NewReader(msg.Body, p["boundary"])
	body, _ := r.NextPart()
	if mt, _ := media(t, body.Header); mt != "text/plain" {
		t.Fatalf("body %s", mt)
	}
	file, _ := r.NextPart()
	if _, fp := media(t, file.Header); fp["charset"] != "utf-8" || fp["name"] != "a.txt" {
		t.Fatalf("file %v", file.Header)
	}
	if !strings.Contains(string(raw), "aGVsbG8=") {
		t.Fatal("content not base64")
	}
}
