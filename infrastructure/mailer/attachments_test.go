package mailer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/razatechofficial/mail-os/domain/provider"
)

// pdfB64 is withFiles' PDF as a JSON API carries it.
var pdfB64 = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("%PDF", 40)))

// Every HTTP API provider carries the files in its own attachment fields:
// the PDF's bytes and name, and the inline logo by its Content-ID.
func TestHTTPProvidersCarryAttachments(t *testing.T) {
	acsKey := base64.StdEncoding.EncodeToString([]byte("acs-access-key-0123456789"))
	cases := []struct {
		kind  provider.Kind
		build func(Options) (Sender, error)
		ok    http.HandlerFunc
		// want are fragments of the request body.
		want []string
	}{
		{provider.KindSendGrid, func(o Options) (Sender, error) {
			return NewSendGrid(provider.Settings{}, provider.Credentials{APIKey: "SG.key"}, o)
		}, reply(202, ``, "X-Message-Id", "sg-1"),
			[]string{`"attachments":[`, pdfB64, `"filename":"Kontoauszug März.pdf"`, `"disposition":"inline"`, `"content_id":"logo"`}},
		{provider.KindPostmark, func(o Options) (Sender, error) {
			return NewPostmark(provider.Settings{}, provider.Credentials{ServerToken: "t"}, o)
		}, reply(200, `{"ErrorCode":0,"Message":"OK","MessageID":"pm-1"}`),
			[]string{`"Attachments":[`, pdfB64, `"ContentID":"cid:logo"`}},
		{provider.KindSparkPost, func(o Options) (Sender, error) {
			return NewSparkPost(provider.Settings{}, provider.Credentials{APIKey: "k"}, o)
		}, reply(200, `{"results":{"total_rejected_recipients":0,"total_accepted_recipients":1,"id":"tx-1"}}`),
			[]string{`"attachments":[{"name":"Kontoauszug März.pdf"`, `"inline_images":[{"name":"logo","type":"image/png"`, pdfB64}},
		{provider.KindBrevo, func(o Options) (Sender, error) {
			return NewBrevo(provider.Settings{}, provider.Credentials{APIKey: "k"}, o)
		}, reply(201, `{"messageId":"<b-1>"}`),
			[]string{`"attachment":[`, pdfB64, `"name":"logo.png"`}},
		{provider.KindMailjet, func(o Options) (Sender, error) {
			return NewMailjet(provider.Settings{}, provider.Credentials{APIKey: "a", APISecret: "b"}, o)
		}, reply(200, `{"Messages":[{"Status":"success","To":[{"Email":"zoe@example.com","MessageUUID":"u-1","MessageID":1}]}]}`),
			[]string{`"Attachments":[`, `"InlinedAttachments":[`, `"ContentID":"logo"`, pdfB64}},
		{provider.KindMandrill, func(o Options) (Sender, error) {
			return NewMandrill(provider.Settings{}, provider.Credentials{APIKey: "k"}, o)
		}, reply(200, `[{"email":"zoe@example.com","status":"sent","_id":"md-1"}]`),
			[]string{`"attachments":[`, `"images":[{"type":"image/png","name":"logo"`, pdfB64}},
		{provider.KindResend, func(o Options) (Sender, error) {
			return NewResend(provider.Settings{}, provider.Credentials{APIKey: "re_1"}, o)
		}, reply(200, `{"id":"re-1"}`),
			[]string{`"attachments":[`, pdfB64, `"content_id":"logo"`}},
		{provider.KindACS, func(o Options) (Sender, error) {
			return NewACS(provider.Settings{Endpoint: "https://bank.unitedstates.communication.azure.com"}, provider.Credentials{AccessKey: acsKey}, o)
		}, reply(202, `{"id":"op-1","status":"Running"}`, "Operation-Location", "https://x/emails/operations/op-1"),
			[]string{`"attachments":[`, `"contentInBase64":"` + pdfB64, `"contentId":"logo"`}},
	}
	for _, c := range cases {
		t.Run(string(c.kind), func(t *testing.T) {
			srv := newAPIServer(t)
			var body string
			srv.handle(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				body = string(raw)
				c.ok(w, r)
			})
			snd, err := c.build(srv.opts(c.kind))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snd.Send(context.Background(), withFiles(sampleOutgoing())); err != nil {
				t.Fatal(err)
			}
			for _, w := range c.want {
				if !strings.Contains(body, w) {
					t.Errorf("body lacks %q:\n%.600s", w, body)
				}
			}
		})
	}
}

// SES sends a message with files as raw MIME.
func TestSESSendsAttachmentsAsRawMIME(t *testing.T) {
	srv := newAPIServer(t)
	var got sesRequest
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		reply(200, `{"MessageId":"010001-ses"}`)(w, r)
	})
	snd, err := NewSES(provider.Settings{Region: "eu-west-1"}, provider.Credentials{AccessKeyID: "AKIATEST", SecretAccessKey: "s"}, srv.opts(provider.KindSES))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snd.Send(context.Background(), withFiles(sampleOutgoing())); err != nil {
		t.Fatal(err)
	}
	if got.Content.Simple != nil || got.Content.Raw == nil {
		t.Fatalf("content %+v", got.Content)
	}
	raw, err := base64.StdEncoding.DecodeString(got.Content.Raw.Data)
	if err != nil || !strings.Contains(string(raw), "multipart/mixed") || !strings.Contains(string(raw), "Content-Id: <logo>") ||
		!strings.Contains(string(raw), "List-Unsubscribe") || strings.Contains(string(raw), "DKIM-Signature") {
		t.Fatalf("raw %v\n%.800s", err, raw)
	}
}

// Mailgun switches to multipart/form-data, inline parts named by
// Content-ID.
func TestMailgunSendsFilesAsMultipart(t *testing.T) {
	srv := newAPIServer(t)
	var files, inline []string
	var tags []string
	srv.handle(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("not multipart: %v", err)
		}
		for _, f := range r.MultipartForm.File["attachment"] {
			files = append(files, f.Filename)
		}
		for _, f := range r.MultipartForm.File["inline"] {
			inline = append(inline, f.Filename)
		}
		tags = r.MultipartForm.Value["o:tag"]
		reply(200, `{"id":"<1@mg.bank.example>"}`)(w, r)
	})
	snd, err := NewMailgun(provider.Settings{Domain: "mg.bank.example"}, provider.Credentials{APIKey: "key-1"}, srv.opts(provider.KindMailgun))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snd.Send(context.Background(), withFiles(sampleOutgoing())); err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "Kontoauszug März.pdf" || len(inline) != 1 || inline[0] != "logo" || len(tags) != 1 {
		t.Fatalf("files %v inline %v tags %v", files, inline, tags)
	}
}
