package mailer

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
)

func sampleOutgoing() message.Outgoing {
	return message.Outgoing{
		TenantID:  "org-1",
		MessageID: "0192f0c4-7b1e-7cc0-9d2e-1a2b3c4d5e6f",
		From:      message.Address{Name: "Bank Security", Email: "security@mail.bank.example"},
		To:        message.Address{Name: "Zoë Müller", Email: "zoe@example.com"},
		ReplyTo:   message.Address{Email: "help@bank.example"},
		Subject:   "Ihr Bestätigungscode " + strings.Repeat("lang ", 30),
		HTML:      "<p>Code: <b>482913</b></p>" + strings.Repeat("x", 2000),
		Text:      "Code: 482913",
		Headers:   map[string]string{"List-Unsubscribe": "<mailto:unsub@bank.example>", "X-Campaign": "otp"},
		Tags:      []string{"otp"},
	}
}

// signingKey returns a verified domain's key and its DNS lookup.
func signingKey(t *testing.T, name string) (*sendingdomain.SigningKey, func(string) ([]string, error)) {
	t.Helper()
	d, s, err := sendingdomain.New("org-1", name, sendingdomain.Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d.ApplyCheck(sendingdomain.Check{DKIM: true, SPF: true}, time.Now())
	k, ok := d.SigningKey(s)
	if !ok {
		t.Fatal("no signing key")
	}
	lookup := func(q string) ([]string, error) {
		if q == d.DKIMRecordName() {
			return []string{d.DKIMRecordValue()}, nil
		}
		return nil, errors.New("no such record")
	}
	return &k, lookup
}

func TestBuildMIME(t *testing.T) {
	raw, id := buildMIME(sampleOutgoing(), time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC))
	for i, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("line %d is %d characters", i, len(line))
		}
	}
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if id != "<0192f0c4-7b1e-7cc0-9d2e-1a2b3c4d5e6f@mail.bank.example>" || m.Header.Get("Message-ID") != id {
		t.Fatalf("message id %q", id)
	}
	dec := new(mime.WordDecoder)
	subject, _ := dec.DecodeHeader(m.Header.Get("Subject"))
	if subject != sampleOutgoing().Subject {
		t.Fatalf("subject %q", subject)
	}
	to, err := m.Header.AddressList("To")
	if err != nil || to[0].Name != "Zoë Müller" {
		t.Fatalf("to %v %v", to, err)
	}
	if m.Header.Get("List-Unsubscribe") == "" || m.Header.Get("X-Campaign") != "otp" {
		t.Fatal("custom headers missing")
	}
	_, params, _ := mime.ParseMediaType(m.Header.Get("Content-Type"))
	mr := multipart.NewReader(m.Body, params["boundary"])
	var types []string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(p) // multipart decodes quoted-printable
		types = append(types, p.Header.Get("Content-Type"))
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") && !strings.Contains(string(body), "<b>482913</b>") {
			t.Fatal("html part not decoded")
		}
	}
	if len(types) != 2 || !strings.HasPrefix(types[0], "text/plain") {
		t.Fatalf("parts %v", types)
	}
}

func TestBuildMIMEUnsafeMessageIDReplaced(t *testing.T) {
	o := sampleOutgoing()
	o.MessageID = "x>\r\nBcc: evil@example.com"
	_, id := buildMIME(o, time.Now())
	if strings.ContainsAny(id, "\r\n ") || !strings.HasSuffix(id, "@mail.bank.example>") {
		t.Fatalf("id %q", id)
	}
}

func TestDKIMSignatureVerifies(t *testing.T) {
	key, lookup := signingKey(t, "bank.example")
	o := sampleOutgoing() // From mail.bank.example: aligned under bank.example
	raw, _ := buildMIME(o, time.Now())
	signed, err := signDKIM(raw, o.From.Email, *key)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(signed), &dkim.VerifyOptions{LookupTXT: lookup})
	if err != nil || len(vs) != 1 || vs[0].Err != nil || vs[0].Domain != "bank.example" {
		t.Fatalf("verify: %v %+v", err, vs)
	}
	// A changed subject breaks the signature.
	tampered := bytes.Replace(signed, []byte("Subject: "), []byte("Subject: Re: "), 1)
	vs, _ = dkim.VerifyWithOptions(bytes.NewReader(tampered), &dkim.VerifyOptions{LookupTXT: lookup})
	if len(vs) != 1 || vs[0].Err == nil {
		t.Fatal("tampered message verified")
	}
}

func TestDKIMSkipsUnalignedSender(t *testing.T) {
	key, _ := signingKey(t, "other.example")
	raw, _ := buildMIME(sampleOutgoing(), time.Now())
	out, err := signDKIM(raw, "security@mail.bank.example", *key)
	if err != nil || !bytes.Equal(out, raw) {
		t.Fatal("signed for an unaligned domain")
	}
}

func TestBackoffGrowsWithJitter(t *testing.T) {
	for n, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second} {
		got := Backoff(time.Second, n)
		if got < want*8/10 || got > want*12/10 {
			t.Errorf("Backoff(%d) = %v", n, got)
		}
	}
}
