package smtp

import (
	"errors"
	"strings"
	"testing"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

func TestParseMultipartAlternative(t *testing.T) {
	raw := crlf(`From: "Core Banking" <statements@alerts.bank.example>
To: "Amna Khan" <amna@example.com>, raza@example.com
Cc: =?utf-8?q?J=C3=BCrgen?= <jurgen@example.com>
Bcc: hidden@example.com
Reply-To: help@bank.example
Subject: =?utf-8?q?Your_statement_=E2=80=93_October?=
Message-ID: <20261103.1@core.bank.example>
X-Mailer: LegacyCore 4.2
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Dear customer, your statement is ready =E2=80=93 log in to read it.
--b1
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PHA+RGVhciBjdXN0b21lciwgeW91ciBzdGF0ZW1lbnQgaXMgcmVhZHkuPC9wPg==
--b1--
`)
	m, err := parseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.From.Address != "statements@alerts.bank.example" || m.From.Name != "Core Banking" || m.ReplyTo != "help@bank.example" {
		t.Fatalf("addresses %+v %q", m.From, m.ReplyTo)
	}
	if m.Subject != "Your statement – October" || m.MessageID != "<20261103.1@core.bank.example>" {
		t.Fatalf("subject %q id %q", m.Subject, m.MessageID)
	}
	if m.Text != "Dear customer, your statement is ready – log in to read it." || m.HTML != "<p>Dear customer, your statement is ready.</p>" {
		t.Fatalf("bodies %q %q", m.Text, m.HTML)
	}
	if m.Names["amna@example.com"] != "Amna Khan" || m.Names["jurgen@example.com"] != "Jürgen" {
		t.Fatalf("names %v", m.Names)
	}
	if len(m.Headers) != 0 {
		t.Fatalf("only List-Unsubscribe is carried: %v", m.Headers)
	}
}

func TestParseLegacyCharsetAndPlainBody(t *testing.T) {
	// A Windows-1252 body as old Windows software writes it: 0x96 is "–", 0xE9 "é".
	raw := append(crlf("From: ops@bank.example\nSubject: Caf\xe9 report\nContent-Type: text/plain; charset=windows-1252\n\nR\xe9sum\xe9 \x96 done\n"), nil...)
	m, err := parseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Text != "Résumé – done\r\n" {
		t.Fatalf("text %q", m.Text)
	}
}

func TestParseRefusesWhatCannotBeSent(t *testing.T) {
	cases := map[string]struct {
		raw    string
		reason string
	}{
		"two senders":    {"From: a@bank.example, b@bank.example\nSubject: s\n\nbody\n", "malformed_message"},
		"no body":        {"From: a@bank.example\nSubject: s\nContent-Type: text/plain\n\n", "malformed_message"},
		"bad charset":    {"From: a@bank.example\nSubject: s\nContent-Type: text/plain; charset=x-unknown\n\nbody\n", "malformed_message"},
		"not utf-8":      {"From: a@bank.example\nSubject: s\nContent-Type: text/plain; charset=utf-8\n\n\xff\xfe\n", "malformed_message"},
		"bad unsub":      {"From: a@bank.example\nSubject: s\nList-Unsubscribe: http://x\n\nbody\n", "malformed_message"},
		"post w/o https": {"From: a@bank.example\nSubject: s\nList-Unsubscribe: <mailto:u@bank.example>\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\n\nbody\n", "malformed_message"},
		"no boundary":    {"From: a@bank.example\nSubject: s\nContent-Type: multipart/mixed\n\nbody\n", "malformed_message"},
	}
	for name, c := range cases {
		_, err := parseMessage(crlf(c.raw))
		var ce *contentError
		if !errors.As(err, &ce) || ce.reason != c.reason {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseKeepsAttachmentsAndInlineParts(t *testing.T) {
	m, err := parseMessage(crlf(`From: a@bank.example
Subject: s
Content-Type: multipart/mixed; boundary=x

--x
Content-Type: multipart/related; boundary=y

--y
Content-Type: text/html

<img src="cid:logo">
--y
Content-Type: image/png
Content-ID: <logo>
Content-Transfer-Encoding: base64

cG5n
--y--
--x
Content-Type: application/pdf
Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf
Content-Transfer-Encoding: base64

JVBERi0=
--x
Content-Type: text/plain; charset=utf-8; name="=?utf-8?q?notes=2Etxt?="

plain file
--x
Content-Type: message/rfc822

From: b@bank.example
Subject: forwarded

hi
--x--
`))
	if err != nil {
		t.Fatal(err)
	}
	if m.HTML != "<img src=\"cid:logo\">" {
		t.Fatalf("html %q", m.HTML)
	}
	if len(m.Attachments) != 4 {
		t.Fatalf("attachments %+v", m.Attachments)
	}
	logo, pdf, notes, eml := m.Attachments[0], m.Attachments[1], m.Attachments[2], m.Attachments[3]
	if logo.ContentID != "logo" || !logo.Inline || string(logo.Data) != "png" || logo.ContentType != "image/png" || logo.Filename != "attachment-1.png" {
		t.Fatalf("logo %+v", logo)
	}
	if pdf.Filename != "résumé.pdf" || pdf.Inline || string(pdf.Data) != "%PDF-" {
		t.Fatalf("pdf %+v", pdf)
	}
	if eml.ContentType != "message/rfc822" || !strings.HasSuffix(eml.Filename, ".eml") {
		t.Fatalf("eml %+v", eml)
	}
	// A named text part is a file, not the body; its charset is kept.
	if notes.Filename != "notes.txt" || notes.ContentType != "text/plain; charset=utf-8" || string(notes.Data) != "plain file" || m.Text != "" {
		t.Fatalf("notes %+v, text %q", notes, m.Text)
	}
}

func TestParseCarriesOneClickUnsubscribe(t *testing.T) {
	m, err := parseMessage(crlf("From: news@bank.example\nSubject: Offers\n" +
		"List-Unsubscribe: <https://bank.example/u/abc>, <mailto:unsub@bank.example>\n" +
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click\nContent-Type: text/html\n\n<p>Offers</p>\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Headers["List-Unsubscribe"] != "<https://bank.example/u/abc>, <mailto:unsub@bank.example>" ||
		m.Headers["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" {
		t.Fatalf("headers %v", m.Headers)
	}
}
