package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/sendingdomain"
)

// dkimHeaders are the fields signed (RFC 6376 §5.4.1). Absent ones are
// signed as empty, so they cannot be added in transit.
var dkimHeaders = []string{
	"From", "Reply-To", "Subject", "Date", "To", "Message-ID", "MIME-Version",
	"Content-Type", "Content-Transfer-Encoding", "List-Unsubscribe", "List-Unsubscribe-Post",
}

// messageID builds the Message-ID: the MailOS id at the sender's domain,
// or a random id when the message has none (or one unfit for the header).
func messageID(o message.Outgoing) string {
	id := o.MessageID
	if id == "" || strings.ContainsFunc(id, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_')
	}) {
		var b [16]byte
		_, _ = rand.Read(b[:])
		id = hex.EncodeToString(b[:])
	}
	domain := sendingdomain.FromDomain(o.From.Email)
	if domain == "" {
		domain = "mailos.invalid"
	}
	return "<" + id + "@" + domain + ">"
}

// encodeHeader encodes a non-ASCII value as RFC 2047 words.
func encodeHeader(v string) string { return mime.QEncoding.Encode("utf-8", v) }

// writeHeader writes one field, folded at spaces to keep lines under 78
// characters where the value allows (RFC 5322 §2.2.3).
func writeHeader(b *bytes.Buffer, name, value string) {
	line := name + ": "
	width := len(line)
	b.WriteString(line)
	for i, word := range strings.Split(value, " ") {
		if i > 0 {
			if width+1+len(word) > 76 {
				b.WriteString("\r\n ")
				width = 1
			} else {
				b.WriteByte(' ')
				width++
			}
		}
		b.WriteString(word)
		width += len(word)
	}
	b.WriteString("\r\n")
}

// quotedPrintable encodes a body part: 7-bit safe and with short lines,
// whatever the template produced.
func quotedPrintable(s string) []byte {
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

// buildMIME renders o as an RFC 5322 message: multipart/alternative with
// the text part first when both bodies are set.
func buildMIME(o message.Outgoing, now time.Time) (raw []byte, msgID string) {
	msgID = messageID(o)
	var b bytes.Buffer
	writeHeader(&b, "From", o.From.String())
	writeHeader(&b, "To", o.To.String())
	if !o.ReplyTo.IsZero() {
		writeHeader(&b, "Reply-To", o.ReplyTo.String())
	}
	writeHeader(&b, "Subject", encodeHeader(o.Subject))
	writeHeader(&b, "Date", now.Format(time.RFC1123Z))
	writeHeader(&b, "Message-ID", msgID)
	writeHeader(&b, "MIME-Version", "1.0")
	keys := make([]string, 0, len(o.Headers))
	for k := range o.Headers {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		writeHeader(&b, textproto.CanonicalMIMEHeaderKey(k), encodeHeader(o.Headers[k]))
	}

	part := func(contentType, body string) (textproto.MIMEHeader, []byte) {
		return textproto.MIMEHeader{
			"Content-Type":              {contentType + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		}, quotedPrintable(body)
	}
	if o.HTML != "" && o.Text != "" {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for _, p := range []struct{ ct, s string }{{"text/plain", o.Text}, {"text/html", o.HTML}} {
			h, data := part(p.ct, p.s)
			w, _ := mw.CreatePart(h)
			_, _ = w.Write(data)
		}
		_ = mw.Close()
		writeHeader(&b, "Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
		b.WriteString("\r\n")
		b.Write(body.Bytes())
		return b.Bytes(), msgID
	}
	ct, s := "text/plain", o.Text
	if o.HTML != "" {
		ct, s = "text/html", o.HTML
	}
	h, data := part(ct, s)
	writeHeader(&b, "Content-Type", h.Get("Content-Type"))
	writeHeader(&b, "Content-Transfer-Encoding", h.Get("Content-Transfer-Encoding"))
	b.WriteString("\r\n")
	b.Write(data)
	if !bytes.HasSuffix(data, []byte("\r\n")) {
		b.WriteString("\r\n")
	}
	return b.Bytes(), msgID
}

// aligned reports whether the sender's domain is the key's domain or under
// it (DMARC relaxed alignment, RFC 7489 §3.1.1).
func aligned(from string, key sendingdomain.SigningKey) bool {
	d := sendingdomain.FromDomain(from)
	return d == key.Domain || strings.HasSuffix(d, "."+key.Domain)
}

// signDKIM adds a DKIM-Signature (rsa-sha256, relaxed/relaxed) when the
// sender is aligned with the key; otherwise raw is returned unsigned, as
// a signature for another domain does not help DMARC.
func signDKIM(raw []byte, from string, key sendingdomain.SigningKey) ([]byte, error) {
	if !aligned(from, key) {
		return raw, nil
	}
	pk, err := sendingdomain.ParsePrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = dkim.Sign(&out, bytes.NewReader(raw), &dkim.SignOptions{
		Domain:                 key.Domain,
		Selector:               key.Selector,
		Signer:                 pk,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             dkimHeaders,
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
