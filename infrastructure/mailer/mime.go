package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
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

// entity is one MIME entity: its content headers and encoded body.
type entity struct {
	header textproto.MIMEHeader
	body   []byte
}

// textEntity is a text body, quoted-printable UTF-8.
func textEntity(contentType, body string) entity {
	return entity{header: textproto.MIMEHeader{
		"Content-Type":              {contentType + "; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	}, body: quotedPrintable(body)}
}

// multipartEntity wraps parts in a multipart/subtype entity.
func multipartEntity(subtype string, parts []entity) entity {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range parts {
		w, _ := mw.CreatePart(p.header)
		_, _ = w.Write(p.body)
	}
	_ = mw.Close()
	return entity{header: textproto.MIMEHeader{"Content-Type": {`multipart/` + subtype + `; boundary="` + mw.Boundary() + `"`}},
		body: body.Bytes()}
}

// fileEntity is an attachment or inline part, base64 in 76-character
// lines, its name RFC 2231-encoded when not ASCII.
func fileEntity(a message.Attachment) entity {
	media, params, err := mime.ParseMediaType(a.ContentType)
	if err != nil {
		media, params = "application/octet-stream", map[string]string{}
	}
	params["name"] = a.Filename
	ct := mime.FormatMediaType(media, params)
	if ct == "" {
		ct = media
	}
	disp := "attachment"
	if a.Inline {
		disp = "inline"
	}
	cd := mime.FormatMediaType(disp, map[string]string{"filename": a.Filename})
	if cd == "" {
		cd = disp
	}
	h := textproto.MIMEHeader{"Content-Type": {ct}, "Content-Disposition": {cd}, "Content-Transfer-Encoding": {"base64"}}
	if a.ContentID != "" {
		h.Set("Content-Id", "<"+a.ContentID+">")
	}
	enc := base64.StdEncoding.EncodeToString(a.Data)
	var b bytes.Buffer
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return entity{header: h, body: b.Bytes()}
}

// bodyEntity is the message's content: the text and HTML bodies
// (multipart/alternative, text first, when both are set), inside a
// multipart/related with the inline parts, inside a multipart/mixed with
// the attachments.
func bodyEntity(o message.Outgoing) entity {
	var e entity
	switch {
	case o.HTML != "" && o.Text != "":
		e = multipartEntity("alternative", []entity{textEntity("text/plain", o.Text), textEntity("text/html", o.HTML)})
	case o.HTML != "":
		e = textEntity("text/html", o.HTML)
	default:
		e = textEntity("text/plain", o.Text)
	}
	var inline, files []entity
	for _, a := range o.Attachments {
		if a.Inline {
			inline = append(inline, fileEntity(a))
		} else {
			files = append(files, fileEntity(a))
		}
	}
	if len(inline) > 0 {
		e = multipartEntity("related", append([]entity{e}, inline...))
	}
	if len(files) > 0 {
		e = multipartEntity("mixed", append([]entity{e}, files...))
	}
	return e
}

// buildMIME renders o as an RFC 5322 message (bodyEntity's structure).
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

	e := bodyEntity(o)
	writeHeader(&b, "Content-Type", e.header.Get("Content-Type"))
	if cte := e.header.Get("Content-Transfer-Encoding"); cte != "" {
		writeHeader(&b, "Content-Transfer-Encoding", cte)
	}
	b.WriteString("\r\n")
	b.Write(e.body)
	if !bytes.HasSuffix(e.body, []byte("\r\n")) {
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
