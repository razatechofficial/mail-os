package smtp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"unicode/utf8"

	gosmtp "github.com/emersion/go-smtp"
	"golang.org/x/text/encoding/htmlindex"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
)

// Bounds of the MIME structure a submission may have.
const (
	maxDepth = 4
	maxParts = 16
)

// submitted is what MailOS keeps of a submitted message. Everything else
// in it (Bcc, Cc, Received, Sender, Return-Path, X-…, its Message-ID and
// any DKIM-Signature) is dropped: MailOS writes the message again, one per
// recipient, with its own Message-ID and DKIM signature.
type submitted struct {
	From    *mail.Address
	ReplyTo string
	Subject string
	Text    string
	HTML    string
	// MessageID is the client's Message-ID: the idempotency key of the
	// transaction's messages, so a retried transaction sends nothing twice.
	MessageID string
	// Names are the display names of the To and Cc addresses, by address.
	Names map[string]string
	// Headers are the carried headers (List-Unsubscribe).
	Headers map[string]string
	// Attachments are the files: parts with an attachment disposition or a
	// file name, inline parts by Content-ID, and anything that is not a
	// text or HTML body (a forwarded message is attached as .eml). The
	// message pipeline checks them against the attachment limits.
	Attachments []domainmsg.Attachment
}

// contentError refuses a message for its content; Reason is for the audit
// trail and the metrics.
type contentError struct {
	reply  *gosmtp.SMTPError
	reason string
}

func (e *contentError) Error() string { return e.reply.Message }

func malformed(format string, args ...any) error {
	return &contentError{reason: "malformed_message", reply: &gosmtp.SMTPError{Code: 554,
		EnhancedCode: gosmtp.EnhancedCode{5, 6, 0}, Message: fmt.Sprintf(format, args...)}}
}

func unsupported(format string, args ...any) error {
	return &contentError{reason: "unsupported_content", reply: &gosmtp.SMTPError{Code: 554,
		EnhancedCode: gosmtp.EnhancedCode{5, 6, 1}, Message: fmt.Sprintf(format, args...)}}
}

var decoder = &mime.WordDecoder{CharsetReader: charsetReader}

// parseMessage reads a submitted RFC 5322 message: its addresses, subject,
// carried headers, its text and HTML bodies decoded to UTF-8, and its
// attachments and inline parts. Nothing is dropped silently: a part that
// cannot be read refuses the message.
func parseMessage(raw []byte) (submitted, error) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return submitted{}, malformed("Message headers cannot be read")
	}
	h := m.Header
	out := submitted{Names: map[string]string{}, Headers: map[string]string{}}
	parser := &mail.AddressParser{WordDecoder: decoder}

	switch from := h["From"]; len(from) {
	case 0:
	case 1:
		list, err := parser.ParseList(from[0])
		if err != nil || len(list) != 1 {
			return submitted{}, malformed("The From header must name exactly one address")
		}
		out.From = list[0]
	default:
		return submitted{}, malformed("The message has more than one From header")
	}
	if v := h.Get("Reply-To"); v != "" {
		list, err := parser.ParseList(v)
		if err != nil || len(list) == 0 {
			return submitted{}, malformed("The Reply-To header cannot be read")
		}
		out.ReplyTo = list[0].Address
	}
	for _, field := range []string{"To", "Cc"} {
		for _, v := range h[field] {
			list, _ := parser.ParseList(v) // display names only: a bad list costs a name, not the message
			for _, a := range list {
				if a.Name != "" {
					out.Names[strings.ToLower(a.Address)] = oneLine(a.Name)
				}
			}
		}
	}
	if len(h["Subject"]) > 1 {
		return submitted{}, malformed("The message has more than one Subject header")
	}
	subject, err := decoder.DecodeHeader(h.Get("Subject"))
	if err != nil {
		subject = h.Get("Subject")
	}
	out.Subject = strings.TrimSpace(oneLine(subject))
	if id := strings.TrimSpace(h.Get("Message-Id")); id != "" && len(id) <= 255 && !strings.ContainsAny(id, "\r\n") {
		out.MessageID = id
	}
	if err := carried(h, out.Headers); err != nil {
		return submitted{}, err
	}

	parts := 0
	if err := walk(h, m.Body, 0, &parts, &out); err != nil {
		return submitted{}, err
	}
	if out.Text == "" && out.HTML == "" {
		return submitted{}, malformed("The message has no text or HTML body")
	}
	return out, nil
}

// carried copies List-Unsubscribe and List-Unsubscribe-Post, checked:
// the first must hold an https or mailto URI in angle brackets (RFC 2369),
// the second may only be the one-click value (RFC 8058).
func carried(h mail.Header, into map[string]string) error {
	if v := strings.TrimSpace(h.Get("List-Unsubscribe")); v != "" {
		if len(v) > 998 || strings.ContainsAny(v, "\r\n") || !(strings.Contains(v, "<https://") || strings.Contains(v, "<mailto:")) {
			return malformed("List-Unsubscribe must hold an https or mailto URI in angle brackets (RFC 2369)")
		}
		into["List-Unsubscribe"] = v
	}
	if v := strings.TrimSpace(h.Get("List-Unsubscribe-Post")); v != "" {
		if v != "List-Unsubscribe=One-Click" || into["List-Unsubscribe"] == "" || !strings.Contains(into["List-Unsubscribe"], "<https://") {
			return malformed("List-Unsubscribe-Post must be List-Unsubscribe=One-Click, with an https List-Unsubscribe (RFC 8058)")
		}
		into["List-Unsubscribe-Post"] = v
	}
	return nil
}

// mimeHeader is the part of a header walk reads.
type mimeHeader interface{ Get(string) string }

// walk reads one MIME entity into out: a text/plain or text/html leaf, or
// a multipart whose parts are read in turn.
func walk(h mimeHeader, body io.Reader, depth int, parts *int, out *submitted) error {
	if *parts++; *parts > maxParts || depth > maxDepth {
		return unsupported("The message has too many MIME parts")
	}
	ctype := h.Get("Content-Type")
	if ctype == "" {
		ctype = "text/plain; charset=us-ascii"
	}
	media, params, err := mime.ParseMediaType(ctype)
	if err != nil {
		return malformed("A Content-Type header cannot be read")
	}
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	if disp == "attachment" || dparams["filename"] != "" || (params["name"] != "" && !strings.HasPrefix(media, "multipart/")) {
		return attach(h, body, media, params, disp, dparams, out)
	}
	if strings.HasPrefix(media, "multipart/") {
		if params["boundary"] == "" {
			return malformed("A multipart part has no boundary")
		}
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return malformed("A multipart part cannot be read")
			}
			if err := walk(p.Header, p, depth+1, parts, out); err != nil {
				return err
			}
		}
	}
	var target *string
	switch media {
	case "text/plain":
		target = &out.Text
	case "text/html":
		target = &out.HTML
	default:
		// An inline image of a multipart/related, a forwarded message, any
		// other file without a disposition.
		return attach(h, body, media, params, disp, dparams, out)
	}
	if *target != "" {
		return unsupported("The message has more than one %s body", media)
	}
	text, err := decodeBody(body, h.Get("Content-Transfer-Encoding"), params["charset"])
	if err != nil {
		return err
	}
	*target = text
	return nil
}

// attach reads a file part into out.Attachments: its bytes (transfer
// encoding undone, no charset conversion), its name (Content-Disposition
// filename, else Content-Type name, RFC 2231 or 2047 encoded; else made
// up from the type), its type and its Content-ID.
func attach(h mimeHeader, body io.Reader, media string, params map[string]string, disp string, dparams map[string]string, out *submitted) error {
	data, err := decodeBytes(body, h.Get("Content-Transfer-Encoding"))
	if err != nil {
		return err
	}
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	if d, err := decoder.DecodeHeader(name); err == nil {
		name = d
	}
	name = strings.TrimSpace(oneLine(name))
	if name == "" {
		ext := ".bin"
		switch {
		case media == "message/rfc822":
			ext = ".eml"
		default:
			if exts, _ := mime.ExtensionsByType(media); len(exts) > 0 {
				ext = exts[0]
			}
		}
		name = fmt.Sprintf("attachment-%d%s", len(out.Attachments)+1, ext)
	}
	ct := media
	if cs := params["charset"]; cs != "" {
		ct = mime.FormatMediaType(media, map[string]string{"charset": cs})
	}
	cid := strings.Trim(strings.TrimSpace(h.Get("Content-Id")), "<>")
	out.Attachments = append(out.Attachments, domainmsg.Attachment{Filename: name, ContentType: ct, ContentID: cid,
		Inline: disp == "inline" || (disp == "" && cid != ""), Data: data})
	return nil
}

// decodeBytes undoes a part's transfer encoding.
func decodeBytes(body io.Reader, cte string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "", "7bit", "8bit", "binary":
	case "base64":
		body = base64.NewDecoder(base64.StdEncoding, &stripSpace{r: body})
	case "quoted-printable":
		body = quotedprintable.NewReader(body)
	default:
		return nil, malformed("Content-Transfer-Encoding %q is not supported", cte)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, malformed("An attachment cannot be decoded")
	}
	return raw, nil
}

// decodeBody undoes the transfer encoding and converts the charset to
// UTF-8. (multipart.Reader has already undone quoted-printable in parts.)
func decodeBody(body io.Reader, cte, charset string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "", "7bit", "8bit", "binary":
	case "base64":
		body = base64.NewDecoder(base64.StdEncoding, &stripSpace{r: body})
	case "quoted-printable":
		body = quotedprintable.NewReader(body)
	default:
		return "", malformed("Content-Transfer-Encoding %q is not supported", cte)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return "", malformed("A body cannot be decoded")
	}
	r, err := charsetReader(charset, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	text, err := io.ReadAll(r)
	if err != nil {
		return "", malformed("A body cannot be decoded from %s", charset)
	}
	if !utf8.Valid(text) {
		return "", malformed("A body is not valid %s", charsetName(charset))
	}
	return strings.ReplaceAll(string(text), "\x00", ""), nil
}

// charsetReader converts from a declared charset to UTF-8 (WHATWG
// encoding names: windows-1252, iso-8859-1, shift_jis…).
func charsetReader(charset string, r io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return r, nil
	}
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return nil, malformed("Charset %q is not supported", charset)
	}
	return enc.NewDecoder().Reader(r), nil
}

func charsetName(c string) string {
	if c == "" {
		return "us-ascii"
	}
	return c
}

func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\x00", "").Replace(s)
}

// stripSpace drops the line breaks and spaces of a base64 body.
type stripSpace struct{ r io.Reader }

func (s *stripSpace) Read(p []byte) (int, error) {
	for {
		n, err := s.r.Read(p)
		j := 0
		for _, c := range p[:n] {
			if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
				p[j] = c
				j++
			}
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}
