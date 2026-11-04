package mailer

import (
	"bytes"
	"encoding/base64"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"sort"
	"strings"

	"github.com/razatechofficial/mail-os/domain/message"
)

// b64 is a file's content for a JSON API (standard base64, no breaks).
func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// disposition is "inline" for a part shown by its Content-ID, else
// "attachment".
func disposition(a message.Attachment) string {
	if a.Inline {
		return "inline"
	}
	return "attachment"
}

// multipartForm encodes form and the files as multipart/form-data (the
// Mailgun API's way to send attachments): attachments as "attachment",
// inline parts as "inline" named by their Content-ID, which is how
// Mailgun's cid: references resolve.
func multipartForm(form url.Values, files []message.Attachment) (body []byte, contentType string) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	keys := make([]string, 0, len(form))
	for k := range form {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range form[k] {
			_ = mw.WriteField(k, v)
		}
	}
	quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	for _, a := range files {
		field, name := "attachment", a.Filename
		if a.Inline && a.ContentID != "" {
			field, name = "inline", a.ContentID
		}
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="`+field+`"; filename="`+quote.Replace(name)+`"`)
		h.Set("Content-Type", a.ContentType)
		w, _ := mw.CreatePart(h)
		_, _ = w.Write(a.Data)
	}
	_ = mw.Close()
	return b.Bytes(), mw.FormDataContentType()
}
