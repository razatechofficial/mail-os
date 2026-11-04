package message

import (
	"fmt"
	"mime"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Attachment is a file a message carries: an attachment, or an inline
// part the HTML body shows by its Content-ID (<img src="cid:logo">).
type Attachment struct {
	Filename    string
	ContentType string
	// ContentID names an inline part, without angle brackets.
	ContentID string
	Inline    bool
	Data      []byte
}

// AttachmentLimits bound a message's files (ATTACHMENTS_*).
type AttachmentLimits struct {
	MaxBytes      int64
	MaxTotalBytes int64
	// MaxCount 0 refuses every attachment.
	MaxCount int
	// AllowedTypes, when set, are the only types accepted ("image/*").
	AllowedTypes []string
	// BlockedTypes and BlockedExtensions add to the built-in lists.
	BlockedTypes      []string
	BlockedExtensions []string
}

// blockedTypes are executable and script types never sent, whatever the
// configuration.
var blockedTypes = []string{
	"application/x-msdownload", "application/x-msdos-program", "application/x-dosexec", "application/x-executable",
	"application/x-sh", "application/x-csh", "application/x-bat", "application/x-msi", "application/x-ms-installer",
	"application/vnd.microsoft.portable-executable", "application/java-archive", "application/x-java-archive",
	"application/hta", "application/x-ms-shortcut", "text/javascript", "application/javascript", "application/x-javascript",
	"text/vbscript", "application/x-powershell",
}

// blockedExtensions are executable, script and installer extensions that
// mail filters reject (and that run when opened on Windows).
var blockedExtensions = []string{
	"ade", "adp", "app", "application", "appx", "bas", "bat", "cab", "chm", "cmd", "com", "cpl", "dll", "exe", "gadget",
	"hta", "inf", "ins", "iso", "img", "isp", "jar", "js", "jse", "lib", "lnk", "mde", "msc", "msi", "msix", "msp", "mst",
	"nsh", "pif", "ps1", "psc1", "psm1", "reg", "scf", "scr", "sct", "shb", "sys", "vb", "vbe", "vbs", "vhd", "vhdx",
	"vxd", "wsc", "wsf", "wsh", "xll",
}

// matchType reports whether media matches one of the patterns
// ("type/subtype" or "type/*").
func matchType(media string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == media || (strings.HasSuffix(p, "/*") && strings.HasPrefix(media, strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}

// extensionOf is the lower-case last extension, without the dot.
func extensionOf(name string) string {
	return strings.TrimPrefix(strings.ToLower(path.Ext(name)), ".")
}

// NormalizeAttachments trims names, lower-cases types, fills a missing
// type from the extension and strips angle brackets from Content-IDs.
func NormalizeAttachments(list []Attachment) {
	for i := range list {
		a := &list[i]
		a.Filename = strings.TrimSpace(a.Filename)
		a.ContentID = strings.Trim(strings.TrimSpace(a.ContentID), "<>")
		ct := strings.TrimSpace(a.ContentType)
		if ct == "" {
			ct = mime.TypeByExtension(path.Ext(a.Filename))
		}
		if media, params, err := mime.ParseMediaType(ct); err == nil {
			// The file name travels in Content-Disposition; a charset stays.
			delete(params, "name")
			ct = mime.FormatMediaType(media, params)
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		a.ContentType = ct
	}
}

// ValidateAttachments checks normalized attachments against the limits:
// one 422 entry per problem, the field naming the attachment
// (attachments[1].filename).
func ValidateAttachments(list []Attachment, l AttachmentLimits) error {
	if len(list) == 0 {
		return nil
	}
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: field, Code: code, Message: msg})
	}
	if l.MaxCount <= 0 {
		return apperrors.Validation(apperrors.FieldError{Field: "attachments", Code: "not_allowed", Message: "attachments are turned off"})
	}
	if len(list) > l.MaxCount {
		add("attachments", "too_many", fmt.Sprintf("at most %d attachments", l.MaxCount))
	}
	var total int64
	cids := map[string]bool{}
	for i, a := range list {
		f := fmt.Sprintf("attachments[%d]", i)
		size := int64(len(a.Data))
		total += size
		switch {
		case a.Filename == "":
			add(f+".filename", "required", "filename is required")
		case len(a.Filename) > 255 || !utf8.ValidString(a.Filename) || strings.ContainsAny(a.Filename, "/\\\r\n\x00\"") ||
			strings.ContainsFunc(a.Filename, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			add(f+".filename", "invalid", "filename must be a plain file name of at most 255 characters")
		case slices.Contains(blockedExtensions, extensionOf(a.Filename)) || matchExt(extensionOf(a.Filename), l.BlockedExtensions):
			add(f+".filename", "blocked_type", "files of type ."+extensionOf(a.Filename)+" cannot be sent")
		}
		if media, _, err := mime.ParseMediaType(a.ContentType); err != nil || !strings.Contains(media, "/") {
			add(f+".content_type", "invalid", "content_type must be a media type such as application/pdf")
		} else if matchType(media, blockedTypes) || matchType(media, l.BlockedTypes) ||
			(len(l.AllowedTypes) > 0 && !matchType(media, l.AllowedTypes)) {
			add(f+".content_type", "blocked_type", "files of type "+media+" cannot be sent")
		}
		if size == 0 {
			add(f+".content", "required", "content is empty")
		} else if size > l.MaxBytes {
			add(f+".content", "too_large", fmt.Sprintf("the file is over %s", humanBytes(l.MaxBytes)))
		}
		if a.Inline && a.ContentID == "" {
			add(f+".content_id", "required", "an inline attachment needs a content_id")
		}
		if a.ContentID != "" {
			if len(a.ContentID) > 255 || strings.ContainsFunc(a.ContentID, func(r rune) bool { return r <= ' ' || r > '~' || r == '<' || r == '>' }) {
				add(f+".content_id", "invalid", "content_id must be printable ASCII without spaces or angle brackets")
			} else if cids[a.ContentID] {
				add(f+".content_id", "duplicate", "content_id must be unique in the message")
			}
			cids[a.ContentID] = true
		}
	}
	if total > l.MaxTotalBytes {
		add("attachments", "too_large", fmt.Sprintf("the attachments are over %s together", humanBytes(l.MaxTotalBytes)))
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

func matchExt(ext string, list []string) bool {
	for _, e := range list {
		if strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".") == ext && ext != "" {
			return true
		}
	}
	return false
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// AttachmentsSize is the sum of the files' sizes.
func AttachmentsSize(list []Attachment) int64 {
	var n int64
	for _, a := range list {
		n += int64(len(a.Data))
	}
	return n
}
