package config

import (
	"fmt"
	"mime"
	"strings"
)

// Attachments bounds the files a message may carry, on the send API and
// the SMTP relay alike. The request body limits (HTTP_MAX_BODY_BYTES,
// SMTP_SUBMISSION_MAX_MESSAGE_BYTES) apply first, and base64 makes a file
// a third larger on the wire.
type Attachments struct {
	// MaxBytes is the largest single file.
	MaxBytes int64 `yaml:"max_bytes" env:"ATTACHMENTS_MAX_BYTES" env-default:"5242880"`
	// MaxTotalBytes is the largest sum of a message's files.
	MaxTotalBytes int64 `yaml:"max_total_bytes" env:"ATTACHMENTS_MAX_TOTAL_BYTES" env-default:"10485760"`
	// MaxCount is the most files on one message; 0 turns attachments off.
	MaxCount int `yaml:"max_count" env:"ATTACHMENTS_MAX_COUNT" env-default:"10"`
	// AllowedTypes, when set, are the only media types accepted
	// ("application/pdf", "image/*").
	AllowedTypes []string `yaml:"allowed_types" env:"ATTACHMENTS_ALLOWED_TYPES" env-separator:","`
	// BlockedTypes are refused on top of the built-in executable types.
	BlockedTypes []string `yaml:"blocked_types" env:"ATTACHMENTS_BLOCKED_TYPES" env-separator:","`
	// BlockedExtensions are refused on top of the built-in executable and
	// script extensions ("exe", ".js").
	BlockedExtensions []string `yaml:"blocked_extensions" env:"ATTACHMENTS_BLOCKED_EXTENSIONS" env-separator:","`
}

func (a Attachments) validate() error {
	if a.MaxCount < 0 || a.MaxCount > 100 {
		return fmt.Errorf("ATTACHMENTS_MAX_COUNT must be between 0 and 100")
	}
	if a.MaxCount > 0 && (a.MaxBytes < 1 || a.MaxTotalBytes < a.MaxBytes || a.MaxTotalBytes > 64<<20) {
		return fmt.Errorf("ATTACHMENTS_MAX_BYTES must be positive and at most ATTACHMENTS_MAX_TOTAL_BYTES (at most 64 MiB)")
	}
	for _, list := range [][]string{a.AllowedTypes, a.BlockedTypes} {
		for _, t := range list {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if strings.HasSuffix(t, "/*") {
				t = strings.TrimSuffix(t, "*") + "x"
			}
			if _, _, err := mime.ParseMediaType(t); err != nil || !strings.Contains(t, "/") {
				return fmt.Errorf("attachment media type %q is not a type/subtype or type/*", t)
			}
		}
	}
	return nil
}
