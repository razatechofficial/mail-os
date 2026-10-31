// Package contact is a tenant's marketing audience: the people it sends
// campaigns to, and the lists it groups them in.
//
// A contact is personal data. Its address is never logged or written to
// the audit log in clear (logger.MaskEmail), and deleting a contact
// removes the row, its list memberships and its campaign recipient rows.
package contact

import (
	"encoding/json"
	"net/mail"
	"strconv"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Status is whether the contact may receive campaigns.
type Status string

// Contact statuses. Only an active contact receives campaigns.
const (
	StatusActive       Status = "active"
	StatusUnsubscribed Status = "unsubscribed"
	StatusBounced      Status = "bounced"
	StatusComplained   Status = "complained"
)

// Valid reports whether s is known.
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusUnsubscribed, StatusBounced, StatusComplained:
		return true
	}
	return false
}

// Limits.
const (
	MaxEmailLen = 254 // RFC 5321 §4.5.3.1.3 path limit less the brackets
	MaxNameLen  = 255
	// MaxMetadataBytes caps a contact's free-form metadata as JSON.
	MaxMetadataBytes = 8 << 10
	// MaxBatch is the most contacts one import creates.
	MaxBatch = 1000
)

// Contact is one person in a tenant's audience.
type Contact struct {
	ID string `json:"id"`
	// OrgID is the IAM tenant (column org_id).
	OrgID     string         `json:"org_id"`
	Email     string         `json:"email"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Metadata  map[string]any `json:"metadata"`
	Status    Status         `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// NormalizeEmail trims and lowercases an address: contacts, like
// suppressions, match without case, so one person is one contact.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ValidEmail reports whether s is a bare address (no display name, no
// header injection) of at most MaxEmailLen characters.
func ValidEmail(s string) bool {
	if s == "" || len(s) > MaxEmailLen || strings.ContainsAny(s, "\r\n<>") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// Normalize trims the names and normalizes the address and status.
func (c *Contact) Normalize() {
	c.Email = NormalizeEmail(c.Email)
	c.FirstName = strings.TrimSpace(c.FirstName)
	c.LastName = strings.TrimSpace(c.LastName)
	if c.Status == "" {
		c.Status = StatusActive
	}
	if c.Metadata == nil {
		c.Metadata = map[string]any{}
	}
}

// Validate checks a normalized contact. Field paths are prefixed with
// prefix ("contacts[3]." in an import). Messages never quote the address.
func (c *Contact) Validate(prefix string) []apperrors.FieldError {
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: prefix + field, Code: code, Message: msg})
	}
	switch {
	case c.Email == "":
		add("email", "required", "email is required")
	case !ValidEmail(c.Email):
		add("email", "invalid", "email is not a valid address")
	}
	name := func(field, v string) {
		if len(v) > MaxNameLen || strings.ContainsAny(v, "\r\n") {
			add(field, "invalid", field+" must be one line of at most 255 characters")
		}
	}
	name("first_name", c.FirstName)
	name("last_name", c.LastName)
	if !c.Status.Valid() {
		add("status", "invalid", "status must be active, unsubscribed, bounced or complained")
	}
	if raw, err := json.Marshal(c.Metadata); err != nil || len(raw) > MaxMetadataBytes {
		add("metadata", "too_large", "metadata must be a JSON object of at most "+strconv.Itoa(MaxMetadataBytes)+" bytes")
	}
	return errs
}

// Check normalizes and validates one contact (422 with every failing field).
func (c *Contact) Check() error {
	c.Normalize()
	if errs := c.Validate(""); len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

// CheckBatch normalizes and validates an import. Duplicate addresses
// within the batch are dropped (the first wins) and counted.
func CheckBatch(in []Contact) (out []Contact, duplicates int, err error) {
	if len(in) == 0 {
		return nil, 0, apperrors.Invalid("contacts", "required", "contacts must not be empty")
	}
	if len(in) > MaxBatch {
		return nil, 0, apperrors.Invalid("contacts", "too_many", "an import holds at most "+strconv.Itoa(MaxBatch)+" contacts")
	}
	var errs []apperrors.FieldError
	seen := make(map[string]bool, len(in))
	out = make([]Contact, 0, len(in))
	for i := range in {
		c := in[i]
		c.Normalize()
		if e := c.Validate("contacts[" + strconv.Itoa(i) + "]."); len(e) > 0 {
			errs = append(errs, e...)
			continue
		}
		if seen[c.Email] {
			duplicates++
			continue
		}
		seen[c.Email] = true
		out = append(out, c)
	}
	if len(errs) > 0 {
		return nil, 0, apperrors.Validation(errs...)
	}
	return out, duplicates, nil
}

// Changes lists the fields that differ between two versions of a contact,
// for the audit log (which records field names, never the values).
func Changes(before, after Contact) []string {
	var out []string
	if before.Email != after.Email {
		out = append(out, "email")
	}
	if before.FirstName != after.FirstName {
		out = append(out, "first_name")
	}
	if before.LastName != after.LastName {
		out = append(out, "last_name")
	}
	if before.Status != after.Status {
		out = append(out, "status")
	}
	b, _ := json.Marshal(before.Metadata)
	a, _ := json.Marshal(after.Metadata)
	if string(a) != string(b) {
		out = append(out, "metadata")
	}
	return out
}

// Errors the repositories return.
var (
	ErrNotFound       = apperrors.NotFound("contact not found")
	ErrListNotFound   = apperrors.NotFound("contact list not found")
	ErrDuplicateEmail = apperrors.NewAppError(apperrors.KindAlreadyExists, apperrors.CodeConflict, "a contact with this email already exists")
)
