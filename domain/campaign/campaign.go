// Package campaign is a tenant's marketing campaigns: one template sent to
// the members of one contact list, now or at a scheduled time.
//
// Status machine:
//
//	draft     -launch-> scheduled (future scheduled_at) or sending
//	scheduled -launch or due-> sending
//	sending   -pause-> paused -resume-> sending
//	sending   -every recipient handled-> completed
//	any but completed or cancelled -cancel-> cancelled
package campaign

import (
	"encoding/json"
	"net/mail"
	"strconv"
	"strings"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Status is where the campaign is in its life.
type Status string

// Campaign statuses.
const (
	StatusDraft     Status = "draft"
	StatusScheduled Status = "scheduled"
	StatusSending   Status = "sending"
	StatusPaused    Status = "paused"
	StatusCompleted Status = "completed"
	StatusCancelled Status = "cancelled"
)

// Valid reports whether s is known.
func (s Status) Valid() bool {
	switch s {
	case StatusDraft, StatusScheduled, StatusSending, StatusPaused, StatusCompleted, StatusCancelled:
		return true
	}
	return false
}

// Type is the kind of campaign.
type Type string

// Campaign types. Only regular campaigns are sent; A/B tests and
// automations are refused until they exist.
const (
	TypeRegular   Type = "regular"
	TypeABTest    Type = "ab_test"
	TypeAutomated Type = "automated"
)

// Limits.
const (
	MaxNameLen = 255
	// MaxSubjectLen is RFC 5322 §2.1.1's line limit.
	MaxSubjectLen    = 998
	MaxFromNameLen   = 200
	MaxEmailLen      = 254
	MaxMetadataBytes = 8 << 10
)

// Campaign is one campaign of a tenant.
type Campaign struct {
	ID string `json:"id"`
	// OrgID is the IAM tenant (column org_id).
	OrgID         string `json:"org_id"`
	Name          string `json:"name"`
	Subject       string `json:"subject"`
	FromName      string `json:"from_name"`
	FromEmail     string `json:"from_email"`
	TemplateID    string `json:"template_id"`
	ContactListID string `json:"contact_list_id"`
	Type          Type   `json:"type"`
	Status        Status `json:"status"`
	// ScheduledAt, when in the future at launch, holds the campaign until
	// then.
	ScheduledAt *time.Time `json:"scheduled_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	// TotalRecipients is set when sending starts: the list members who
	// can receive it (active and not suppressed).
	TotalRecipients int            `json:"total_recipients"`
	SentCount       int            `json:"sent_count"`
	FailedCount     int            `json:"failed_count"`
	Metadata        map[string]any `json:"metadata"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// Check normalizes and validates the campaign's content (422 with every
// failing field).
func (c *Campaign) Check() error {
	c.Name = strings.TrimSpace(c.Name)
	c.Subject = strings.TrimSpace(c.Subject)
	c.FromName = strings.TrimSpace(c.FromName)
	c.FromEmail = strings.TrimSpace(c.FromEmail)
	c.TemplateID = strings.TrimSpace(c.TemplateID)
	c.ContactListID = strings.TrimSpace(c.ContactListID)
	if c.Type == "" {
		c.Type = TypeRegular
	}
	if c.Metadata == nil {
		c.Metadata = map[string]any{}
	}
	var errs []apperrors.FieldError
	add := func(field, code, msg string) {
		errs = append(errs, apperrors.FieldError{Field: field, Code: code, Message: msg})
	}
	line := func(field, v string, max int) {
		switch {
		case v == "":
			add(field, "required", field+" is required")
		case len(v) > max || strings.ContainsAny(v, "\r\n"):
			add(field, "invalid", field+" must be one line of at most "+strconv.Itoa(max)+" characters")
		}
	}
	line("name", c.Name, MaxNameLen)
	line("subject", c.Subject, MaxSubjectLen)
	line("from_name", c.FromName, MaxFromNameLen)
	switch {
	case c.FromEmail == "":
		add("from_email", "required", "from_email is required")
	case !validEmail(c.FromEmail):
		add("from_email", "invalid", "from_email is not a valid address")
	}
	if c.TemplateID == "" {
		add("template_id", "required", "template_id is required")
	}
	if c.ContactListID == "" {
		add("contact_list_id", "required", "contact_list_id is required")
	}
	switch c.Type {
	case TypeRegular:
	case TypeABTest, TypeAutomated:
		add("type", "unsupported", "only regular campaigns are supported")
	default:
		add("type", "invalid", "type must be regular")
	}
	if raw, err := json.Marshal(c.Metadata); err != nil || len(raw) > MaxMetadataBytes {
		add("metadata", "too_large", "metadata must be a JSON object of at most "+strconv.Itoa(MaxMetadataBytes)+" bytes")
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}

func validEmail(s string) bool {
	if len(s) > MaxEmailLen || strings.ContainsAny(s, "\r\n<>") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// refuse is the 409 for an action the status does not allow.
func refuse(s Status, action string) error {
	return apperrors.Conflict("a " + string(s) + " campaign cannot be " + action)
}

// Editable reports whether the content may change: only before sending.
func (c *Campaign) Editable() error {
	if c.Status != StatusDraft && c.Status != StatusScheduled {
		return refuse(c.Status, "edited")
	}
	return nil
}

// Deletable refuses deleting a campaign while it sends: pause or cancel it
// first, so the fan-out is not cut off mid-page without a record.
func (c *Campaign) Deletable() error {
	if c.Status == StatusSending {
		return refuse(c.Status, "deleted")
	}
	return nil
}

// Launch sends the campaign: a draft with a future schedule waits as
// scheduled; otherwise (or launching a scheduled one) it starts sending
// now. It reports whether sending started.
func (c *Campaign) Launch(now time.Time) (sending bool, err error) {
	switch c.Status {
	case StatusDraft:
		if c.ScheduledAt != nil && c.ScheduledAt.After(now) {
			c.Status = StatusScheduled
			c.UpdatedAt = now
			return false, nil
		}
	case StatusScheduled:
	default:
		return false, refuse(c.Status, "launched")
	}
	c.start(now)
	return true, nil
}

// Release starts a scheduled campaign whose time has come.
func (c *Campaign) Release(now time.Time) error {
	if c.Status != StatusScheduled {
		return refuse(c.Status, "released")
	}
	if c.ScheduledAt != nil && c.ScheduledAt.After(now) {
		return apperrors.Conflict("the campaign is not due yet")
	}
	c.start(now)
	return nil
}

func (c *Campaign) start(now time.Time) {
	c.Status = StatusSending
	if c.StartedAt == nil {
		c.StartedAt = &now
	}
	c.UpdatedAt = now
}

// Pause stops a sending campaign after the page in flight.
func (c *Campaign) Pause(now time.Time) error {
	if c.Status != StatusSending {
		return refuse(c.Status, "paused")
	}
	c.Status, c.UpdatedAt = StatusPaused, now
	return nil
}

// Resume continues a paused campaign where it stopped.
func (c *Campaign) Resume(now time.Time) error {
	if c.Status != StatusPaused {
		return refuse(c.Status, "resumed")
	}
	c.Status, c.UpdatedAt = StatusSending, now
	return nil
}

// Cancel ends the campaign for good; recipients already sent to stay sent.
func (c *Campaign) Cancel(now time.Time) error {
	switch c.Status {
	case StatusDraft, StatusScheduled, StatusSending, StatusPaused:
	default:
		return refuse(c.Status, "cancelled")
	}
	c.Status, c.UpdatedAt, c.CompletedAt = StatusCancelled, now, &now
	return nil
}

// Complete marks a sending campaign done once every recipient is handled.
func (c *Campaign) Complete(now time.Time) error {
	if c.Status != StatusSending {
		return refuse(c.Status, "completed")
	}
	c.Status, c.UpdatedAt, c.CompletedAt = StatusCompleted, now, &now
	return nil
}

// Recipient statuses (campaign_recipients.status). A recipient is claimed
// (queued) before it is handed to the sender, so a recipient is never sent
// the campaign twice, even by two fan-outs running at once.
const (
	RecipientQueued = "queued"
	RecipientSent   = "sent"
	RecipientFailed = "failed"
)

// ErrNotFound is a campaign the tenant does not have (or deleted).
var ErrNotFound = apperrors.NotFound("campaign not found")
