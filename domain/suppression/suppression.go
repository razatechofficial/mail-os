// Package suppression is a tenant's list of addresses MailOS does not send
// to: hard bounces and complaints (recorded by the send path and provider
// webhooks), unsubscribes, and addresses an operator added. An entry is
// tenant-wide (every application's mail and the tenant's own) or scoped to
// one application; tenant-wide entries always apply.
package suppression

import (
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Type is why the address is suppressed.
type Type string

// Suppression types (the console's SUPPRESSION_TYPES).
const (
	TypeBounce      Type = "bounce"
	TypeComplaint   Type = "complaint"
	TypeUnsubscribe Type = "unsubscribe"
	TypeManual      Type = "manual"
)

// Valid reports whether t is known.
func (t Type) Valid() bool {
	return t == TypeBounce || t == TypeComplaint || t == TypeUnsubscribe || t == TypeManual
}

// Blocks reports whether a suppression of type t stops a message of type
// mt: an unsubscribe stops marketing only, so a person who unsubscribed
// still gets their one-time codes; the rest stop everything.
func (t Type) Blocks(mt message.Type) bool {
	if t == TypeUnsubscribe {
		return mt == message.TypeMarketing
	}
	return true
}

// Sources of a suppression.
const (
	SourceSend    = "send"    // the provider refused the recipient
	SourceManual  = "manual"  // an operator added it
	SourceWebhook = "webhook" // a provider's bounce or complaint event
)

// Suppression is one suppressed address of a tenant.
type Suppression struct {
	ID    string
	OrgID string
	// ApplicationID scopes the entry to one application; empty is
	// tenant-wide.
	ApplicationID string
	Email     string
	Type      Type
	Reason    string
	Source    string
	CreatedBy string
	CreatedAt time.Time
}

// NormalizeEmail lowercases an address, as suppressions match without case.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Validate checks a suppression before it is saved.
func (s Suppression) Validate() error {
	var errs []apperrors.FieldError
	if !provider.ValidEmail(s.Email) {
		errs = append(errs, apperrors.FieldError{Field: "email", Code: "invalid", Message: "email is not a valid address"})
	}
	if !s.Type.Valid() {
		errs = append(errs, apperrors.FieldError{Field: "type", Code: "invalid", Message: "type must be bounce, complaint, unsubscribe or manual"})
	}
	if len(s.Reason) > 1000 {
		errs = append(errs, apperrors.FieldError{Field: "reason", Code: "too_long", Message: "reason must be at most 1000 characters"})
	}
	if len(s.Source) > 50 {
		errs = append(errs, apperrors.FieldError{Field: "source", Code: "too_long", Message: "source must be at most 50 characters"})
	}
	if len(errs) > 0 {
		return apperrors.Validation(errs...)
	}
	return nil
}
