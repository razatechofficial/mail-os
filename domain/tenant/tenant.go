// Package tenant is a MailOS tenant: an IAM tenant that has MailOS enabled.
// Its id is the IAM tenant UUID (stored as organizations.id and org_id on
// every tenant-owned row); MailOS keeps only what it needs locally.
package tenant

import (
	"errors"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Tenant is the local record of an IAM tenant.
type Tenant struct {
	ID        string
	Name      string
	Active    bool
	CreatedAt time.Time
}

// Settings are the tenant's security settings, managed by mailos_admin.
type Settings struct {
	TenantID string `json:"org_id"`
	// FourEyesPublish refuses publishing a draft the publisher last edited
	// (contract §5 separation of duties).
	FourEyesPublish bool `json:"four_eyes_publish"`
	// MessageRetentionDays overrides the platform default; nil keeps it.
	MessageRetentionDays *int      `json:"message_retention_days"`
	UpdatedBy            string    `json:"updated_by,omitempty"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// ErrDisabled is a tenant MailOS was switched off for.
var ErrDisabled = apperrors.Forbidden("MailOS is disabled for this tenant")

// ErrNotFound is returned by repositories for an unknown tenant.
var ErrNotFound = errors.New("tenant not found")

// Validate checks the settings an administrator submits.
func (s Settings) Validate() error {
	if s.MessageRetentionDays != nil && (*s.MessageRetentionDays < 1 || *s.MessageRetentionDays > 3650) {
		return apperrors.Invalid("message_retention_days", "out_of_range", "must be between 1 and 3650 days")
	}
	return nil
}

// RetentionDays is the effective retention given the platform default.
func (s Settings) RetentionDays(platform int) int {
	if s.MessageRetentionDays != nil {
		return *s.MessageRetentionDays
	}
	return platform
}
