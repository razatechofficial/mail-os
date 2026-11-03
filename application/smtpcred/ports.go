// Package smtpcred is the SMTP credential use case: a tenant's
// administrators generate, rotate and revoke the SMTP usernames and
// passwords of the server applications they opted in (smtp_password_auth),
// and the SMTP submission listener (transport/smtp) authenticates with them.
// Why MailOS issues this one secret, and how it is kept, is in
// domain/smtpcredential.
package smtpcred

import (
	"context"
	"errors"
	"time"

	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domain "github.com/razatechofficial/mail-os/domain/smtpcredential"
)

// ErrNotFound is returned by Repository.ByUsername for an unknown username.
var ErrNotFound = errors.New("smtp credential not found")

// Repository stores credentials.
type Repository interface {
	Create(ctx context.Context, c domain.Credential) error
	// Get returns the tenant's credential, apperrors.NotFound otherwise.
	Get(ctx context.Context, tenantID, id string) (domain.Credential, error)
	// ByUsername returns the credential of a username in any tenant,
	// ErrNotFound when there is none.
	ByUsername(ctx context.Context, username string) (domain.Credential, error)
	// List returns the application's credentials, newest first.
	List(ctx context.Context, tenantID, applicationID string) ([]domain.Credential, error)
	// SetPassword stores a rotated hash with RotatedAt and RotatedBy.
	SetPassword(ctx context.Context, c domain.Credential) error
	// Revoke marks the credential revoked unless it already is.
	Revoke(ctx context.Context, tenantID, id string, at time.Time, by string) error
	// Touch records a successful authentication, at most once a minute.
	Touch(ctx context.Context, id string, at time.Time, ip string) error
}

// Applications reads the registry (applications.Service).
type Applications interface {
	Get(ctx context.Context, tenantID, id string) (domainapp.Application, error)
}

// Auditor records changes.
type Auditor interface {
	Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error
}

// Config tunes the use case.
type Config struct {
	// HashConcurrency bounds the Argon2id verifications running at once
	// (each holds 19 MiB); default 4.
	HashConcurrency int
}
