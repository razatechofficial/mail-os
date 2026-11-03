package smtpcred

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domain "github.com/razatechofficial/mail-os/domain/smtpcredential"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Audit actions.
const (
	AuditCreated = "smtp_credential.created"
	AuditRotated = "smtp_credential.rotated"
	AuditRevoked = "smtp_credential.revoked"
)

// Service is the SMTP credential use case.
type Service struct {
	repo  Repository
	apps  Applications
	audit Auditor
	sem   chan struct{}
	now   func() time.Time
	// dummy is a hash verified for an unknown username, so a failed sign-in
	// takes as long whether or not the username exists.
	dummy     string
	dummyOnce sync.Once
}

// NewService builds the service.
func NewService(repo Repository, apps Applications, audit Auditor, cfg Config) *Service {
	n := cfg.HashConcurrency
	if n <= 0 {
		n = 4
	}
	return &Service{repo: repo, apps: apps, audit: audit, sem: make(chan struct{}, n),
		now: func() time.Time { return time.Now().UTC() }}
}

// record is what the audit trail keeps of a credential: never a password
// or its hash.
type record struct {
	ApplicationID string `json:"application_id"`
	Username      string `json:"username"`
	Description   string `json:"description,omitempty"`
	Revoked       bool   `json:"revoked"`
}

func recordOf(c domain.Credential) record {
	return record{ApplicationID: c.ApplicationID, Username: c.Username, Description: c.Description, Revoked: !c.Active()}
}

// ErrNotEnabled refuses credentials for an application that is not opted in.
var ErrNotEnabled = apperrors.Conflict("turn on SMTP credentials (smtp_password_auth) for this application first")

// ErrTooMany refuses a third active credential.
var ErrTooMany = apperrors.Conflict("an application has at most 2 active SMTP credentials; revoke one first")

// eligible is the application, when it may hold credentials: a server
// application registered in the console and opted in.
func (s *Service) eligible(ctx context.Context, tenantID, applicationID string) (domainapp.Application, error) {
	a, err := s.apps.Get(ctx, tenantID, applicationID)
	if err != nil {
		return a, err
	}
	if a.Kind != domainapp.KindServer || a.System {
		return a, apperrors.Forbidden("SMTP credentials are for server applications registered in the console only")
	}
	if !a.SMTPPasswordAuth {
		return a, ErrNotEnabled
	}
	return a, nil
}

// List returns an application's credentials, revoked ones included.
func (s *Service) List(ctx context.Context, tenantID, applicationID string) ([]domain.Credential, error) {
	if _, err := s.apps.Get(ctx, tenantID, applicationID); err != nil {
		return nil, err
	}
	return s.repo.List(ctx, tenantID, applicationID)
}

// Create generates a credential for the application. The password is
// returned once and never again.
func (s *Service) Create(ctx context.Context, tenantID, applicationID, description, actor string) (domain.Credential, string, error) {
	description = strings.TrimSpace(description)
	if len(description) > domain.MaxDescription || strings.ContainsAny(description, "\r\n\x00") {
		return domain.Credential{}, "", apperrors.Invalid("description", "invalid", "description must be one line of at most 200 characters")
	}
	if _, err := s.eligible(ctx, tenantID, applicationID); err != nil {
		return domain.Credential{}, "", err
	}
	existing, err := s.repo.List(ctx, tenantID, applicationID)
	if err != nil {
		return domain.Credential{}, "", err
	}
	active := 0
	for _, c := range existing {
		if c.Active() {
			active++
		}
	}
	if active >= domain.MaxActive {
		return domain.Credential{}, "", ErrTooMany
	}
	username, err := domain.NewUsername()
	if err != nil {
		return domain.Credential{}, "", err
	}
	password, hash, err := newSecret()
	if err != nil {
		return domain.Credential{}, "", err
	}
	c := domain.Credential{ID: id.New(), TenantID: tenantID, ApplicationID: applicationID, Username: username,
		PasswordHash: hash, Description: description, CreatedBy: actor, CreatedAt: s.now()}
	if err := s.repo.Create(ctx, c); err != nil {
		return domain.Credential{}, "", err
	}
	if err := s.audit.Change(ctx, "smtp_credential", c.ID, AuditCreated, nil, recordOf(c), nil); err != nil {
		return domain.Credential{}, "", err
	}
	return c, password, nil
}

func newSecret() (password, hash string, err error) {
	if password, err = domain.NewPassword(); err != nil {
		return "", "", err
	}
	hash, err = domain.Hash(password)
	return password, hash, err
}

// Rotate gives an active credential a new password, effective at once;
// the username stays. The new password is returned once.
func (s *Service) Rotate(ctx context.Context, tenantID, applicationID, credentialID, actor string) (domain.Credential, string, error) {
	c, err := s.owned(ctx, tenantID, applicationID, credentialID)
	if err != nil {
		return domain.Credential{}, "", err
	}
	if !c.Active() {
		return domain.Credential{}, "", apperrors.Conflict("a revoked credential cannot be rotated")
	}
	if _, err := s.eligible(ctx, tenantID, applicationID); err != nil {
		return domain.Credential{}, "", err
	}
	password, hash, err := newSecret()
	if err != nil {
		return domain.Credential{}, "", err
	}
	now := s.now()
	c.PasswordHash, c.RotatedAt, c.RotatedBy = hash, &now, actor
	if err := s.repo.SetPassword(ctx, c); err != nil {
		return domain.Credential{}, "", err
	}
	if err := s.audit.Change(ctx, "smtp_credential", c.ID, AuditRotated, nil, nil,
		map[string]any{"application_id": c.ApplicationID, "username": c.Username, "changed": []string{"password"}}); err != nil {
		return domain.Credential{}, "", err
	}
	return c, password, nil
}

// Revoke stops a credential at once, including the SMTP sessions it
// opened (each transaction checks it again). Revoking twice is a no-op.
func (s *Service) Revoke(ctx context.Context, tenantID, applicationID, credentialID, actor string) error {
	c, err := s.owned(ctx, tenantID, applicationID, credentialID)
	if err != nil {
		return err
	}
	if !c.Active() {
		return nil
	}
	before := recordOf(c)
	now := s.now()
	if err := s.repo.Revoke(ctx, tenantID, c.ID, now, actor); err != nil {
		return err
	}
	c.RevokedAt, c.RevokedBy = &now, actor
	return s.audit.Change(ctx, "smtp_credential", c.ID, AuditRevoked, before, recordOf(c), nil)
}

func (s *Service) owned(ctx context.Context, tenantID, applicationID, credentialID string) (domain.Credential, error) {
	c, err := s.repo.Get(ctx, tenantID, credentialID)
	if err != nil {
		return c, err
	}
	if c.ApplicationID != applicationID {
		return domain.Credential{}, apperrors.NotFound("smtp credential not found")
	}
	return c, nil
}

// AuthError is a refused SMTP authentication. Reason is for the audit
// trail and the logs only: the client is told "authentication failed",
// whatever the reason.
type AuthError struct{ Reason string }

func (e *AuthError) Error() string { return "smtp authentication failed: " + e.Reason }

// Refusal reasons.
const (
	ReasonUnknownUsername = "unknown_username"
	ReasonBadPassword     = "bad_password"
	ReasonRevoked         = "credential_revoked"
	ReasonNotEnabled      = "smtp_password_auth_off"
	ReasonApplication     = "application_unusable"
)

func refused(reason string) error { return &AuthError{Reason: reason} }

// Authenticate checks a username and password. The password is always
// verified (against a dummy hash for an unknown username) before anything
// else is decided, so the answer takes as long either way. The credential
// must be active, and its application an active server application still
// opted in. A success records the last use.
func (s *Service) Authenticate(ctx context.Context, username, password, remoteIP string) (domain.Credential, domainapp.Application, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var c domain.Credential
	var err error
	if domain.ValidUsername(username) {
		c, err = s.repo.ByUsername(ctx, username)
	} else {
		err = ErrNotFound
	}
	known := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return domain.Credential{}, domainapp.Application{}, err
	}
	hash := c.PasswordHash
	if !known {
		hash = s.dummyHash()
	}
	ok, err := s.verify(ctx, hash, password)
	if err != nil {
		return domain.Credential{}, domainapp.Application{}, err
	}
	switch {
	case !known:
		return domain.Credential{}, domainapp.Application{}, refused(ReasonUnknownUsername)
	case !ok:
		return c, domainapp.Application{}, refused(ReasonBadPassword)
	}
	a, err := s.Check(ctx, c)
	if err != nil {
		return c, a, err
	}
	if err := s.repo.Touch(ctx, c.ID, s.now(), remoteIP); err != nil {
		logger.FromContext(ctx).Warn("smtp credential last use not recorded", logger.String("credential_id", c.ID), logger.Err(err))
	}
	return c, a, nil
}

// Check decides again whether an authenticated credential may still send:
// SMTP sessions are long, so each transaction re-reads the credential and
// its application (a revocation, a suspension or the opt-in turned off
// takes effect at the next MAIL FROM).
func (s *Service) Check(ctx context.Context, c domain.Credential) (domainapp.Application, error) {
	cur, err := s.repo.Get(ctx, c.TenantID, c.ID)
	if apperrors.IsNotFound(err) {
		return domainapp.Application{}, refused(ReasonRevoked)
	}
	if err != nil {
		return domainapp.Application{}, err
	}
	if !cur.Active() {
		return domainapp.Application{}, refused(ReasonRevoked)
	}
	a, err := s.apps.Get(ctx, cur.TenantID, cur.ApplicationID)
	if apperrors.IsNotFound(err) {
		return a, refused(ReasonApplication)
	}
	if err != nil {
		return a, err
	}
	switch {
	case a.Kind != domainapp.KindServer || a.System || !a.Active():
		return a, refused(ReasonApplication)
	case !a.SMTPPasswordAuth:
		return a, refused(ReasonNotEnabled)
	}
	return a, nil
}

// verify runs one Argon2id verification, at most HashConcurrency at once:
// each holds 19 MiB, and a flood of attempts must not exhaust memory.
func (s *Service) verify(ctx context.Context, hash, password string) (bool, error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-s.sem }()
	ok, err := domain.Verify(hash, password)
	if errors.Is(err, domain.ErrMalformedHash) {
		logger.FromContext(ctx).Error("smtp credential hash is malformed")
		return false, nil
	}
	return ok, err
}

func (s *Service) dummyHash() string {
	s.dummyOnce.Do(func() {
		p, _ := domain.NewPassword()
		s.dummy, _ = domain.Hash(p)
	})
	return s.dummy
}
