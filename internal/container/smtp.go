package container

import (
	"context"
	"fmt"

	"github.com/razatechofficial/mail-os/application/smtpcred"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/internal/bootstrap"
	"github.com/razatechofficial/mail-os/transport/http/handler"
	smtptransport "github.com/razatechofficial/mail-os/transport/smtp"
)

// The structures the migration 20261103100000 adds. Application and message
// reads select their new columns, so the probe is required.
func init() {
	bootstrap.Register("SMTP submission (20261103100000)",
		"SELECT a.smtp_password_auth, c.username, c.password_hash, m.headers FROM applications a, smtp_credentials c, messages m LIMIT 0",
		true, "applications and messages cannot be read, and SMTP credentials cannot be checked")
}

// buildSMTP runs after buildMessaging (it needs the registry and the
// message use case). The SMTP credential API is always mounted, so
// administrators can prepare credentials before the listener is on; the
// listener itself is built by SMTPServer, in the server process only.
func (c *Container) buildSMTP(context.Context) error {
	cfg := c.Cfg.SMTPSubmission
	c.SMTPCredentials = smtpcred.NewService(postgres.NewSMTPCredentialRepository(c.DB), c.Apps, c.Audit, smtpcred.Config{})
	c.Routes = append(c.Routes, handler.NewSMTPCredentialHandler(c.SMTPCredentials, handler.SMTPEndpoint{
		Enabled: cfg.Enabled, Host: cfg.Hostname, Port: cfg.Port, ImplicitTLSPort: cfg.ImplicitTLSPort, PasswordAuth: cfg.PasswordAuth,
	}))
	return nil
}

// SMTPServer builds the SMTP submission listener (SMTP_SUBMISSION_ENABLED):
// IAM tokens verified like the HTTP API's, the application registry, the
// message pipeline, Redis for the AUTH failure counters, and SMTP
// credentials when SMTP_SUBMISSION_PASSWORD_AUTH is on.
func (c *Container) SMTPServer() (*smtptransport.Server, error) {
	cfg := c.Cfg.SMTPSubmission
	deps := smtptransport.Deps{Tokens: c.Verifier, Apps: c.Apps, Messages: c.Messages, Counter: c.Redis, Audit: c.Audit}
	if cfg.PasswordAuth {
		deps.Credentials = c.SMTPCredentials
	}
	srv, err := smtptransport.NewServer(cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("smtp submission: %w", err)
	}
	return srv, nil
}
