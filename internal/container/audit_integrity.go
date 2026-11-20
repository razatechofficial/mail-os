package container

import (
	"context"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/application/auditintegrity"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// buildAuditIntegrity seals the audit log with signed, chained digests
// (AUDIT_DIGEST_SIGNING_KEY). Production refuses to start without the key
// (config); elsewhere the log is left unsealed. Verification covers every
// tenant's rows, so no tenant route serves it (ADR 0001 §3.9): it returns
// on the platform API under the log administrator role.
func (c *Container) buildAuditIntegrity(context.Context) error {
	cfg := c.Cfg.Audit
	if cfg.DigestSigningKey == "" {
		logger.Warn("AUDIT_DIGEST_SIGNING_KEY is not set: the audit log is not sealed")
		return nil
	}
	signer, err := auditintegrity.NewSigner(cfg.DigestSigningKey)
	if err != nil {
		return err
	}
	previous, err := auditintegrity.ParsePublicKeys(cfg.DigestPreviousKeys)
	if err != nil {
		return err
	}
	svc := auditintegrity.NewService(postgres.NewAuditIntegrityRepository(c.DB), signer, previous...)
	c.Tasks = append(c.Tasks, func(s *worker.Server) error {
		s.HandleFunc(worker.TypeAuditSeal, worker.AuditSeal(svc))
		every := cfg.DigestInterval
		return s.Every(fmt.Sprintf("@every %s", every), worker.TypeAuditSeal, every-time.Second)
	})
	return nil
}
