package container

import (
	"context"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/application/auditintegrity"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/infrastructure/worker"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/handler"
)

// buildAuditIntegrity seals the audit log with signed, chained digests
// (AUDIT_DIGEST_SIGNING_KEY) and serves their verification to the operator
// tenant. Production refuses to start without the key (config); elsewhere
// the log is left unsealed.
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
	c.Routes = append(c.Routes, handler.NewAuditIntegrityHandler(svc, c.Audit, c.Cfg.IAM.ServiceTenantID))
	c.Tasks = append(c.Tasks, func(s *worker.Server) error {
		s.HandleFunc(worker.TypeAuditSeal, worker.AuditSeal(svc))
		every := cfg.DigestInterval
		return s.Every(fmt.Sprintf("@every %s", every), worker.TypeAuditSeal, every-time.Second)
	})
	return nil
}
