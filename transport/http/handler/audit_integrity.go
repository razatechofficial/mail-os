package handler

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/auditintegrity"
	"github.com/razatechofficial/mail-os/domain/access"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// Verifier checks the audit digests and names the keys they verify with.
type Verifier interface {
	Verify(ctx context.Context) (*auditintegrity.Report, error)
	PublicKey() auditintegrity.VerificationKey
	PreviousKeys() []auditintegrity.VerificationKey
}

// Appender records the verification in the audit log.
type Appender interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// AuditIntegrityHandler serves the audit log's tamper check. The digests
// cover every tenant's rows, so only the operator tenant may run it.
type AuditIntegrityHandler struct {
	svc            Verifier
	audit          Appender
	operatorTenant string
}

// NewAuditIntegrityHandler builds the handler; operatorTenant is
// IAM_SERVICE_TENANT_ID (unset refuses everyone).
func NewAuditIntegrityHandler(svc Verifier, audit Appender, operatorTenant string) *AuditIntegrityHandler {
	return &AuditIntegrityHandler{svc: svc, audit: audit, operatorTenant: operatorTenant}
}

// Mount registers the route.
func (h *AuditIntegrityHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/analytics/audit-logs/integrity", g.Require(access.PermAuditExport), h.Verify)
}

type integrityView struct {
	*auditintegrity.Report
	SigningKey   auditintegrity.VerificationKey   `json:"signing_key"`
	PreviousKeys []auditintegrity.VerificationKey `json:"previous_keys"`
}

// Verify is GET /analytics/audit-logs/integrity: every digest's chain,
// signature and rows, with the public keys an auditor checks offline.
func (h *AuditIntegrityHandler) Verify(c *gin.Context) {
	if h.operatorTenant == "" || middleware.PrincipalFrom(c).TenantID != h.operatorTenant {
		response.FromError(c, apperrors.Forbidden("only the operator tenant may verify the deployment's audit log"))
		return
	}
	ctx := c.Request.Context()
	rep, err := h.svc.Verify(ctx)
	if err != nil {
		response.FromError(c, err)
		return
	}
	if err := h.audit.Append(ctx, "audit_log", "integrity", "audit.verified", map[string]any{
		"intact": rep.Intact, "digests": rep.Digests, "records": rep.Records, "problems": len(rep.Problems)}); err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, integrityView{Report: rep, SigningKey: h.svc.PublicKey(), PreviousKeys: h.svc.PreviousKeys()})
}
