package middleware

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/domain/platformrole"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// PlatformChecker asks ACS whether a platform account holds a platform
// permission now (infrastructure/acs.Platform).
type PlatformChecker interface {
	Allowed(ctx context.Context, subject string, perm platformrole.Permission) (bool, error)
}

// PlatformRoleMessage is the 403 message on the platform API (contract C6).
const PlatformRoleMessage = "Your platform role does not allow this. Activate a MailOS platform role in the IAM."

// PlatformGuard checks a platform route's permission in ACS on every
// request (ADR 0001 §3.4): roles are activated for hours and end in ACS,
// so nothing is cached. ACS not answering is 503, never an allow.
type PlatformGuard struct {
	ACS   PlatformChecker
	Audit Auditor
}

// Require refuses a platform account whose active roles lack perm (403
// FORBIDDEN with PlatformRoleMessage, audited).
func (g PlatformGuard) Require(perm platformrole.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := access.FromContext(c.Request.Context())
		if !ok || !p.IsPlatform() {
			unauthorized(c, "Bearer", MissingTokenMessage)
			return
		}
		if g.ACS == nil {
			response.FromError(c, apperrors.Unavailable("the platform API is not configured (no authorization service)"))
			return
		}
		allowed, err := g.ACS.Allowed(c.Request.Context(), p.Subject, perm)
		if err != nil {
			logger.FromContext(c.Request.Context()).Error("platform permission check", logger.String("permission", string(perm)), logger.Err(err))
			response.FromError(c, apperrors.Unavailable("the authorization service is unavailable; try again shortly"))
			return
		}
		if !allowed {
			g.deny(c, perm)
			response.FromError(c, apperrors.Forbidden(PlatformRoleMessage))
			return
		}
		c.Next()
	}
}

func (g PlatformGuard) deny(c *gin.Context, perm platformrole.Permission) {
	if g.Audit == nil {
		return
	}
	meta := map[string]any{"reason": "platform_permission", "permission": string(perm), "route": c.FullPath(), "method": c.Request.Method}
	if err := g.Audit.Append(c.Request.Context(), "platform_api", c.FullPath(), "access_denied", meta); err != nil {
		logger.Error("audit access_denied", logger.Err(err))
	}
}
