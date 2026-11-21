package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// PlatformTokenVerifier verifies platform tokens (contract C2).
type PlatformTokenVerifier interface {
	PlatformPrincipal(ctx context.Context, raw string) (access.Principal, error)
}

// PlatformAuth authenticates /api/platform/v1 requests (ADR 0001 §3.3):
// only a platform token (aud exactly mailos-platform, no tenant, no act)
// passes, so every tenant, service and lockbox token is refused here, as
// a platform token is refused by Auth on /api/v1. There is no tenant to
// provision and no application registry; the route's guard asks ACS.
type PlatformAuth struct {
	Verifier PlatformTokenVerifier
	// DPoP enforces the binding of a token that carries cnf.jkt.
	DPoP           ProofChecker
	TrustForwarded bool
}

// Required verifies the platform token (and its DPoP proof when the token
// is bound) and puts the platform principal in the request context.
func (a *PlatformAuth) Required() gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, raw := bearer(c.GetHeader("Authorization"))
		if raw == "" {
			unauthorized(c, "Bearer", MissingTokenMessage)
			return
		}
		ctx := c.Request.Context()
		p, err := a.Verifier.PlatformPrincipal(ctx, raw)
		if err != nil {
			if errors.Is(err, jwt.ErrUnavailable) {
				response.FromError(c, apperrors.Unavailable("the identity provider is unavailable; try again shortly"))
				return
			}
			logger.SecurityWarn("platform token refused", logger.Err(err), logger.String("route", c.FullPath()))
			unauthorized(c, "Bearer", "invalid or expired token")
			return
		}
		if a.DPoP != nil {
			if err := a.DPoP.Check(ctx, c.Request, scheme, raw, p.DPoPThumbprint, dpop.RequestURI(c.Request, a.TrustForwarded)); err != nil {
				if errors.Is(err, dpop.ErrUnavailable) {
					response.FromError(c, apperrors.Unavailable("the replay cache is unavailable; try again shortly"))
					return
				}
				logger.SecurityWarn("dpop proof refused", logger.Err(err), logger.String("route", c.FullPath()))
				c.Header("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
				response.Abort(c, http.StatusUnauthorized, &response.Error{Code: apperrors.CodeUnauthorized, Message: "invalid DPoP proof"})
				return
			}
		} else if p.DPoPThumbprint != "" {
			// A bound token is never accepted without its proof check.
			response.FromError(c, apperrors.Unavailable("DPoP proofs cannot be checked; try again shortly"))
			return
		}
		c.Request = c.Request.WithContext(access.WithPrincipal(ctx, p))
		c.Next()
	}
}
