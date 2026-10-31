package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// TokenVerifier verifies IAM access tokens.
type TokenVerifier interface {
	Principal(ctx context.Context, raw string) (access.Principal, error)
}

// ProofChecker enforces DPoP binding (RFC 9449).
type ProofChecker interface {
	Check(ctx context.Context, r *http.Request, scheme, accessToken, jkt, htu string) error
}

// TenantEnsurer provisions a user's tenant on first use and refuses a
// tenant MailOS is disabled for.
type TenantEnsurer interface {
	Ensure(ctx context.Context, tenantID string) error
}

// Auditor records refusals.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Auth authenticates /api/v1 requests with IAM access tokens.
type Auth struct {
	Verifier TokenVerifier
	DPoP     ProofChecker
	Tenants  TenantEnsurer
	Audit    Auditor
	// TrustForwarded believes X-Forwarded-Proto/Host for the DPoP htu
	// (only when HTTP_TRUSTED_PROXIES is configured).
	TrustForwarded bool
}

// MissingTokenMessage is the 401 message for a request without a token.
const MissingTokenMessage = "missing or invalid authorization header"

// NoRoleMessage tells a signed-in person why they have no access (contract
// §5: no role means no access, with a clear message).
const NoRoleMessage = "Your account has no MailOS role. Ask your MailOS administrator to assign one in IAM."

// Required verifies the token (and its DPoP proof when bound), refuses a
// person without a MailOS role, provisions the person's tenant, and puts
// the principal in the request context.
func (a *Auth) Required() gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, raw := bearer(c.GetHeader("Authorization"))
		if raw == "" {
			unauthorized(c, "Bearer", MissingTokenMessage)
			return
		}
		ctx := c.Request.Context()
		p, err := a.Verifier.Principal(ctx, raw)
		if err != nil {
			if errors.Is(err, jwt.ErrUnavailable) {
				response.FromError(c, apperrors.Unavailable("the identity provider is unavailable; try again shortly"))
				return
			}
			logger.SecurityWarn("access token refused", logger.Err(err), logger.String("route", c.FullPath()))
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
		}
		ctx = access.WithPrincipal(ctx, p)
		c.Request = c.Request.WithContext(ctx)
		if !p.IsService() {
			if len(p.Roles) == 0 {
				a.deny(c, "no_role", "")
				response.FromError(c, apperrors.Forbidden(NoRoleMessage))
				return
			}
			if err := a.Tenants.Ensure(ctx, p.TenantID); err != nil {
				response.FromError(c, err)
				return
			}
		}
		c.Next()
	}
}

func (a *Auth) deny(c *gin.Context, reason, perm string) {
	if a.Audit == nil {
		return
	}
	meta := map[string]any{"reason": reason, "route": c.FullPath(), "method": c.Request.Method}
	if perm != "" {
		meta["permission"] = perm
	}
	if err := a.Audit.Append(c.Request.Context(), "api", c.FullPath(), "access_denied", meta); err != nil {
		logger.Error("audit access_denied", logger.Err(err))
	}
}

// bearer splits "Bearer <t>" or "DPoP <t>".
func bearer(h string) (scheme, token string) {
	h = strings.TrimSpace(h)
	for _, s := range []string{"Bearer", "DPoP"} {
		if len(h) > len(s)+1 && strings.EqualFold(h[:len(s)], s) && h[len(s)] == ' ' {
			return s, strings.TrimSpace(h[len(s)+1:])
		}
	}
	return "", ""
}

func unauthorized(c *gin.Context, scheme, message string) {
	c.Header("WWW-Authenticate", scheme+` error="invalid_token"`)
	response.Abort(c, http.StatusUnauthorized, &response.Error{Code: apperrors.CodeUnauthorized, Message: message})
}

// PrincipalFrom returns the request's principal (set by Required).
func PrincipalFrom(c *gin.Context) access.Principal {
	p, _ := access.FromContext(c.Request.Context())
	return p
}
