package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/dpop"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/stepup"
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
//
// The token must also meet the platform sign-in rule (contract C2): issued
// to the platform console (azp), a phishing-resistant sign-in (acr), no
// older than the platform session (auth_time). A weak or old sign-in is
// refused with 401 and the RFC 9470 challenge, so the console runs the
// platform sign-in again.
type PlatformAuth struct {
	Verifier PlatformTokenVerifier
	// SignIn is the platform sign-in rule; with no client IDs every token
	// is refused.
	SignIn access.PlatformSignIn
	// DPoP enforces the binding of a token that carries cnf.jkt.
	DPoP           ProofChecker
	TrustForwarded bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// PlatformSignInMessage is the refusal of a weak or old platform sign-in.
const PlatformSignInMessage = "Sign in to the platform console again with your passkey or security key"

// Required verifies the platform token (and its DPoP proof when the token
// is bound), applies the platform sign-in rule and puts the platform
// principal in the request context.
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
		if !a.signedIn(c, p) {
			return
		}
		c.Request = c.Request.WithContext(access.WithPrincipal(ctx, p))
		c.Next()
	}
}

// signedIn applies the platform sign-in rule and answers the refusal: a
// token for another client is invalid_token; a weak or old sign-in is the
// RFC 9470 step-up challenge (insufficient_user_authentication with the
// acr_values and max_age the new sign-in must meet).
func (a *PlatformAuth) signedIn(c *gin.Context, p access.Principal) bool {
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	err := a.SignIn.Check(p, now)
	if err == nil {
		return true
	}
	logger.SecurityWarn("platform sign-in refused", logger.Err(err), logger.String("route", c.FullPath()),
		logger.String("sub", p.Subject), logger.String("azp", p.ClientID), logger.String("acr", p.ACR))
	scheme := "Bearer"
	if p.DPoPThumbprint != "" {
		scheme = "DPoP"
	}
	if errors.Is(err, access.ErrPlatformClient) {
		unauthorized(c, scheme, "the token was not issued to the platform console")
		return false
	}
	ch := stepup.Challenge{ACRValues: []string{access.PlatformACR}, MaxAge: a.SignIn.MaxAgeOrDefault(), Description: err.Error()}
	c.Header("WWW-Authenticate", ch.Header(scheme))
	response.Abort(c, http.StatusUnauthorized, &response.Error{Code: apperrors.CodeInsufficientUserAuthentication,
		Message: PlatformSignInMessage, ACRValues: access.PlatformACR, MaxAge: ch.MaxAgeSeconds()})
	return false
}
