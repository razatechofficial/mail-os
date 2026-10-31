package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/domain/access"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/stepup"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// Guard checks a route's permission and, for the sensitive ones, step-up.
type Guard struct {
	StepUp access.StepUpPolicy
	Audit  Auditor
	Now    func() time.Time
}

// Require refuses a principal whose roles lack perm (403 FORBIDDEN). For a
// permission that needs step-up (contract §5) it also refuses a sign-in
// older than StepUp.MaxAge or weaker than StepUp.ACR with 403
// STEP_UP_REQUIRED and the RFC 9470 challenge in WWW-Authenticate, as IAM's
// pkg/stepup writes it, so the console re-authorizes with max_age and
// acr_values and retries. Both refusals are audited.
func (g Guard) Require(perm access.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := access.FromContext(c.Request.Context())
		if !ok {
			unauthorized(c, "Bearer", MissingTokenMessage)
			return
		}
		if !p.Can(perm) {
			g.record(c, "access_denied", map[string]any{"reason": "permission", "permission": string(perm)})
			response.FromError(c, apperrors.Forbidden("Your MailOS role does not allow this action"))
			return
		}
		if access.NeedsStepUp(perm) {
			now := time.Now()
			if g.Now != nil {
				now = g.Now()
			}
			if err := g.StepUp.Check(p, now); err != nil {
				g.record(c, "step_up_required", map[string]any{"permission": string(perm), "reason": err.Error()})
				g.challenge(c, p, err)
				return
			}
		}
		c.Next()
	}
}

func (g Guard) challenge(c *gin.Context, p access.Principal, err error) {
	ch := stepup.Challenge{MaxAge: g.StepUp.MaxAge, Description: "A recent sign-in with a second factor is required"}
	if errors.Is(err, access.ErrStepUpWeak) || !access.ACRSatisfies(p.ACR, g.StepUp.ACR) {
		ch.ACRValues = []string{g.StepUp.ACR}
	}
	if errors.Is(err, access.ErrStepUpDelegated) {
		response.FromError(c, apperrors.Forbidden(err.Error()))
		return
	}
	scheme := "Bearer"
	if p.DPoPThumbprint != "" {
		scheme = "DPoP"
	}
	c.Header("WWW-Authenticate", ch.Header(scheme))
	e := &response.Error{Code: apperrors.CodeStepUpRequired, Message: "Confirm it is you: sign in again with your second factor", MaxAge: ch.MaxAgeSeconds()}
	if len(ch.ACRValues) > 0 {
		e.ACRValues = ch.ACRValues[0]
	}
	response.Abort(c, http.StatusForbidden, e)
}

func (g Guard) record(c *gin.Context, action string, meta map[string]any) {
	if g.Audit == nil {
		return
	}
	meta["route"], meta["method"] = c.FullPath(), c.Request.Method
	if err := g.Audit.Append(c.Request.Context(), "api", c.FullPath(), action, meta); err != nil {
		logger.Error("audit "+action, logger.Err(err))
	}
}
