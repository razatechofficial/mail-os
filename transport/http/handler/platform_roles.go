package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/platformroles"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// RoleAttestations applies the IAM's signed role attestations
// (application/platformroles).
type RoleAttestations interface {
	Apply(ctx context.Context, raw string) (platformroles.Result, error)
}

// PlatformRolesHandler is the IAM's delivery point for MailOS platform role
// decisions (contract C5): POST /api/platform/v1/role-attestations with
// {"attestation": "<compact JWS>"}. It takes no bearer token: the
// attestation, signed with the IAM's ACS approval key, is the credential.
type PlatformRolesHandler struct {
	svc RoleAttestations
}

// NewPlatformRolesHandler builds the handler; a nil service (ACS not
// configured) answers 503.
func NewPlatformRolesHandler(svc RoleAttestations) *PlatformRolesHandler {
	return &PlatformRolesHandler{svc: svc}
}

// RoleAttestationsPath is the delivery route.
const RoleAttestationsPath = "/api/platform/v1/role-attestations"

// maxAttestationBody bounds the request: one compact JWS.
const maxAttestationBody = 16 << 10

// MountPublic registers the route outside the platform API's bearer
// authentication.
func (h *PlatformRolesHandler) MountPublic(r gin.IRouter) {
	r.POST(RoleAttestationsPath, h.Deliver)
}

type attestationRequest struct {
	Attestation string `json:"attestation" binding:"required"`
}

// Deliver verifies and applies one attestation: 204 when applied or
// already applied, 401 for a credential that does not verify, 400 for one
// MailOS will not apply, 403 for an activation of a person not eligible,
// 503 when the IAM's keys or ACS cannot be reached.
func (h *PlatformRolesHandler) Deliver(c *gin.Context) {
	if h.svc == nil {
		response.FromError(c, apperrors.Unavailable("platform roles are not configured (no authorization service)"))
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAttestationBody)
	var req attestationRequest
	if !bind(c, &req) {
		return
	}
	if _, err := h.svc.Apply(c.Request.Context(), req.Attestation); err != nil {
		if apperrors.KindOf(err) == apperrors.KindUnauthorized {
			c.Header("WWW-Authenticate", `JWS error="invalid_attestation"`)
		}
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
