package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/suppression"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type SuppressionHandler struct {
	svc suppression.Service
}

func NewSuppressionHandler(svc suppression.Service) *SuppressionHandler {
	return &SuppressionHandler{svc: svc}
}

func (h *SuppressionHandler) Add(c *gin.Context) {
	var req dto.AddSuppressionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	s, err := h.svc.Add(c.Request.Context(), dto.AddSuppressionReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.SuppressionToResponse(s))
}

func (h *SuppressionHandler) Remove(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		var req dto.RemoveSuppressionRequest
		if err := c.ShouldBindJSON(&req); err == nil {
			email = req.Email
		}
	}
	if email == "" {
		httputil.FromError(c, errors.NewBadRequest("email is required"))
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	if err := h.svc.Remove(c.Request.Context(), orgID, email); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *SuppressionHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := suppression.ListParams{
		OrgID: string(orgID),
		Type:  c.Query("type"),
	}
	listParams.Params = params
	suppressions, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.SuppressionResponse, len(suppressions))
	for i, s := range suppressions {
		items[i] = dto.SuppressionToResponse(s)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
