package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/organization"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type OrganizationHandler struct {
	svc organization.Service
}

func NewOrganizationHandler(svc organization.Service) *OrganizationHandler {
	return &OrganizationHandler{svc: svc}
}

func (h *OrganizationHandler) Create(c *gin.Context) {
	var req dto.CreateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	org, err := h.svc.Create(c.Request.Context(), dto.CreateOrganizationReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.OrganizationToResponse(org))
}

func (h *OrganizationHandler) GetByID(c *gin.Context) {
	id := domain.OrganizationID(c.Param("id"))
	org, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.OrganizationToResponse(org))
}

func (h *OrganizationHandler) Update(c *gin.Context) {
	var req dto.UpdateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	id := domain.OrganizationID(c.Param("id"))
	org, err := h.svc.Update(c.Request.Context(), id, dto.UpdateOrganizationReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.OrganizationToResponse(org))
}

func (h *OrganizationHandler) Delete(c *gin.Context) {
	id := domain.OrganizationID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *OrganizationHandler) List(c *gin.Context) {
	params := httputil.PaginationFromContext(c)
	listParams := organization.ListParams{}
	listParams.Params = params
	orgs, total, err := h.svc.List(c.Request.Context(), listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.OrganizationResponse, len(orgs))
	for i, o := range orgs {
		items[i] = dto.OrganizationToResponse(o)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
