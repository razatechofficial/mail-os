package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/provider"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type ProviderHandler struct {
	svc provider.Service
}

func NewProviderHandler(svc provider.Service) *ProviderHandler {
	return &ProviderHandler{svc: svc}
}

func (h *ProviderHandler) Create(c *gin.Context) {
	var req dto.CreateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	p, err := h.svc.Create(c.Request.Context(), dto.CreateProviderReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.ProviderToResponse(p))
}

func (h *ProviderHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ProviderID(c.Param("id"))
	p, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.ProviderToResponse(p))
}

func (h *ProviderHandler) Update(c *gin.Context) {
	var req dto.UpdateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ProviderID(c.Param("id"))
	p, err := h.svc.Update(c.Request.Context(), orgID, id, dto.UpdateProviderReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.ProviderToResponse(p))
}

func (h *ProviderHandler) Delete(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ProviderID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *ProviderHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := provider.ListParams{}
	listParams.Params = params
	providers, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.ProviderResponse, len(providers))
	for i, p := range providers {
		items[i] = dto.ProviderToResponse(p)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
