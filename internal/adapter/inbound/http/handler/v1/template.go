package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/template"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type TemplateHandler struct {
	svc template.Service
}

func NewTemplateHandler(svc template.Service) *TemplateHandler {
	return &TemplateHandler{svc: svc}
}

func (h *TemplateHandler) Create(c *gin.Context) {
	var req dto.CreateTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	tpl, err := h.svc.Create(c.Request.Context(), dto.CreateTemplateReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.TemplateToResponse(tpl))
}

func (h *TemplateHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.TemplateID(c.Param("id"))
	tpl, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.TemplateToResponse(tpl))
}

func (h *TemplateHandler) Update(c *gin.Context) {
	var req dto.UpdateTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.TemplateID(c.Param("id"))
	tpl, err := h.svc.Update(c.Request.Context(), orgID, id, dto.UpdateTemplateReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.TemplateToResponse(tpl))
}

func (h *TemplateHandler) Delete(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.TemplateID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *TemplateHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := template.ListParams{}
	listParams.Params = params
	templates, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.TemplateResponse, len(templates))
	for i, t := range templates {
		items[i] = dto.TemplateToResponse(t)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}

func (h *TemplateHandler) CreateVersion(c *gin.Context) {
	var req dto.CreateTemplateVersionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	templateID := c.Param("id")
	v, err := h.svc.CreateVersion(c.Request.Context(), dto.CreateTemplateVersionReqToInput(req, templateID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.TemplateVersionToResponse(v))
}

func (h *TemplateHandler) GetActiveVersion(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	templateID := domain.TemplateID(c.Param("id"))
	_, err := h.svc.GetByID(c.Request.Context(), orgID, templateID)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	v, err := h.svc.GetActiveVersion(c.Request.Context(), templateID)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.TemplateVersionToResponse(v))
}

func (h *TemplateHandler) ListVersions(c *gin.Context) {
	templateID := domain.TemplateID(c.Param("id"))
	versions, err := h.svc.ListVersions(c.Request.Context(), templateID)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.TemplateVersionResponse, len(versions))
	for i, v := range versions {
		items[i] = dto.TemplateVersionToResponse(v)
	}
	httputil.OK(c, items)
}
