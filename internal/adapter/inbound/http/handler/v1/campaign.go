package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/campaign"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type CampaignHandler struct {
	svc campaign.Service
}

func NewCampaignHandler(svc campaign.Service) *CampaignHandler {
	return &CampaignHandler{svc: svc}
}

func (h *CampaignHandler) Create(c *gin.Context) {
	var req dto.CreateCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	cm, err := h.svc.Create(c.Request.Context(), dto.CreateCampaignReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.CampaignToResponse(cm))
}

func (h *CampaignHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.CampaignID(c.Param("id"))
	cm, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.CampaignToResponse(cm))
}

func (h *CampaignHandler) Update(c *gin.Context) {
	var req dto.UpdateCampaignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.CampaignID(c.Param("id"))
	cm, err := h.svc.Update(c.Request.Context(), orgID, id, dto.UpdateCampaignReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.CampaignToResponse(cm))
}

func (h *CampaignHandler) Delete(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.CampaignID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *CampaignHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := campaign.ListParams{}
	listParams.Params = params
	campaigns, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.CampaignResponse, len(campaigns))
	for i, cm := range campaigns {
		items[i] = dto.CampaignToResponse(cm)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}

func (h *CampaignHandler) Launch(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.CampaignID(c.Param("id"))
	if err := h.svc.Launch(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, gin.H{"status": "launched"})
}

func (h *CampaignHandler) Pause(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.CampaignID(c.Param("id"))
	if err := h.svc.Pause(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, gin.H{"status": "paused"})
}

func (h *CampaignHandler) Resume(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.CampaignID(c.Param("id"))
	if err := h.svc.Resume(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, gin.H{"status": "resumed"})
}

func (h *CampaignHandler) Cancel(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.CampaignID(c.Param("id"))
	if err := h.svc.Cancel(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, gin.H{"status": "cancelled"})
}
