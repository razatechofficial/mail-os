package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/webhook"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type WebhookHandler struct {
	svc webhook.Service
}

func NewWebhookHandler(svc webhook.Service) *WebhookHandler {
	return &WebhookHandler{svc: svc}
}

func (h *WebhookHandler) Create(c *gin.Context) {
	var req dto.CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	w, err := h.svc.Create(c.Request.Context(), dto.CreateWebhookReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.WebhookToResponse(w))
}

func (h *WebhookHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.WebhookID(c.Param("id"))
	w, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.WebhookToResponse(w))
}

func (h *WebhookHandler) Update(c *gin.Context) {
	var req dto.UpdateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.WebhookID(c.Param("id"))
	w, err := h.svc.Update(c.Request.Context(), orgID, id, dto.UpdateWebhookReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.WebhookToResponse(w))
}

func (h *WebhookHandler) Delete(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.WebhookID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *WebhookHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := webhook.ListParams{OrgID: string(orgID)}
	listParams.Params = params
	webhooks, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.WebhookResponse, len(webhooks))
	for i, w := range webhooks {
		items[i] = dto.WebhookToResponse(w)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
