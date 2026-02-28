package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/apikey"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type APIKeyHandler struct {
	svc apikey.Service
}

func NewAPIKeyHandler(svc apikey.Service) *APIKeyHandler {
	return &APIKeyHandler{svc: svc}
}

func (h *APIKeyHandler) Create(c *gin.Context) {
	var req dto.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	key, plaintext, err := h.svc.Create(c.Request.Context(), dto.CreateAPIKeyReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	resp := dto.APIKeyCreateResponse{
		APIKeyResponse: dto.APIKeyToResponse(key),
		Key:            plaintext,
	}
	httputil.Created(c, resp)
}

func (h *APIKeyHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.APIKeyID(c.Param("id"))
	key, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.APIKeyToResponse(key))
}

func (h *APIKeyHandler) Revoke(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.APIKeyID(c.Param("id"))
	if err := h.svc.Revoke(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *APIKeyHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := apikey.ListParams{}
	listParams.Params = params
	keys, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.APIKeyResponse, len(keys))
	for i, k := range keys {
		items[i] = dto.APIKeyToResponse(k)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
