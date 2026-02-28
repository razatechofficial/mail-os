package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/sendingdomain"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type SendingDomainHandler struct {
	svc sendingdomain.Service
}

func NewSendingDomainHandler(svc sendingdomain.Service) *SendingDomainHandler {
	return &SendingDomainHandler{svc: svc}
}

func (h *SendingDomainHandler) Create(c *gin.Context) {
	var req dto.CreateSendingDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	sd, err := h.svc.Create(c.Request.Context(), dto.CreateSendingDomainReqToInput(req, string(orgID)))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.SendingDomainToResponse(sd))
}

func (h *SendingDomainHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.SendingDomainID(c.Param("id"))
	sd, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.SendingDomainToResponse(sd))
}

func (h *SendingDomainHandler) Verify(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.SendingDomainID(c.Param("id"))
	sd, err := h.svc.Verify(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.SendingDomainToResponse(sd))
}

func (h *SendingDomainHandler) Delete(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.SendingDomainID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *SendingDomainHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := sendingdomain.ListParams{}
	listParams.Params = params
	domains, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.SendingDomainResponse, len(domains))
	for i, d := range domains {
		items[i] = dto.SendingDomainToResponse(d)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
