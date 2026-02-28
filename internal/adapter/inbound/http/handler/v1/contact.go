package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/contact"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type ContactHandler struct {
	svc contact.Service
}

func NewContactHandler(svc contact.Service) *ContactHandler {
	return &ContactHandler{svc: svc}
}

func (h *ContactHandler) Create(c *gin.Context) {
	var req dto.CreateContactRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	cont, err := h.svc.Create(c.Request.Context(), dto.CreateContactReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.ContactToResponse(cont))
}

func (h *ContactHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ContactID(c.Param("id"))
	cont, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.ContactToResponse(cont))
}

func (h *ContactHandler) Update(c *gin.Context) {
	var req dto.UpdateContactRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ContactID(c.Param("id"))
	cont, err := h.svc.Update(c.Request.Context(), orgID, id, dto.UpdateContactReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.ContactToResponse(cont))
}

func (h *ContactHandler) Delete(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ContactID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *ContactHandler) List(c *gin.Context) {
	orgID := httputil.OrgIDFromContext(c)
	params := httputil.PaginationFromContext(c)
	listParams := contact.ListParams{
		OrgID:  orgID,
		Status: c.Query("status"),
		Search: c.Query("search"),
	}
	listParams.Params = params
	contacts, total, err := h.svc.List(c.Request.Context(), domain.OrganizationID(orgID), listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.ContactResponse, len(contacts))
	for i, cont := range contacts {
		items[i] = dto.ContactToResponse(cont)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}

func (h *ContactHandler) BatchCreate(c *gin.Context) {
	var req dto.BatchCreateContactsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	inputs := make([]contact.CreateInput, len(req.Contacts))
	for i, r := range req.Contacts {
		inputs[i] = dto.CreateContactReqToInput(r, orgID)
	}
	count, err := h.svc.BatchCreate(c.Request.Context(), domain.OrganizationID(orgID), inputs)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, gin.H{"created_count": count})
}
