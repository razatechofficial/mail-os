package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/contactlist"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type ContactListHandler struct {
	svc contactlist.Service
}

func NewContactListHandler(svc contactlist.Service) *ContactListHandler {
	return &ContactListHandler{svc: svc}
}

func (h *ContactListHandler) Create(c *gin.Context) {
	var req dto.CreateContactListRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	cl, err := h.svc.Create(c.Request.Context(), dto.CreateContactListReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.ContactListToResponse(cl))
}

func (h *ContactListHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ContactListID(c.Param("id"))
	cl, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.ContactListToResponse(cl))
}

func (h *ContactListHandler) Update(c *gin.Context) {
	var req dto.UpdateContactListRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ContactListID(c.Param("id"))
	cl, err := h.svc.Update(c.Request.Context(), orgID, id, dto.UpdateContactListReqToInput(req))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.ContactListToResponse(cl))
}

func (h *ContactListHandler) Delete(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.ContactListID(c.Param("id"))
	if err := h.svc.Delete(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *ContactListHandler) List(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	params := httputil.PaginationFromContext(c)
	listParams := contactlist.ListParams{}
	listParams.Params = params
	lists, total, err := h.svc.List(c.Request.Context(), orgID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.ContactListResponse, len(lists))
	for i, cl := range lists {
		items[i] = dto.ContactListToResponse(cl)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}

func (h *ContactListHandler) AddMembers(c *gin.Context) {
	var req dto.AddMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	listID := domain.ContactListID(c.Param("id"))
	contactIDs := make([]domain.ContactID, len(req.ContactIDs))
	for i, id := range req.ContactIDs {
		contactIDs[i] = domain.ContactID(id)
	}
	if err := h.svc.AddMembers(c.Request.Context(), orgID, listID, contactIDs); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *ContactListHandler) RemoveMembers(c *gin.Context) {
	var req dto.RemoveMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	listID := domain.ContactListID(c.Param("id"))
	contactIDs := make([]domain.ContactID, len(req.ContactIDs))
	for i, id := range req.ContactIDs {
		contactIDs[i] = domain.ContactID(id)
	}
	if err := h.svc.RemoveMembers(c.Request.Context(), orgID, listID, contactIDs); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.NoContent(c)
}

func (h *ContactListHandler) ListMembers(c *gin.Context) {
	listID := domain.ContactListID(c.Param("id"))
	params := httputil.PaginationFromContext(c)
	listParams := contactlist.ListParams{}
	listParams.Params = params
	members, total, err := h.svc.ListMembers(c.Request.Context(), listID, listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.ContactResponse, len(members))
	for i, m := range members {
		items[i] = dto.ContactToResponse(m)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}
