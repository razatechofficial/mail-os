package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/contact"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/contact"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// ContactListHandler serves the tenant's contact lists and their members.
type ContactListHandler struct {
	svc *contact.Service
}

// NewContactListHandler builds the handler.
func NewContactListHandler(svc *contact.Service) *ContactListHandler {
	return &ContactListHandler{svc: svc}
}

// Mount registers the routes.
func (h *ContactListHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/contact-lists", g.Require(access.PermContactsRead), h.List)
	api.POST("/contact-lists", g.Require(access.PermContactsManage), h.Create)
	api.GET("/contact-lists/:id", g.Require(access.PermContactsRead), h.Get)
	api.PUT("/contact-lists/:id", g.Require(access.PermContactsManage), h.Update)
	api.DELETE("/contact-lists/:id", g.Require(access.PermContactsManage), h.Delete)
	api.GET("/contact-lists/:id/members", g.Require(access.PermContactsRead), h.Members)
	api.POST("/contact-lists/:id/members", g.Require(access.PermContactsManage), h.AddMembers)
	api.DELETE("/contact-lists/:id/members", g.Require(access.PermContactsManage), h.RemoveMembers)
}

type contactListView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	Query       string    `json:"query"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func listOut(l domain.List) contactListView {
	return contactListView{ID: l.ID, Name: l.Name, Description: l.Description, Type: string(l.Type), Query: l.Query,
		CreatedAt: l.CreatedAt, UpdatedAt: l.UpdatedAt}
}

// List is GET /contact-lists.
func (h *ContactListHandler) List(c *gin.Context) {
	pg := page(c)
	ls, total, err := h.svc.Lists(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, pg.Limit, pg.Offset)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]contactListView, 0, len(ls))
	for _, l := range ls {
		out = append(out, listOut(l))
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Get is GET /contact-lists/:id.
func (h *ContactListHandler) Get(c *gin.Context) {
	l, err := h.svc.GetList(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, listOut(l))
}

// Create is POST /contact-lists. Only static lists are accepted.
func (h *ContactListHandler) Create(c *gin.Context) {
	var in struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Type        domain.ListType `json:"type"`
		Query       string          `json:"query"`
	}
	if !bind(c, &in) {
		return
	}
	l, err := h.svc.CreateList(c.Request.Context(), middleware.PrincipalFrom(c).TenantID,
		domain.List{Name: in.Name, Description: in.Description, Type: in.Type, Query: in.Query})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, listOut(l))
}

// Update is PUT /contact-lists/:id; absent fields keep their value.
func (h *ContactListHandler) Update(c *gin.Context) {
	var in struct {
		Name        *string          `json:"name"`
		Description *string          `json:"description"`
		Type        *domain.ListType `json:"type"`
		Query       *string          `json:"query"`
	}
	if !bind(c, &in) {
		return
	}
	l, err := h.svc.UpdateList(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"),
		contact.ListUpdate{Name: in.Name, Description: in.Description, Type: in.Type, Query: in.Query})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, listOut(l))
}

// Delete is DELETE /contact-lists/:id; refused (409) while a scheduled,
// sending or paused campaign sends to it.
func (h *ContactListHandler) Delete(c *gin.Context) {
	if err := h.svc.DeleteList(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id")); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}

// Members is GET /contact-lists/:id/members (filters as GET /contacts).
func (h *ContactListHandler) Members(c *gin.Context) {
	f, pg := contactFilter(c)
	cs, total, err := h.svc.Members(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"), f)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.List(c, contactsOut(cs), pagination.NewMeta(pg, total))
}

type membersInput struct {
	ContactIDs []string `json:"contact_ids"`
}

// AddMembers is POST /contact-lists/:id/members; every id must be one of
// the tenant's contacts (422 otherwise, nothing added).
func (h *ContactListHandler) AddMembers(c *gin.Context) {
	var in membersInput
	if !bind(c, &in) {
		return
	}
	if _, err := h.svc.AddMembers(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"), in.ContactIDs); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}

// RemoveMembers is DELETE /contact-lists/:id/members with the ids in the
// body.
func (h *ContactListHandler) RemoveMembers(c *gin.Context) {
	var in membersInput
	if !bind(c, &in) {
		return
	}
	if _, err := h.svc.RemoveMembers(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"), in.ContactIDs); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
