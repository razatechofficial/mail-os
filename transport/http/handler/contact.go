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

// ContactHandler serves the tenant's contacts.
type ContactHandler struct {
	svc *contact.Service
}

// NewContactHandler builds the handler.
func NewContactHandler(svc *contact.Service) *ContactHandler { return &ContactHandler{svc: svc} }

// Mount registers the routes.
func (h *ContactHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/contacts", g.Require(access.PermContactsRead), h.List)
	api.POST("/contacts", g.Require(access.PermContactsManage), h.Create)
	api.POST("/contacts/batch", g.Require(access.PermContactsManage), h.Import)
	api.GET("/contacts/:id", g.Require(access.PermContactsRead), h.Get)
	api.PUT("/contacts/:id", g.Require(access.PermContactsManage), h.Update)
	api.DELETE("/contacts/:id", g.Require(access.PermContactsManage), h.Delete)
}

type contactView struct {
	ID        string         `json:"id"`
	Email     string         `json:"email"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Status    string         `json:"status"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func contactOut(c domain.Contact) contactView {
	return contactView{ID: c.ID, Email: c.Email, FirstName: c.FirstName, LastName: c.LastName, Status: string(c.Status),
		Metadata: c.Metadata, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

func contactsOut(cs []domain.Contact) []contactView {
	out := make([]contactView, 0, len(cs))
	for _, c := range cs {
		out = append(out, contactOut(c))
	}
	return out
}

// contactFilter reads page, limit, sort_by, sort_order, status and search.
func contactFilter(c *gin.Context) (contact.Filter, pagination.Params) {
	pg := page(c)
	return contact.Filter{Status: domain.Status(c.Query("status")), Search: c.Query("search"),
		SortBy: pg.SortBy, SortOrder: pg.SortOrder, Limit: pg.Limit, Offset: pg.Offset}, pg
}

type contactInput struct {
	Email     string         `json:"email"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Metadata  map[string]any `json:"metadata"`
}

func (in contactInput) contact() domain.Contact {
	return domain.Contact{Email: in.Email, FirstName: in.FirstName, LastName: in.LastName, Metadata: in.Metadata}
}

// List is GET /contacts.
func (h *ContactHandler) List(c *gin.Context) {
	f, pg := contactFilter(c)
	cs, total, err := h.svc.List(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, f)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.List(c, contactsOut(cs), pagination.NewMeta(pg, total))
}

// Get is GET /contacts/:id.
func (h *ContactHandler) Get(c *gin.Context) {
	ct, err := h.svc.Get(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, contactOut(ct))
}

// Create is POST /contacts.
func (h *ContactHandler) Create(c *gin.Context) {
	var in contactInput
	if !bind(c, &in) {
		return
	}
	ct, err := h.svc.Create(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, in.contact())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, contactOut(ct))
}

// Import is POST /contacts/batch: up to 1000 contacts; addresses already
// in the audience are skipped.
func (h *ContactHandler) Import(c *gin.Context) {
	var in struct {
		Contacts []contactInput `json:"contacts"`
	}
	if !bind(c, &in) {
		return
	}
	cs := make([]domain.Contact, len(in.Contacts))
	for i, x := range in.Contacts {
		cs[i] = x.contact()
	}
	res, err := h.svc.Import(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, cs)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, res)
}

// Update is PUT /contacts/:id; absent fields keep their value.
func (h *ContactHandler) Update(c *gin.Context) {
	var in struct {
		Email     *string         `json:"email"`
		FirstName *string         `json:"first_name"`
		LastName  *string         `json:"last_name"`
		Status    *domain.Status  `json:"status"`
		Metadata  *map[string]any `json:"metadata"`
	}
	if !bind(c, &in) {
		return
	}
	ct, err := h.svc.Update(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"), contact.Update{
		Email: in.Email, FirstName: in.FirstName, LastName: in.LastName, Status: in.Status, Metadata: in.Metadata})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, contactOut(ct))
}

// Delete is DELETE /contacts/:id: the contact, its memberships and its
// campaign recipient rows are removed.
func (h *ContactHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id")); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
