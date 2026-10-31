package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	appsup "github.com/razatechofficial/mail-os/application/suppression"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/suppression"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// SuppressionHandler serves the suppression list.
type SuppressionHandler struct {
	svc *appsup.Service
}

// NewSuppressionHandler builds the handler.
func NewSuppressionHandler(svc *appsup.Service) *SuppressionHandler {
	return &SuppressionHandler{svc: svc}
}

// Mount registers the routes.
func (h *SuppressionHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/suppressions", g.Require(access.PermSuppressionsRead), h.List)
	api.POST("/suppressions", g.Require(access.PermSuppressionsEdit), h.Add)
	api.DELETE("/suppressions", g.Require(access.PermSuppressionsEdit), h.Remove)
}

type suppressionView struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Type      string    `json:"type"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

func suppressionViewOf(s domain.Suppression) suppressionView {
	return suppressionView{ID: s.ID, Email: s.Email, Type: string(s.Type), Reason: s.Reason, Source: s.Source, CreatedAt: s.CreatedAt}
}

// List is GET /suppressions?type.
func (h *SuppressionHandler) List(c *gin.Context) {
	pg := page(c)
	list, total, err := h.svc.List(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Query("type"), pg.Limit, pg.Offset)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]suppressionView, len(list))
	for i, s := range list {
		out[i] = suppressionViewOf(s)
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Add is POST /suppressions.
func (h *SuppressionHandler) Add(c *gin.Context) {
	var req struct {
		Email  string `json:"email"`
		Type   string `json:"type"`
		Reason string `json:"reason"`
		Source string `json:"source"`
	}
	if !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	s, err := h.svc.Add(c.Request.Context(), domain.Suppression{OrgID: p.TenantID, Email: req.Email, Type: domain.Type(req.Type),
		Reason: req.Reason, Source: req.Source, CreatedBy: p.Actor()})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, suppressionViewOf(s))
}

// Remove is DELETE /suppressions with {"email"} (or ?email=).
func (h *SuppressionHandler) Remove(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		var req struct {
			Email string `json:"email"`
		}
		if !bind(c, &req) {
			return
		}
		email = req.Email
	}
	if email == "" {
		response.BadRequest(c, "email is required")
		return
	}
	if err := h.svc.Remove(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, email); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
