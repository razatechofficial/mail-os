package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	appwebhook "github.com/razatechofficial/mail-os/application/webhook"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/webhook"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// WebhookHandler serves outbound webhooks, tenant-wide or for one of the
// tenant's applications. The signing secret is returned once, when
// created; changes need step-up.
type WebhookHandler struct {
	svc  *appwebhook.Service
	apps ApplicationReader
}

// NewWebhookHandler builds the handler; apps checks the application an
// endpoint is scoped to.
func NewWebhookHandler(svc *appwebhook.Service, apps ApplicationReader) *WebhookHandler {
	return &WebhookHandler{svc: svc, apps: apps}
}

// Mount registers the routes.
func (h *WebhookHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/webhooks", g.Require(access.PermWebhooksRead), h.List)
	api.GET("/webhooks/:id", g.Require(access.PermWebhooksRead), h.Get)
	api.POST("/webhooks", g.Require(access.PermWebhooksManage), h.Create)
	api.PUT("/webhooks/:id", g.Require(access.PermWebhooksManage), h.Update)
	api.DELETE("/webhooks/:id", g.Require(access.PermWebhooksManage), h.Delete)
}

type webhookView struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	URL           string    `json:"url"`
	Events        []string  `json:"events"`
	IsActive      bool      `json:"is_active"`
	Secret        string    `json:"secret,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func webhookViewOf(w domain.Webhook) webhookView {
	events := w.Events
	if events == nil {
		events = []string{}
	}
	return webhookView{ID: w.ID, ApplicationID: w.ApplicationID, URL: w.URL, Events: events, IsActive: w.Active, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt}
}

// List is GET /webhooks.
func (h *WebhookHandler) List(c *gin.Context) {
	pg := page(c)
	list, total, err := h.svc.List(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, pg.Limit, pg.Offset)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]webhookView, len(list))
	for i, w := range list {
		out[i] = webhookViewOf(w)
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Get is GET /webhooks/:id.
func (h *WebhookHandler) Get(c *gin.Context) {
	w, err := h.svc.Get(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, webhookViewOf(w))
}

// Create is POST /webhooks (step-up); the response carries the secret.
func (h *WebhookHandler) Create(c *gin.Context) {
	var req struct {
		ApplicationID string   `json:"application_id"`
		URL           string   `json:"url"`
		Secret        string   `json:"secret"`
		Events        []string `json:"events"`
	}
	if !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	if req.ApplicationID != "" && h.apps != nil {
		if _, err := h.apps.Get(c.Request.Context(), p.TenantID, req.ApplicationID); err != nil {
			response.FromError(c, err)
			return
		}
	}
	w, secret, err := h.svc.Create(c.Request.Context(), p.TenantID, appwebhook.Input{ApplicationID: req.ApplicationID, URL: req.URL,
		Secret: req.Secret, Events: req.Events}, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	v := webhookViewOf(w)
	v.Secret = secret
	c.Header("Cache-Control", "no-store")
	response.Created(c, v)
}

// Update is PUT /webhooks/:id (step-up).
func (h *WebhookHandler) Update(c *gin.Context) {
	var req struct {
		URL      *string   `json:"url"`
		Secret   *string   `json:"secret"`
		Events   *[]string `json:"events"`
		IsActive *bool     `json:"is_active"`
	}
	if !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	w, err := h.svc.Update(c.Request.Context(), p.TenantID, c.Param("id"),
		appwebhook.Patch{URL: req.URL, Secret: req.Secret, Events: req.Events, Active: req.IsActive}, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, webhookViewOf(w))
}

// Delete is DELETE /webhooks/:id (step-up).
func (h *WebhookHandler) Delete(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	if err := h.svc.Delete(c.Request.Context(), p.TenantID, c.Param("id"), p.Actor()); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
