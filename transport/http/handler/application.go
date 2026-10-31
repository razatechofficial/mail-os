package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/applications"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/application"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// ApplicationHandler serves the application registry: every MailOS role
// reads it; mailos_admin registers, changes, suspends and deletes
// applications, with step-up.
type ApplicationHandler struct {
	svc *applications.Service
}

// NewApplicationHandler builds the handler.
func NewApplicationHandler(svc *applications.Service) *ApplicationHandler {
	return &ApplicationHandler{svc: svc}
}

// Mount registers the routes.
func (h *ApplicationHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/applications", g.Require(access.PermApplicationsRead), h.List)
	api.GET("/applications/:id", g.Require(access.PermApplicationsRead), h.Get)
	api.GET("/applications/:id/usage", g.Require(access.PermApplicationsRead), h.Usage)
	api.POST("/applications", g.Require(access.PermApplicationsManage), h.Create)
	api.PUT("/applications/:id", g.Require(access.PermApplicationsManage), h.Update)
	api.DELETE("/applications/:id", g.Require(access.PermApplicationsManage), h.Delete)
	api.POST("/applications/:id/suspend", g.Require(access.PermApplicationsManage), h.Suspend)
	api.POST("/applications/:id/activate", g.Require(access.PermApplicationsManage), h.Activate)
}

type applicationView struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Kind             string    `json:"kind"`
	ClientID         string    `json:"client_id"`
	Status           string    `json:"status"`
	SuspendedReason  string    `json:"suspended_reason"`
	Environment      string    `json:"environment"`
	Stream           string    `json:"stream"`
	MessageTypes     []string  `json:"message_types"`
	Senders          []string  `json:"senders"`
	DefaultFromEmail string    `json:"default_from_email"`
	DefaultFromName  string    `json:"default_from_name"`
	DefaultReplyTo   string    `json:"default_reply_to"`
	RatePerMinute    int       `json:"rate_limit_per_minute"`
	DailyQuota       int       `json:"daily_quota"`
	BrowserTemplates []string  `json:"browser_templates"`
	UserRatePerHour  int       `json:"user_rate_limit_per_hour"`
	AllowedOrigins   []string  `json:"allowed_origins"`
	System           bool      `json:"system"`
	CreatedBy        string    `json:"created_by"`
	UpdatedBy        string    `json:"updated_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func applicationViewOf(a domain.Application) applicationView {
	return applicationView{ID: a.ID, Name: a.Name, Description: a.Description, Kind: string(a.Kind), ClientID: a.ClientID,
		Status: string(a.Status), SuspendedReason: a.SuspendedReason, Environment: string(a.Environment), Stream: string(a.Stream),
		MessageTypes: orEmpty(a.MessageTypes), Senders: orEmpty(a.Senders), DefaultFromEmail: a.DefaultFromEmail,
		DefaultFromName: a.DefaultFromName, DefaultReplyTo: a.DefaultReplyTo, RatePerMinute: a.RatePerMinute,
		DailyQuota: a.DailyQuota, BrowserTemplates: orEmpty(a.BrowserTemplates), UserRatePerHour: a.UserRatePerHour,
		AllowedOrigins: orEmpty(a.AllowedOrigins), System: a.System, CreatedBy: a.CreatedBy, UpdatedBy: a.UpdatedBy,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
}

// applicationRequest is what an administrator sends to create or replace
// an application.
type applicationRequest struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Kind             string   `json:"kind"`
	ClientID         string   `json:"client_id"`
	Environment      string   `json:"environment"`
	Stream           string   `json:"stream"`
	MessageTypes     []string `json:"message_types"`
	Senders          []string `json:"senders"`
	DefaultFromEmail string   `json:"default_from_email"`
	DefaultFromName  string   `json:"default_from_name"`
	DefaultReplyTo   string   `json:"default_reply_to"`
	RatePerMinute    int      `json:"rate_limit_per_minute"`
	DailyQuota       int      `json:"daily_quota"`
	BrowserTemplates []string `json:"browser_templates"`
	UserRatePerHour  int      `json:"user_rate_limit_per_hour"`
	AllowedOrigins   []string `json:"allowed_origins"`
}

func (r applicationRequest) input() applications.Input {
	return applications.Input{Name: r.Name, Description: r.Description, Kind: domain.Kind(r.Kind), ClientID: r.ClientID,
		Environment: domain.Environment(r.Environment), Stream: domain.Stream(r.Stream), MessageTypes: r.MessageTypes,
		Senders: r.Senders, DefaultFromEmail: r.DefaultFromEmail, DefaultFromName: r.DefaultFromName,
		DefaultReplyTo: r.DefaultReplyTo, RatePerMinute: r.RatePerMinute, DailyQuota: r.DailyQuota,
		BrowserTemplates: r.BrowserTemplates, UserRatePerHour: r.UserRatePerHour, AllowedOrigins: r.AllowedOrigins}
}

// List is GET /applications?status&kind.
func (h *ApplicationHandler) List(c *gin.Context) {
	pg := page(c)
	items, total, err := h.svc.List(c.Request.Context(), applications.Filter{TenantID: middleware.PrincipalFrom(c).TenantID,
		Status: c.Query("status"), Kind: c.Query("kind"), Limit: pg.Limit, Offset: pg.Offset})
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]applicationView, len(items))
	for i, a := range items {
		out[i] = applicationViewOf(a)
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Get is GET /applications/:id.
func (h *ApplicationHandler) Get(c *gin.Context) {
	a, err := h.svc.Get(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, applicationViewOf(a))
}

// Usage is GET /applications/:id/usage?days (1 to 90, default 30).
func (h *ApplicationHandler) Usage(c *gin.Context) {
	u, err := h.svc.Usage(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"), intQuery(c, "days", 30))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, u)
}

// Create is POST /applications (step-up).
func (h *ApplicationHandler) Create(c *gin.Context) {
	var req applicationRequest
	if !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	a, err := h.svc.Create(c.Request.Context(), p.TenantID, req.input(), p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, applicationViewOf(a))
}

// Update is PUT /applications/:id (step-up): every editable field.
func (h *ApplicationHandler) Update(c *gin.Context) {
	var req applicationRequest
	if !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	a, err := h.svc.Update(c.Request.Context(), p.TenantID, c.Param("id"), req.input(), p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, applicationViewOf(a))
}

// Delete is DELETE /applications/:id (step-up).
func (h *ApplicationHandler) Delete(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	if err := h.svc.Delete(c.Request.Context(), p.TenantID, c.Param("id"), p.Actor()); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}

// Suspend is POST /applications/:id/suspend {reason} (step-up): every call
// of the application is refused from now on.
func (h *ApplicationHandler) Suspend(c *gin.Context) {
	var req struct {
		Reason string `json:"reason"`
	}
	if c.Request.ContentLength != 0 && !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	a, err := h.svc.Suspend(c.Request.Context(), p.TenantID, c.Param("id"), req.Reason, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, applicationViewOf(a))
}

// Activate is POST /applications/:id/activate (step-up).
func (h *ApplicationHandler) Activate(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	a, err := h.svc.Activate(c.Request.Context(), p.TenantID, c.Param("id"), p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, applicationViewOf(a))
}
