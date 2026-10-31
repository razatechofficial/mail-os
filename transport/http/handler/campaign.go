package handler

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/campaign"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/campaign"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// CampaignHandler serves the tenant's campaigns and their status changes.
type CampaignHandler struct {
	svc *campaign.Service
}

// NewCampaignHandler builds the handler.
func NewCampaignHandler(svc *campaign.Service) *CampaignHandler { return &CampaignHandler{svc: svc} }

// Mount registers the routes.
func (h *CampaignHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/campaigns", g.Require(access.PermCampaignsRead), h.List)
	api.POST("/campaigns", g.Require(access.PermCampaignsManage), h.Create)
	api.GET("/campaigns/:id", g.Require(access.PermCampaignsRead), h.Get)
	api.PUT("/campaigns/:id", g.Require(access.PermCampaignsManage), h.Update)
	api.DELETE("/campaigns/:id", g.Require(access.PermCampaignsManage), h.Delete)
	api.POST("/campaigns/:id/launch", g.Require(access.PermCampaignsManage), h.Launch)
	api.POST("/campaigns/:id/pause", g.Require(access.PermCampaignsManage), h.Pause)
	api.POST("/campaigns/:id/resume", g.Require(access.PermCampaignsManage), h.Resume)
	api.POST("/campaigns/:id/cancel", g.Require(access.PermCampaignsManage), h.Cancel)
}

type campaignView struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Subject         string         `json:"subject"`
	FromName        string         `json:"from_name"`
	FromEmail       string         `json:"from_email"`
	TemplateID      string         `json:"template_id"`
	ContactListID   string         `json:"contact_list_id"`
	Type            string         `json:"type"`
	Status          string         `json:"status"`
	ScheduledAt     *time.Time     `json:"scheduled_at,omitempty"`
	StartedAt       *time.Time     `json:"started_at,omitempty"`
	CompletedAt     *time.Time     `json:"completed_at,omitempty"`
	TotalRecipients int            `json:"total_recipients"`
	SentCount       int            `json:"sent_count"`
	FailedCount     int            `json:"failed_count"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func campaignOut(c domain.Campaign) campaignView {
	return campaignView{ID: c.ID, Name: c.Name, Subject: c.Subject, FromName: c.FromName, FromEmail: c.FromEmail,
		TemplateID: c.TemplateID, ContactListID: c.ContactListID, Type: string(c.Type), Status: string(c.Status),
		ScheduledAt: c.ScheduledAt, StartedAt: c.StartedAt, CompletedAt: c.CompletedAt, TotalRecipients: c.TotalRecipients,
		SentCount: c.SentCount, FailedCount: c.FailedCount, Metadata: c.Metadata, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

// List is GET /campaigns (?status= filters).
func (h *CampaignHandler) List(c *gin.Context) {
	pg := page(c)
	cs, total, err := h.svc.List(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, campaign.Filter{
		Status: domain.Status(c.Query("status")), SortBy: pg.SortBy, SortOrder: pg.SortOrder, Limit: pg.Limit, Offset: pg.Offset})
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]campaignView, 0, len(cs))
	for _, x := range cs {
		out = append(out, campaignOut(x))
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Get is GET /campaigns/:id.
func (h *CampaignHandler) Get(c *gin.Context) {
	x, err := h.svc.Get(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, campaignOut(x))
}

// Create is POST /campaigns: a draft; launch sends or schedules it.
func (h *CampaignHandler) Create(c *gin.Context) {
	var in struct {
		Name          string         `json:"name"`
		Subject       string         `json:"subject"`
		FromName      string         `json:"from_name"`
		FromEmail     string         `json:"from_email"`
		TemplateID    string         `json:"template_id"`
		ContactListID string         `json:"contact_list_id"`
		Type          domain.Type    `json:"type"`
		ScheduledAt   *time.Time     `json:"scheduled_at"`
		Metadata      map[string]any `json:"metadata"`
	}
	if !bind(c, &in) {
		return
	}
	if in.ScheduledAt != nil {
		at := in.ScheduledAt.UTC()
		in.ScheduledAt = &at
	}
	x, err := h.svc.Create(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, domain.Campaign{
		Name: in.Name, Subject: in.Subject, FromName: in.FromName, FromEmail: in.FromEmail, TemplateID: in.TemplateID,
		ContactListID: in.ContactListID, Type: in.Type, ScheduledAt: in.ScheduledAt, Metadata: in.Metadata})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, campaignOut(x))
}

// Update is PUT /campaigns/:id: a draft or scheduled campaign only (409
// otherwise); absent fields keep their value.
func (h *CampaignHandler) Update(c *gin.Context) {
	var in struct {
		Name          *string         `json:"name"`
		Subject       *string         `json:"subject"`
		FromName      *string         `json:"from_name"`
		FromEmail     *string         `json:"from_email"`
		TemplateID    *string         `json:"template_id"`
		ContactListID *string         `json:"contact_list_id"`
		Type          *domain.Type    `json:"type"`
		ScheduledAt   *time.Time      `json:"scheduled_at"`
		Metadata      *map[string]any `json:"metadata"`
	}
	if !bind(c, &in) {
		return
	}
	x, err := h.svc.Update(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"), campaign.Update{
		Name: in.Name, Subject: in.Subject, FromName: in.FromName, FromEmail: in.FromEmail, TemplateID: in.TemplateID,
		ContactListID: in.ContactListID, Type: in.Type, ScheduledAt: in.ScheduledAt, Metadata: in.Metadata})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, campaignOut(x))
}

// Delete is DELETE /campaigns/:id; refused (409) while sending.
func (h *CampaignHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id")); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}

// action answers a status change with the campaign after it.
func (h *CampaignHandler) action(c *gin.Context, do func(ctx context.Context, tenant, id string) (domain.Campaign, error)) {
	x, err := do(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, campaignOut(x))
}

// Launch is POST /campaigns/:id/launch: sending now, or scheduled when the
// draft's scheduled_at is in the future. 503 until sending is configured.
func (h *CampaignHandler) Launch(c *gin.Context) { h.action(c, h.svc.Launch) }

// Pause is POST /campaigns/:id/pause; the page in flight finishes.
func (h *CampaignHandler) Pause(c *gin.Context) { h.action(c, h.svc.Pause) }

// Resume is POST /campaigns/:id/resume.
func (h *CampaignHandler) Resume(c *gin.Context) { h.action(c, h.svc.Resume) }

// Cancel is POST /campaigns/:id/cancel.
func (h *CampaignHandler) Cancel(c *gin.Context) { h.action(c, h.svc.Cancel) }
