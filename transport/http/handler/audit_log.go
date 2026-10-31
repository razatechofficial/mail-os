package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/auditlog"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// AuditLogHandler serves the tenant's audit log.
type AuditLogHandler struct {
	svc *auditlog.Service
}

// NewAuditLogHandler builds the handler.
func NewAuditLogHandler(svc *auditlog.Service) *AuditLogHandler { return &AuditLogHandler{svc: svc} }

// Mount registers the routes.
func (h *AuditLogHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/analytics/audit-logs", g.Require(access.PermAuditRead), h.List)
	api.GET("/analytics/audit-logs/export", g.Require(access.PermAuditExport), h.Export)
}

// auditLogView is the console's AuditLog shape with the IAM event fields.
type auditLogView struct {
	ID         string         `json:"id"`
	Service    string         `json:"service"`
	Tier       string         `json:"tier"`
	Severity   string         `json:"severity"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	ResourceID string         `json:"resource_id"`
	TenantUUID string         `json:"tenant_uuid,omitempty"`
	Changes    map[string]any `json:"changes,omitempty"`
	IPAddress  string         `json:"ip_address"`
	UserAgent  string         `json:"user_agent"`
	CreatedAt  time.Time      `json:"created_at"`
}

func view(ev audit.Event) auditLogView {
	v := auditLogView{ID: ev.EventID.String(), Service: ev.Service, Tier: ev.Tier, Severity: ev.Severity.String(),
		ActorType: ev.ActorType, Action: ev.Action, Resource: ev.ResourceType, ResourceID: ev.ResourceID,
		Changes: ev.Metadata, IPAddress: ev.IPAddress, UserAgent: ev.UserAgent, CreatedAt: ev.CreatedAt}
	switch {
	case ev.ActorUUID != nil:
		v.ActorID = ev.ActorUUID.String()
	case ev.Metadata["client_id"] != nil:
		v.ActorID, _ = ev.Metadata["client_id"].(string)
	}
	if ev.TenantUUID != nil {
		v.TenantUUID = ev.TenantUUID.String()
	}
	return v
}

func (h *AuditLogHandler) query(c *gin.Context) (auditlog.Query, bool) {
	from, err := timeQuery(c, "from")
	if err != nil {
		response.FromError(c, err)
		return auditlog.Query{}, false
	}
	to, err := timeQuery(c, "to")
	if err != nil {
		response.FromError(c, err)
		return auditlog.Query{}, false
	}
	p := middleware.PrincipalFrom(c)
	return auditlog.Query{Tenant: p.TenantID, ResourceType: c.Query("resource"), ResourceID: c.Query("resource_id"),
		Action: c.Query("action"), From: from, To: to}, true
}

// List is GET /analytics/audit-logs.
func (h *AuditLogHandler) List(c *gin.Context) {
	q, ok := h.query(c)
	if !ok {
		return
	}
	pg := page(c)
	events, total, err := h.svc.List(c.Request.Context(), q, pg.Limit, pg.Offset)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]auditLogView, 0, len(events))
	for _, ev := range events {
		out = append(out, view(ev))
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Export is GET /analytics/audit-logs/export (step-up).
func (h *AuditLogHandler) Export(c *gin.Context) {
	q, ok := h.query(c)
	if !ok {
		return
	}
	events, err := h.svc.Export(c.Request.Context(), q)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]auditLogView, 0, len(events))
	for _, ev := range events {
		out = append(out, view(ev))
	}
	response.OK(c, out)
}
