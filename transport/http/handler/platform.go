package handler

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/platform"
	"github.com/razatechofficial/mail-os/domain/platformrole"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// PlatformRoles reads a platform account's roles and permissions in ACS
// (infrastructure/acs.Platform).
type PlatformRoles interface {
	Holdings(ctx context.Context, subject string) ([]platformrole.Holding, []platformrole.Role, error)
	AllowedEach(ctx context.Context, subject string, perms []platformrole.Permission) ([]bool, error)
}

// PlatformHandler serves the platform API's reads (contract C6). Each
// route is guarded by one ACS permission; /me needs only a platform token.
type PlatformHandler struct {
	svc   *platform.Service
	roles PlatformRoles
}

// NewPlatformHandler builds the handler; nil roles (ACS not configured)
// make /me answer 503.
func NewPlatformHandler(svc *platform.Service, roles PlatformRoles) *PlatformHandler {
	return &PlatformHandler{svc: svc, roles: roles}
}

// MountPlatform registers the routes on /api/platform/v1.
func (h *PlatformHandler) MountPlatform(api *gin.RouterGroup, g middleware.PlatformGuard) {
	api.GET("/me", h.Me)
	api.GET("/tenants", g.Require(platformrole.ViewTenants), h.Tenants)
	api.GET("/connectors", g.Require(platformrole.ViewConnectors), h.Connectors)
	api.GET("/templates", g.Require(platformrole.ViewTemplates), h.Templates)
	api.GET("/templates/:topic", g.Require(platformrole.ViewTemplates), h.Template)
}

type activeRole struct {
	Role      platformrole.Role `json:"role"`
	ExpiresAt *time.Time        `json:"expires_at"`
}

type platformMe struct {
	Subject     string                    `json:"subject"`
	Email       string                    `json:"email"`
	Roles       []activeRole              `json:"roles"`
	Eligible    []platformrole.Role       `json:"eligible"`
	Permissions []platformrole.Permission `json:"permissions"`
}

// Me is GET /api/platform/v1/me: who the token names, the roles active now
// (with their end) and eligible, and the permissions they give, so the
// console shows only what the server allows.
func (h *PlatformHandler) Me(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	if h.roles == nil {
		response.FromError(c, apperrors.Unavailable("the platform API is not configured (no authorization service)"))
		return
	}
	ctx := c.Request.Context()
	active, eligible, err := h.roles.Holdings(ctx, p.Subject)
	if err != nil {
		response.FromError(c, err)
		return
	}
	perms := platformrole.AllPermissions()
	allowed, err := h.roles.AllowedEach(ctx, p.Subject, perms)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := platformMe{Subject: p.Subject, Email: p.Email, Roles: []activeRole{}, Eligible: []platformrole.Role{}, Permissions: []platformrole.Permission{}}
	for _, a := range active {
		r := activeRole{Role: a.Role}
		if !a.ExpiresAt.IsZero() {
			t := a.ExpiresAt.UTC()
			r.ExpiresAt = &t
		}
		out.Roles = append(out.Roles, r)
	}
	out.Eligible = append(out.Eligible, eligible...)
	for i, ok := range allowed {
		if ok {
			out.Permissions = append(out.Permissions, perms[i])
		}
	}
	response.OK(c, out)
}

type tenantsPage struct {
	Items      []platform.TenantAggregate `json:"items"`
	NextCursor string                     `json:"next_cursor"`
}

// Tenants is GET /api/platform/v1/tenants?limit=&cursor=: tenants with
// counts only (no subject, recipient, body or template data).
func (h *PlatformHandler) Tenants(c *gin.Context) {
	items, next, err := h.svc.Tenants(c.Request.Context(), intQuery(c, "limit", 0), c.Query("cursor"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, tenantsPage{Items: items, NextCursor: next})
}

// Connectors is GET /api/platform/v1/connectors: the provider kinds and
// the platform relay, never a credential.
func (h *PlatformHandler) Connectors(c *gin.Context) {
	items, err := h.svc.Connectors(c.Request.Context())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, gin.H{"items": items})
}

// Templates is GET /api/platform/v1/templates: the platform topics.
func (h *PlatformHandler) Templates(c *gin.Context) {
	response.OK(c, gin.H{"items": h.svc.Templates()})
}

// Template is GET /api/platform/v1/templates/{topic}: the platform
// default, never a tenant's override.
func (h *PlatformHandler) Template(c *gin.Context) {
	t, err := h.svc.Template(c.Param("topic"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, t)
}
