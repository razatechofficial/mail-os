package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	appkm "github.com/razatechofficial/mail-os/application/keymanager"
	"github.com/razatechofficial/mail-os/application/tenant"
	"github.com/razatechofficial/mail-os/domain/access"
	domainkm "github.com/razatechofficial/mail-os/domain/keymanager"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// TenantHandler serves the caller's identity, the tenant record and its
// security settings, and the encryption key status.
type TenantHandler struct {
	tenants *tenant.Service
	repo    tenant.Repository
	keys    *appkm.Service
}

// NewTenantHandler builds the handler.
func NewTenantHandler(tenants *tenant.Service, repo tenant.Repository, keys *appkm.Service) *TenantHandler {
	return &TenantHandler{tenants: tenants, repo: repo, keys: keys}
}

// Mount registers the routes.
func (h *TenantHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/me", g.Require(access.PermTemplatesRead), h.Me)
	api.GET("/organizations", g.Require(access.PermSettingsRead), h.ListOrganizations)
	api.GET("/organizations/:id", g.Require(access.PermSettingsRead), h.GetOrganization)
	api.GET("/tenant/settings", g.Require(access.PermSettingsRead), h.GetSettings)
	api.PUT("/tenant/settings", g.Require(access.PermSettingsManage), h.UpdateSettings)
	api.GET("/keys/encryption", g.Require(access.PermSettingsManage), h.EncryptionKeys)
	api.POST("/keys/encryption/:purpose/rotate", g.Require(access.PermSettingsManage), h.RotateKey)
}

type meView struct {
	Subject     string              `json:"sub"`
	TenantID    string              `json:"tenant_id"`
	OrgID       string              `json:"org_id"`
	Roles       []access.Role       `json:"roles"`
	Permissions []access.Permission `json:"permissions"`
	ACR         string              `json:"acr"`
	AuthTime    time.Time           `json:"auth_time"`
}

// Me is GET /me: who the token names and what its roles allow, so the
// console gates the same matrix the server enforces.
func (h *TenantHandler) Me(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	response.OK(c, meView{Subject: p.Subject, TenantID: p.TenantID, OrgID: p.OrgID, Roles: p.Roles,
		Permissions: access.PermissionsOf(p.Roles), ACR: p.ACR, AuthTime: p.AuthTime})
}

type organizationView struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug"`
	IsActive  bool           `json:"is_active"`
	Settings  map[string]any `json:"settings"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func (h *TenantHandler) organization(c *gin.Context) (organizationView, error) {
	p := middleware.PrincipalFrom(c)
	t, err := h.repo.Get(c.Request.Context(), p.TenantID)
	if err != nil {
		return organizationView{}, err
	}
	s, err := h.tenants.Settings(c.Request.Context(), p.TenantID)
	if err != nil {
		return organizationView{}, err
	}
	return organizationView{ID: t.ID, Name: t.Name, Slug: t.ID, IsActive: t.Active, CreatedAt: t.CreatedAt, UpdatedAt: s.UpdatedAt,
		Settings: map[string]any{"four_eyes_publish": s.FourEyesPublish, "message_retention_days": s.MessageRetentionDays}}, nil
}

// ListOrganizations is GET /organizations: the caller's own tenant only.
// Tenants come from IAM, so there is no create or delete.
func (h *TenantHandler) ListOrganizations(c *gin.Context) {
	o, err := h.organization(c)
	if err != nil {
		response.FromError(c, err)
		return
	}
	pg := page(c)
	response.List(c, []organizationView{o}, pagination.NewMeta(pg, 1))
}

// GetOrganization is GET /organizations/:id; another tenant is 404.
func (h *TenantHandler) GetOrganization(c *gin.Context) {
	if c.Param("id") != middleware.PrincipalFrom(c).TenantID {
		response.FromError(c, apperrors.NotFound("organization not found"))
		return
	}
	o, err := h.organization(c)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, o)
}

// GetSettings is GET /tenant/settings.
func (h *TenantHandler) GetSettings(c *gin.Context) {
	s, err := h.tenants.Settings(c.Request.Context(), middleware.PrincipalFrom(c).TenantID)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, s)
}

type settingsInput struct {
	FourEyesPublish      bool `json:"four_eyes_publish"`
	MessageRetentionDays *int `json:"message_retention_days"`
}

// UpdateSettings is PUT /tenant/settings (mailos_admin, step-up).
func (h *TenantHandler) UpdateSettings(c *gin.Context) {
	var in settingsInput
	if !bind(c, &in) {
		return
	}
	p := middleware.PrincipalFrom(c)
	s, err := h.tenants.UpdateSettings(c.Request.Context(), domaintenant.Settings{TenantID: p.TenantID,
		FourEyesPublish: in.FourEyesPublish, MessageRetentionDays: in.MessageRetentionDays}, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, s)
}

// EncryptionKeys is GET /keys/encryption: keys per purpose and how many
// values each still seals, never key material.
func (h *TenantHandler) EncryptionKeys(c *gin.Context) {
	st, err := h.keys.Status(c.Request.Context())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, st)
}

// RotateKey is POST /keys/encryption/:purpose/rotate (mailos_admin, step-up).
func (h *TenantHandler) RotateKey(c *gin.Context) {
	purpose := domainkm.Purpose(c.Param("purpose"))
	if !purpose.Valid() {
		response.FromError(c, apperrors.Invalid("purpose", "invalid", "unknown key purpose"))
		return
	}
	k, err := h.keys.Rotate(c.Request.Context(), purpose, middleware.PrincipalFrom(c).Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, appkm.KeyStatus{KID: k.KID, State: k.State, Provider: k.Provider, CreatedAt: k.CreatedAt})
}
