package handler

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"

	appprovider "github.com/razatechofficial/mail-os/application/provider"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// ProviderHandler serves mail providers. Credentials go in with the
// configuration and never come out: responses carry the non-secret
// settings, has_credentials and last-four hints. Changes need step-up.
type ProviderHandler struct {
	svc *appprovider.Service
}

// NewProviderHandler builds the handler.
func NewProviderHandler(svc *appprovider.Service) *ProviderHandler { return &ProviderHandler{svc: svc} }

// Mount registers the routes.
func (h *ProviderHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/providers", g.Require(access.PermProvidersRead), h.List)
	api.GET("/providers/:id", g.Require(access.PermProvidersRead), h.Get)
	api.POST("/providers", g.Require(access.PermProvidersManage), h.Create)
	api.PUT("/providers/:id", g.Require(access.PermProvidersManage), h.Update)
	api.DELETE("/providers/:id", g.Require(access.PermProvidersManage), h.Delete)
}

type providerView struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Type            string         `json:"type"`
	Configuration   map[string]any `json:"configuration"`
	Priority        int            `json:"priority"`
	Weight          int            `json:"weight"`
	DailyLimit      int            `json:"daily_limit"`
	IsActive        bool           `json:"is_active"`
	HasCredentials  bool           `json:"has_credentials"`
	CredentialHints domain.Hints   `json:"credential_hints,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func providerViewOf(p domain.Provider) providerView {
	v := p.View()
	cfg := map[string]any{}
	raw, _ := json.Marshal(v.Settings)
	_ = json.Unmarshal(raw, &cfg)
	return providerView{ID: v.ID, Name: v.Name, Type: string(v.Kind), Configuration: cfg, Priority: v.Priority, Weight: v.Weight,
		DailyLimit: v.DailyLimit, IsActive: v.Active, HasCredentials: v.HasCredentials, CredentialHints: v.CredentialHints,
		CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}

type providerRequest struct {
	Name          *string        `json:"name"`
	Type          *string        `json:"type"`
	Configuration map[string]any `json:"configuration"`
	Priority      *int           `json:"priority"`
	Weight        *int           `json:"weight"`
	DailyLimit    *int           `json:"daily_limit"`
	IsActive      *bool          `json:"is_active"`
}

func value[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// List is GET /providers.
func (h *ProviderHandler) List(c *gin.Context) {
	pg := page(c)
	list, total, err := h.svc.List(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, pg.Limit, pg.Offset)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]providerView, len(list))
	for i, p := range list {
		out[i] = providerViewOf(p)
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Get is GET /providers/:id.
func (h *ProviderHandler) Get(c *gin.Context) {
	p, err := h.svc.Get(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, providerViewOf(p))
}

// Create is POST /providers (step-up).
func (h *ProviderHandler) Create(c *gin.Context) {
	var req providerRequest
	if !bind(c, &req) {
		return
	}
	settings, creds, err := appprovider.SplitConfiguration(req.Configuration)
	if err != nil {
		response.FromError(c, err)
		return
	}
	p := middleware.PrincipalFrom(c)
	out, err := h.svc.Create(c.Request.Context(), p.TenantID, appprovider.Input{Name: value(req.Name), Kind: domain.Kind(value(req.Type)),
		Settings: settings, Credentials: creds, Priority: value(req.Priority), Weight: req.Weight, DailyLimit: value(req.DailyLimit),
		Active: req.IsActive}, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, providerViewOf(out))
}

// Update is PUT /providers/:id (step-up). A configuration replaces the
// settings; its blank secrets keep the stored ones.
func (h *ProviderHandler) Update(c *gin.Context) {
	var req providerRequest
	if !bind(c, &req) {
		return
	}
	patch := appprovider.Patch{Name: req.Name, Priority: req.Priority, Weight: req.Weight, DailyLimit: req.DailyLimit, Active: req.IsActive}
	if req.Type != nil {
		k := domain.Kind(*req.Type)
		patch.Kind = &k
	}
	if req.Configuration != nil {
		settings, creds, err := appprovider.SplitConfiguration(req.Configuration)
		if err != nil {
			response.FromError(c, err)
			return
		}
		patch.Settings, patch.Credentials = &settings, &creds
	}
	p := middleware.PrincipalFrom(c)
	out, err := h.svc.Update(c.Request.Context(), p.TenantID, c.Param("id"), patch, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, providerViewOf(out))
}

// Delete is DELETE /providers/:id (step-up).
func (h *ProviderHandler) Delete(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	if err := h.svc.Delete(c.Request.Context(), p.TenantID, c.Param("id"), p.Actor()); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
