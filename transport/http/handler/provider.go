package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	appprovider "github.com/razatechofficial/mail-os/application/provider"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/provider"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// ProviderHandler serves mail providers. Credentials go in and never come
// out: responses carry the non-secret settings, has_credentials and a hint
// per stored secret. Changes, and testing unsaved values (which may use
// the stored secrets), need step-up; testing a stored provider does not.
type ProviderHandler struct {
	svc *appprovider.Service
}

// NewProviderHandler builds the handler.
func NewProviderHandler(svc *appprovider.Service) *ProviderHandler { return &ProviderHandler{svc: svc} }

// Mount registers the routes.
func (h *ProviderHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/providers", g.Require(access.PermProvidersRead), h.List)
	api.GET("/providers/schema", g.Require(access.PermProvidersRead), h.Schema)
	api.GET("/providers/:id", g.Require(access.PermProvidersRead), h.Get)
	api.POST("/providers", g.Require(access.PermProvidersManage), h.Create)
	api.POST("/providers/test-connection", g.Require(access.PermProvidersManage), h.TestDraft)
	api.PUT("/providers/:id", g.Require(access.PermProvidersManage), h.Update)
	api.DELETE("/providers/:id", g.Require(access.PermProvidersManage), h.Delete)
	api.POST("/providers/:id/test-connection", g.Require(access.PermProvidersTest), h.TestConnection)
	api.POST("/providers/:id/send-test", g.Require(access.PermProvidersTest), h.SendTest)
}

type providerView struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Settings map[string]any `json:"settings"`
	Priority int            `json:"priority"`
	Weight   int            `json:"weight"`
	// DailyLimit is messages per UTC day; 0 is unlimited.
	DailyLimit     int  `json:"daily_limit"`
	IsActive       bool `json:"is_active"`
	HasCredentials bool `json:"has_credentials"`
	// CredentialHints has a key per stored secret: its hint, or "".
	CredentialHints domain.Hints     `json:"credential_hints"`
	LastTest        *domain.LastTest `json:"last_test"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

func providerViewOf(p domain.Provider) providerView {
	v := p.View()
	hints := v.CredentialHints
	if hints == nil {
		hints = domain.Hints{}
	}
	return providerView{ID: v.ID, Name: v.Name, Type: string(v.Kind), Settings: v.Settings.Map(), Priority: v.Priority, Weight: v.Weight,
		DailyLimit: v.DailyLimit, IsActive: v.Active, HasCredentials: v.HasCredentials, CredentialHints: hints, LastTest: v.LastTest,
		CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}

// providerRequest is a create or update. On update the type is fixed,
// settings replace the stored ones, and an omitted or empty credential
// keeps the stored secret.
type providerRequest struct {
	Name        *string        `json:"name"`
	Type        *string        `json:"type"`
	Settings    map[string]any `json:"settings"`
	Credentials map[string]any `json:"credentials"`
	Priority    *int           `json:"priority"`
	Weight      *int           `json:"weight"`
	DailyLimit  *int           `json:"daily_limit"`
	IsActive    *bool          `json:"is_active"`
}

// decode reads the request's settings and credentials, reporting both
// sides' field errors together.
func (r providerRequest) decode() (domain.Settings, domain.Credentials, error) {
	settings, serr := domain.DecodeSettings(r.Settings)
	creds, cerr := domain.DecodeCredentials(r.Credentials)
	details := append(apperrors.DetailsOf(serr), apperrors.DetailsOf(cerr)...)
	if len(details) > 0 {
		return settings, creds, apperrors.Validation(details...)
	}
	return settings, creds, nil
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
	settings, creds, err := req.decode()
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

// Update is PUT /providers/:id (step-up). Settings replace the stored
// ones; omitted or empty credentials keep the stored secrets. The type is
// fixed: a different one is refused.
func (h *ProviderHandler) Update(c *gin.Context) {
	var req providerRequest
	if !bind(c, &req) {
		return
	}
	patch := appprovider.Patch{Name: req.Name, Priority: req.Priority, Weight: req.Weight, DailyLimit: req.DailyLimit, Active: req.IsActive}
	settings, creds, err := req.decode()
	if err != nil {
		response.FromError(c, err)
		return
	}
	if req.Settings != nil {
		patch.Settings = &settings
	}
	if req.Credentials != nil {
		patch.Credentials = &creds
	}
	if req.Type != nil {
		patch.Kind = domain.Kind(*req.Type)
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

// Schema is GET /providers/schema: each type's form fields, groups and
// presets, and the scheduling fields' explanations.
func (h *ProviderHandler) Schema(c *gin.Context) {
	response.OK(c, h.svc.Schema())
}

// TestConnection is POST /providers/:id/test-connection: it reaches the
// stored provider and checks its credentials without sending mail. A
// failed test is still 200, with ok false.
func (h *ProviderHandler) TestConnection(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	d, err := h.svc.TestConnection(c.Request.Context(), p.TenantID, c.Param("id"), p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, d)
}

type draftTestRequest struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Settings    map[string]any `json:"settings"`
	Credentials map[string]any `json:"credentials"`
}

// TestDraft is POST /providers/test-connection (step-up): it tests a form's
// unsaved values; with id, the stored secrets fill the blank ones.
func (h *ProviderHandler) TestDraft(c *gin.Context) {
	var req draftTestRequest
	if !bind(c, &req) {
		return
	}
	settings, creds, err := providerRequest{Settings: req.Settings, Credentials: req.Credentials}.decode()
	if err != nil {
		response.FromError(c, err)
		return
	}
	p := middleware.PrincipalFrom(c)
	d, err := h.svc.TestDraft(c.Request.Context(), p.TenantID, appprovider.Draft{ID: req.ID, Kind: domain.Kind(req.Type),
		Settings: settings, Credentials: creds}, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, d)
}

type sendTestRequest struct {
	ToEmail string `json:"to_email"`
}

// SendTest is POST /providers/:id/send-test: it sends the fixed test
// message to to_email through this provider and records it as a test
// message.
func (h *ProviderHandler) SendTest(c *gin.Context) {
	var req sendTestRequest
	if !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	d, err := h.svc.SendTest(c.Request.Context(), p.TenantID, c.Param("id"), req.ToEmail, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, d)
}
