package handler

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/gin-gonic/gin"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/template"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// TemplateHandler serves the template designer API
// (docs/mailos-template-api.md): templates, topics, drafts, publishing,
// versions, preview, test sends and branding.
type TemplateHandler struct {
	svc     *apptemplate.Service
	limiter middleware.WindowCounter
	limits  TemplateLimits
}

// TemplateLimits are the per-user limits on the costly endpoints; 0 turns
// one off.
type TemplateLimits struct {
	PreviewPerMinute int
	TestSendPerHour  int
}

// NewTemplateHandler builds the handler.
func NewTemplateHandler(svc *apptemplate.Service, limiter middleware.WindowCounter, limits TemplateLimits) *TemplateHandler {
	return &TemplateHandler{svc: svc, limiter: limiter, limits: limits}
}

// Mount registers the routes with the roles of the API's table: reads for
// every role, edits for editors and admins, publishing (step-up) for
// publishers and admins, delete and branding for admins.
func (h *TemplateHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	read, edit := g.Require(access.PermTemplatesRead), g.Require(access.PermTemplatesEdit)
	api.GET("/templates", read, h.List)
	api.POST("/templates", edit, h.Create)
	api.GET("/templates/:id", read, h.Get)
	api.PUT("/templates/:id", edit, h.Update)
	api.DELETE("/templates/:id", g.Require(access.PermTemplatesDelete), h.Delete)
	api.GET("/template-topics", read, h.Topics)

	api.GET("/templates/:id/draft", read, h.GetDraft)
	api.PUT("/templates/:id/draft", edit, h.SaveDraft)
	api.POST("/templates/:id/publish", g.Require(access.PermTemplatesPublish), h.Publish)
	api.GET("/templates/:id/versions", read, h.Versions)
	api.GET("/templates/:id/active-version", read, h.ActiveVersion)
	api.POST("/templates/:id/versions/:version/restore", edit, h.Restore)
	api.POST("/templates/:id/preview", edit,
		middleware.RateLimit(h.limiter, "template_preview", middleware.PerUser, h.limits.PreviewPerMinute, time.Minute), h.Preview)
	api.POST("/templates/:id/test-send", edit,
		middleware.RateLimit(h.limiter, "template_test_send", middleware.PerUser, h.limits.TestSendPerHour, time.Hour), h.TestSend)

	api.GET("/template-branding", read, h.GetBranding)
	api.PUT("/template-branding", g.Require(access.PermBrandingEdit), h.UpdateBranding)
}

// editor is the caller as a content editor.
func editor(c *gin.Context) apptemplate.Editor {
	p := middleware.PrincipalFrom(c)
	return apptemplate.Editor{ID: p.Actor(), Admin: slices.Contains(p.Roles, access.RoleAdmin)}
}

func tenantOf(c *gin.Context) string { return middleware.PrincipalFrom(c).TenantID }

// ── templates ─────────────────────────────────────────────────────────────

type templateView struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	Name          string    `json:"name"`
	Slug          string    `json:"slug"`
	Category      string    `json:"category"`
	Description   string    `json:"description"`
	Topic         string    `json:"topic"`
	DefaultLocale string    `json:"default_locale"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func newTemplateView(t domain.Template) templateView {
	return templateView{ID: t.ID, OrgID: t.OrgID, Name: t.Name, Slug: t.Slug, Category: string(t.Category),
		Description: t.Description, Topic: t.Topic, DefaultLocale: string(t.DefaultLocale), IsActive: t.IsActive,
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt}
}

// List is GET /templates.
func (h *TemplateHandler) List(c *gin.Context) {
	pg := page(c)
	list, total, err := h.svc.List(c.Request.Context(), tenantOf(c), pg.Limit, pg.Offset)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]templateView, len(list))
	for i, t := range list {
		out[i] = newTemplateView(t)
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

type createTemplateInput struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	Description   string `json:"description"`
	Category      string `json:"category"`
	Topic         string `json:"topic"`
	DefaultLocale string `json:"default_locale"`
}

// Create is POST /templates.
func (h *TemplateHandler) Create(c *gin.Context) {
	var in createTemplateInput
	if !bind(c, &in) {
		return
	}
	t, err := h.svc.Create(c.Request.Context(), tenantOf(c), apptemplate.CreateInput{Name: in.Name, Slug: in.Slug,
		Description: in.Description, Category: domain.Category(in.Category), Topic: in.Topic, DefaultLocale: domain.Locale(in.DefaultLocale)})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, newTemplateView(t))
}

// Get is GET /templates/:id.
func (h *TemplateHandler) Get(c *gin.Context) {
	t, err := h.svc.Get(c.Request.Context(), tenantOf(c), c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, newTemplateView(t))
}

type updateTemplateInput struct {
	Name          *string `json:"name"`
	Slug          *string `json:"slug"`
	Description   *string `json:"description"`
	Category      *string `json:"category"`
	Topic         *string `json:"topic"`
	DefaultLocale *string `json:"default_locale"`
	IsActive      *bool   `json:"is_active"`
}

// Update is PUT /templates/:id: the fields given change.
func (h *TemplateHandler) Update(c *gin.Context) {
	var in updateTemplateInput
	if !bind(c, &in) {
		return
	}
	up := apptemplate.UpdateInput{Name: in.Name, Slug: in.Slug, Description: in.Description, Topic: in.Topic, IsActive: in.IsActive}
	if in.Category != nil {
		cat := domain.Category(*in.Category)
		up.Category = &cat
	}
	if in.DefaultLocale != nil {
		l := domain.Locale(*in.DefaultLocale)
		up.DefaultLocale = &l
	}
	t, err := h.svc.Update(c.Request.Context(), tenantOf(c), c.Param("id"), up)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, newTemplateView(t))
}

// Delete is DELETE /templates/:id (mailos_admin).
func (h *TemplateHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), tenantOf(c), c.Param("id")); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}

// Topics is GET /template-topics: the static catalogue.
func (h *TemplateHandler) Topics(c *gin.Context) {
	response.OK(c, h.svc.Topics())
}

// ── branding ──────────────────────────────────────────────────────────────

type brandingView struct {
	CompanyName            string     `json:"company_name"`
	LogoURL                string     `json:"logo_url"`
	LogoAlt                string     `json:"logo_alt"`
	PrimaryColor           string     `json:"primary_color"`
	BackgroundColor        string     `json:"background_color"`
	ContentBackgroundColor string     `json:"content_background_color"`
	TextColor              string     `json:"text_color"`
	LinkColor              string     `json:"link_color"`
	FontFamily             string     `json:"font_family"`
	CompanyAddress         string     `json:"company_address"`
	FooterText             string     `json:"footer_text"`
	UpdatedAt              *time.Time `json:"updated_at"`
}

func newBrandingView(b domain.Branding) brandingView {
	v := brandingView{CompanyName: b.CompanyName, LogoURL: b.LogoURL, LogoAlt: b.LogoAlt, PrimaryColor: b.PrimaryColor,
		BackgroundColor: b.BackgroundColor, ContentBackgroundColor: b.ContentBackgroundColor, TextColor: b.TextColor,
		LinkColor: b.LinkColor, FontFamily: b.FontFamily, CompanyAddress: b.CompanyAddress, FooterText: b.FooterText}
	if !b.UpdatedAt.IsZero() {
		v.UpdatedAt = &b.UpdatedAt
	}
	return v
}

// GetBranding is GET /template-branding: the defaults when none is saved.
func (h *TemplateHandler) GetBranding(c *gin.Context) {
	b, err := h.svc.Branding(c.Request.Context(), tenantOf(c))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, newBrandingView(b))
}

// UpdateBranding is PUT /template-branding (mailos_admin).
func (h *TemplateHandler) UpdateBranding(c *gin.Context) {
	var in brandingView
	if !bind(c, &in) {
		return
	}
	b, err := h.svc.UpdateBranding(c.Request.Context(), tenantOf(c), domain.Branding{CompanyName: in.CompanyName,
		LogoURL: in.LogoURL, LogoAlt: in.LogoAlt, PrimaryColor: in.PrimaryColor, BackgroundColor: in.BackgroundColor,
		ContentBackgroundColor: in.ContentBackgroundColor, TextColor: in.TextColor, LinkColor: in.LinkColor,
		FontFamily: in.FontFamily, CompanyAddress: in.CompanyAddress, FooterText: in.FooterText}, middleware.PrincipalFrom(c).Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, newBrandingView(b))
}

// rawJSON is a design as the API writes it: the stored JSON, or null.
func rawJSON(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(b)
}
