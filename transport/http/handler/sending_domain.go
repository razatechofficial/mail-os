package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	appdomain "github.com/razatechofficial/mail-os/application/sendingdomain"
	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/sendingdomain"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// SendingDomainHandler serves sending domains: the DNS records to publish
// and their verification. The DKIM private key never leaves the server.
// Create, verify and delete need step-up.
type SendingDomainHandler struct {
	svc *appdomain.Service
}

// NewSendingDomainHandler builds the handler.
func NewSendingDomainHandler(svc *appdomain.Service) *SendingDomainHandler {
	return &SendingDomainHandler{svc: svc}
}

// Mount registers the routes.
func (h *SendingDomainHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/sending-domains", g.Require(access.PermDomainsRead), h.List)
	api.GET("/sending-domains/:id", g.Require(access.PermDomainsRead), h.Get)
	api.POST("/sending-domains", g.Require(access.PermDomainsManage), h.Create)
	api.POST("/sending-domains/:id/verify", g.Require(access.PermDomainsManage), h.Verify)
	api.DELETE("/sending-domains/:id", g.Require(access.PermDomainsManage), h.Delete)
}

type domainView struct {
	ID            string          `json:"id"`
	Domain        string          `json:"domain"`
	Status        string          `json:"status"`
	DKIMSelector  string          `json:"dkim_selector"`
	DKIMPublicKey string          `json:"dkim_public_key"`
	SPFRecord     string          `json:"spf_record"`
	DMARCRecord   string          `json:"dmarc_record"`
	Records       []domain.Record `json:"records"`
	FailureReason string          `json:"failure_reason,omitempty"`
	LastCheckedAt *time.Time      `json:"last_checked_at,omitempty"`
	VerifiedAt    *time.Time      `json:"verified_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func domainViewOf(d domain.Domain) domainView {
	return domainView{ID: d.ID, Domain: d.Name, Status: string(d.Status), DKIMSelector: d.DKIMSelector, DKIMPublicKey: d.DKIMPublicKey,
		SPFRecord: d.SPFRecord, DMARCRecord: d.DMARCRecord, Records: d.Records(), FailureReason: d.FailureReason,
		LastCheckedAt: d.LastCheckedAt, VerifiedAt: d.VerifiedAt, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt}
}

// List is GET /sending-domains.
func (h *SendingDomainHandler) List(c *gin.Context) {
	pg := page(c)
	list, total, err := h.svc.List(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, pg.Limit, pg.Offset)
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]domainView, len(list))
	for i, d := range list {
		out[i] = domainViewOf(d)
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Get is GET /sending-domains/:id.
func (h *SendingDomainHandler) Get(c *gin.Context) {
	d, err := h.svc.Get(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, domainViewOf(d))
}

// Create is POST /sending-domains (step-up).
func (h *SendingDomainHandler) Create(c *gin.Context) {
	var req struct {
		Domain        string `json:"domain"`
		DKIMSelector  string `json:"dkim_selector"`
		DMARCReportTo string `json:"dmarc_report_to"`
	}
	if !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	d, err := h.svc.Create(c.Request.Context(), p.TenantID, appdomain.Input{Name: req.Domain, Selector: req.DKIMSelector,
		DMARCReportTo: req.DMARCReportTo}, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, domainViewOf(d))
}

// Verify is POST /sending-domains/:id/verify (step-up).
func (h *SendingDomainHandler) Verify(c *gin.Context) {
	d, err := h.svc.Verify(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, domainViewOf(d))
}

// Delete is DELETE /sending-domains/:id (step-up).
func (h *SendingDomainHandler) Delete(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	if err := h.svc.Delete(c.Request.Context(), p.TenantID, c.Param("id"), p.Actor()); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
