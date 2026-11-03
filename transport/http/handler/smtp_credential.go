package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/smtpcred"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/domain/smtpcredential"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// SMTPEndpoint is where applications submit over SMTP, shown with their
// credentials so an administrator can configure the legacy software.
type SMTPEndpoint struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	// Port takes STARTTLS (587); ImplicitTLSPort, when not 0, implicit TLS (465).
	Port            int  `json:"port"`
	ImplicitTLSPort int  `json:"implicit_tls_port"`
	PasswordAuth    bool `json:"password_auth"`
}

// SMTPCredentialHandler serves an application's SMTP credentials: every
// MailOS role lists them (never a password or hash); mailos_admin creates,
// rotates and revokes them, with step-up. A password is in the response
// that creates or rotates it, and nowhere else.
type SMTPCredentialHandler struct {
	svc      *smtpcred.Service
	endpoint SMTPEndpoint
}

// NewSMTPCredentialHandler builds the handler.
func NewSMTPCredentialHandler(svc *smtpcred.Service, endpoint SMTPEndpoint) *SMTPCredentialHandler {
	return &SMTPCredentialHandler{svc: svc, endpoint: endpoint}
}

// Mount registers the routes.
func (h *SMTPCredentialHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.GET("/applications/:id/smtp-credentials", g.Require(access.PermApplicationsRead), h.List)
	api.POST("/applications/:id/smtp-credentials", g.Require(access.PermApplicationsManage), h.Create)
	api.POST("/applications/:id/smtp-credentials/:credential_id/rotate", g.Require(access.PermApplicationsManage), h.Rotate)
	api.DELETE("/applications/:id/smtp-credentials/:credential_id", g.Require(access.PermApplicationsManage), h.Revoke)
}

type smtpCredentialView struct {
	ID            string     `json:"id"`
	ApplicationID string     `json:"application_id"`
	Username      string     `json:"username"`
	Description   string     `json:"description"`
	Active        bool       `json:"active"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	RotatedAt     *time.Time `json:"rotated_at"`
	RotatedBy     string     `json:"rotated_by"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	LastUsedIP    string     `json:"last_used_ip"`
	RevokedAt     *time.Time `json:"revoked_at"`
	RevokedBy     string     `json:"revoked_by"`
}

func smtpCredentialViewOf(c smtpcredential.Credential) smtpCredentialView {
	return smtpCredentialView{ID: c.ID, ApplicationID: c.ApplicationID, Username: c.Username, Description: c.Description,
		Active: c.Active(), CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt, RotatedAt: c.RotatedAt, RotatedBy: c.RotatedBy,
		LastUsedAt: c.LastUsedAt, LastUsedIP: c.LastUsedIP, RevokedAt: c.RevokedAt, RevokedBy: c.RevokedBy}
}

// smtpCredentialSecret is a credential with its password, once.
type smtpCredentialSecret struct {
	smtpCredentialView
	Password string       `json:"password"`
	SMTP     SMTPEndpoint `json:"smtp"`
}

// List is GET /applications/:id/smtp-credentials: the credentials, newest
// first, revoked ones included, and the SMTP endpoint.
func (h *SMTPCredentialHandler) List(c *gin.Context) {
	list, err := h.svc.List(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]smtpCredentialView, len(list))
	for i, cred := range list {
		out[i] = smtpCredentialViewOf(cred)
	}
	response.OK(c, gin.H{"credentials": out, "smtp": h.endpoint})
}

// Create is POST /applications/:id/smtp-credentials {description}
// (step-up): a generated username and password for an application opted
// in to SMTP credentials; at most two are active.
func (h *SMTPCredentialHandler) Create(c *gin.Context) {
	var req struct {
		Description string `json:"description"`
	}
	if c.Request.ContentLength != 0 && !bind(c, &req) {
		return
	}
	p := middleware.PrincipalFrom(c)
	cred, password, err := h.svc.Create(c.Request.Context(), p.TenantID, c.Param("id"), req.Description, p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.Created(c, smtpCredentialSecret{smtpCredentialView: smtpCredentialViewOf(cred), Password: password, SMTP: h.endpoint})
}

// Rotate is POST /applications/:id/smtp-credentials/:credential_id/rotate
// (step-up): a new password for the same username, effective at once.
func (h *SMTPCredentialHandler) Rotate(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	cred, password, err := h.svc.Rotate(c.Request.Context(), p.TenantID, c.Param("id"), c.Param("credential_id"), p.Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.OK(c, smtpCredentialSecret{smtpCredentialView: smtpCredentialViewOf(cred), Password: password, SMTP: h.endpoint})
}

// Revoke is DELETE /applications/:id/smtp-credentials/:credential_id
// (step-up): the credential stops at once, open sessions included.
func (h *SMTPCredentialHandler) Revoke(c *gin.Context) {
	p := middleware.PrincipalFrom(c)
	if err := h.svc.Revoke(c.Request.Context(), p.TenantID, c.Param("id"), c.Param("credential_id"), p.Actor()); err != nil {
		response.FromError(c, err)
		return
	}
	response.NoContent(c)
}
