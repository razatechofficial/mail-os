package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

// MessageHandler serves sends and the message log. Lists and gets never
// carry bodies; GET /messages/:id/body is its own permission (step-up) and
// is audited.
type MessageHandler struct {
	svc *appmsg.Service
}

// NewMessageHandler builds the handler.
func NewMessageHandler(svc *appmsg.Service) *MessageHandler { return &MessageHandler{svc: svc} }

// Mount registers the routes.
func (h *MessageHandler) Mount(api *gin.RouterGroup, g middleware.Guard) {
	api.POST("/messages/send", g.Require(access.PermMessagesOperate), h.Send)
	api.POST("/messages/batch", g.Require(access.PermMessagesOperate), h.Batch)
	api.GET("/messages", g.Require(access.PermMessagesRead), h.List)
	api.GET("/messages/:id", g.Require(access.PermMessagesRead), h.Get)
	api.GET("/messages/:id/body", g.Require(access.PermMessageBodies), h.Body)
	api.POST("/messages/:id/cancel", g.Require(access.PermMessagesOperate), h.Cancel)
	api.POST("/messages/:id/resend", g.Require(access.PermMessagesOperate), h.Resend)
}

type sendRequest struct {
	FromName       string         `json:"from_name"`
	FromEmail      string         `json:"from_email"`
	ToEmail        string         `json:"to_email"`
	ToName         string         `json:"to_name"`
	ReplyTo        string         `json:"reply_to"`
	Subject        string         `json:"subject"`
	HTMLBody       string         `json:"html_body"`
	TextBody       string         `json:"text_body"`
	TemplateSlug   string         `json:"template_slug"`
	TemplateID     string         `json:"template_id"`
	TemplateLocale string         `json:"template_locale"`
	TemplateVars   map[string]any `json:"template_vars"`
	Tags           []string       `json:"tags"`
	Metadata       map[string]any `json:"metadata"`
	Priority       int            `json:"priority"`
	IdempotencyKey string         `json:"idempotency_key"`
	ScheduleAt     *time.Time     `json:"schedule_at"`
	Type           string         `json:"type"`
}

func (r sendRequest) input(tenantID string) appmsg.SendInput {
	return appmsg.SendInput{TenantID: tenantID, FromName: r.FromName, FromEmail: r.FromEmail, ToEmail: r.ToEmail, ToName: r.ToName,
		ReplyTo: r.ReplyTo, Subject: r.Subject, HTML: r.HTMLBody, Text: r.TextBody, TemplateSlug: r.TemplateSlug,
		TemplateID: r.TemplateID, Locale: r.TemplateLocale, TemplateData: r.TemplateVars, Tags: r.Tags, Metadata: r.Metadata,
		Priority: r.Priority, IdempotencyKey: r.IdempotencyKey, ScheduleAt: r.ScheduleAt, Type: domainmsg.Type(r.Type)}
}

// Send is POST /messages/send. The Idempotency-Key header stands in for
// idempotency_key.
func (h *MessageHandler) Send(c *gin.Context) {
	var req sendRequest
	if !bind(c, &req) {
		return
	}
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = c.GetHeader("Idempotency-Key")
	}
	r, err := h.svc.Send(c.Request.Context(), req.input(middleware.PrincipalFrom(c).TenantID))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, r)
}

// Batch is POST /messages/batch.
func (h *MessageHandler) Batch(c *gin.Context) {
	var req struct {
		Messages []sendRequest `json:"messages"`
	}
	if !bind(c, &req) {
		return
	}
	tenantID := middleware.PrincipalFrom(c).TenantID
	in := make([]appmsg.SendInput, len(req.Messages))
	for i, m := range req.Messages {
		in[i] = m.input(tenantID)
	}
	r, err := h.svc.Batch(c.Request.Context(), tenantID, in)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, r)
}

// messageView is the console's Message with the delivery fields. The
// subject and template data have secret values masked; no body.
type messageView struct {
	ID                string         `json:"id"`
	CampaignID        string         `json:"campaign_id,omitempty"`
	FromName          string         `json:"from_name"`
	FromEmail         string         `json:"from_email"`
	ToEmail           string         `json:"to_email"`
	ToName            string         `json:"to_name"`
	ReplyTo           string         `json:"reply_to,omitempty"`
	Subject           string         `json:"subject"`
	Type              string         `json:"type"`
	Status            string         `json:"status"`
	Priority          int            `json:"priority"`
	Tags              []string       `json:"tags"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	Topic             string         `json:"topic,omitempty"`
	TemplateID        string         `json:"template_id,omitempty"`
	TemplateVersionID string         `json:"template_version_id,omitempty"`
	Locale            string         `json:"locale,omitempty"`
	TemplateData      map[string]any `json:"template_data,omitempty"`
	EventID           string         `json:"event_id,omitempty"`
	ActorType         string         `json:"actor_type,omitempty"`
	ActorID           string         `json:"actor_id,omitempty"`
	ProviderID        string         `json:"provider_id,omitempty"`
	ProviderMessageID string         `json:"provider_message_id,omitempty"`
	Attempts          int            `json:"attempts"`
	LastError         string         `json:"last_error,omitempty"`
	HasBody           bool           `json:"has_body"`
	ScheduledAt       *time.Time     `json:"scheduled_at,omitempty"`
	SentAt            *time.Time     `json:"sent_at,omitempty"`
	DeliveredAt       *time.Time     `json:"delivered_at,omitempty"`
	BouncedAt         *time.Time     `json:"bounced_at,omitempty"`
	FailedAt          *time.Time     `json:"failed_at,omitempty"`
	CancelledAt       *time.Time     `json:"cancelled_at,omitempty"`
	BodyPurgedAt      *time.Time     `json:"body_purged_at,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

func messageViewOf(v appmsg.View) messageView {
	m := v.Message
	tags := m.Tags
	if tags == nil {
		tags = []string{}
	}
	return messageView{ID: m.ID, CampaignID: m.CampaignID, FromName: m.FromName, FromEmail: m.FromEmail, ToEmail: m.ToEmail,
		ToName: m.ToName, ReplyTo: m.ReplyTo, Subject: v.MaskedSubject, Type: string(m.Type), Status: string(m.Status),
		Priority: int(m.Priority), Tags: tags, Metadata: m.Metadata, Topic: m.Topic, TemplateID: m.TemplateID,
		TemplateVersionID: m.TemplateVersionID, Locale: m.Locale, TemplateData: v.MaskedTemplateData, EventID: m.EventID,
		ActorType: string(m.Actor.Type), ActorID: m.Actor.ID, ProviderID: m.ProviderID, ProviderMessageID: m.ProviderMessageID,
		Attempts: m.Attempts, LastError: m.LastError, HasBody: m.BodyPurgedAt == nil && (m.HTMLBody != "" || m.TextBody != ""),
		ScheduledAt: m.ScheduledAt, SentAt: m.SentAt, DeliveredAt: m.DeliveredAt, BouncedAt: m.BouncedAt, FailedAt: m.FailedAt,
		CancelledAt: m.CancelledAt, BodyPurgedAt: m.BodyPurgedAt, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}

// List is GET /messages?status&type&topic&to&from&until.
func (h *MessageHandler) List(c *gin.Context) {
	from, err := timeQuery(c, "from")
	if err != nil {
		response.FromError(c, err)
		return
	}
	until, err := timeQuery(c, "until")
	if err != nil {
		response.FromError(c, err)
		return
	}
	pg := page(c)
	list, total, err := h.svc.List(c.Request.Context(), appmsg.Filter{TenantID: middleware.PrincipalFrom(c).TenantID,
		Status: c.Query("status"), Type: c.Query("type"), Topic: c.Query("topic"), To: c.Query("to"), From: from, Until: until,
		Limit: pg.Limit, Offset: pg.Offset})
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]messageView, len(list))
	for i, v := range list {
		out[i] = messageViewOf(v)
	}
	response.List(c, out, pagination.NewMeta(pg, total))
}

// Get is GET /messages/:id.
func (h *MessageHandler) Get(c *gin.Context) {
	v, err := h.svc.Get(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, messageViewOf(v))
}

// Body is GET /messages/:id/body (step-up, audited; 404 once purged).
func (h *MessageHandler) Body(c *gin.Context) {
	b, err := h.svc.Body(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.OK(c, b)
}

// Cancel is POST /messages/:id/cancel.
func (h *MessageHandler) Cancel(c *gin.Context) {
	m, err := h.svc.Cancel(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, gin.H{"message_id": m.ID, "status": string(m.Status)})
}

// Resend is POST /messages/:id/resend: a new message with the same
// content.
func (h *MessageHandler) Resend(c *gin.Context) {
	m, err := h.svc.Resend(c.Request.Context(), middleware.PrincipalFrom(c).TenantID, c.Param("id"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, appmsg.Result{MessageID: m.ID, Status: string(m.Status)})
}
