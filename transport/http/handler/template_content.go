package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	apptemplate "github.com/razatechofficial/mail-os/application/template"
	domain "github.com/razatechofficial/mail-os/domain/template"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/response"
)

type draftView struct {
	TemplateID string          `json:"template_id"`
	Locale     string          `json:"locale"`
	Subject    string          `json:"subject"`
	Preheader  string          `json:"preheader"`
	Design     json.RawMessage `json:"design"`
	HTMLBody   string          `json:"html_body"`
	TextBody   string          `json:"text_body"`
	Variables  []string        `json:"variables"`
	Revision   int             `json:"revision"`
	UpdatedBy  string          `json:"updated_by"`
	UpdatedAt  *time.Time      `json:"updated_at"`
}

func newDraftView(d domain.Draft) draftView {
	v := draftView{TemplateID: d.TemplateID, Locale: string(d.Locale), Subject: d.Subject, Preheader: d.Preheader,
		Design: rawJSON(d.Design), HTMLBody: d.HTMLBody, TextBody: d.TextBody, Variables: d.Variables, Revision: d.Revision,
		UpdatedBy: d.UpdatedBy}
	if v.Variables == nil {
		v.Variables = []string{}
	}
	if !d.UpdatedAt.IsZero() {
		v.UpdatedAt = &d.UpdatedAt
	}
	return v
}

type versionView struct {
	ID          string          `json:"id"`
	TemplateID  string          `json:"template_id"`
	Version     int             `json:"version"`
	Locale      string          `json:"locale"`
	Subject     string          `json:"subject"`
	Preheader   string          `json:"preheader"`
	Design      json.RawMessage `json:"design"`
	HTMLBody    string          `json:"html_body"`
	TextBody    string          `json:"text_body"`
	Variables   []string        `json:"variables"`
	Status      string          `json:"status"`
	IsActive    bool            `json:"is_active"`
	PublishedBy string          `json:"published_by"`
	PublishedAt time.Time       `json:"published_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

func newVersionView(v domain.Version) versionView {
	out := versionView{ID: v.ID, TemplateID: v.TemplateID, Version: v.Number, Locale: string(v.Locale), Subject: v.Subject,
		Preheader: v.Preheader, Design: rawJSON(v.Design), HTMLBody: v.HTMLBody, TextBody: v.TextBody, Variables: v.Variables,
		Status: string(v.Status), IsActive: v.IsActive, PublishedBy: v.PublishedBy, PublishedAt: v.PublishedAt, CreatedAt: v.CreatedAt}
	if out.Variables == nil {
		out.Variables = []string{}
	}
	return out
}

// GetDraft is GET /templates/:id/draft?locale=en.
func (h *TemplateHandler) GetDraft(c *gin.Context) {
	d, err := h.svc.Draft(c.Request.Context(), tenantOf(c), c.Param("id"), c.Query("locale"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, newDraftView(d))
}

type draftInput struct {
	Locale    string          `json:"locale"`
	Revision  int             `json:"revision"`
	Subject   string          `json:"subject"`
	Preheader string          `json:"preheader"`
	Design    json.RawMessage `json:"design"`
	HTMLBody  string          `json:"html_body"`
	TextBody  string          `json:"text_body"`
	Variables []string        `json:"variables"`
}

// SaveDraft is PUT /templates/:id/draft. Variables the topic does not
// declare come back as warnings in meta.warnings.
func (h *TemplateHandler) SaveDraft(c *gin.Context) {
	var in draftInput
	if !bind(c, &in) {
		return
	}
	d, warnings, err := h.svc.SaveDraft(c.Request.Context(), tenantOf(c), c.Param("id"), apptemplate.DraftInput{
		Locale: in.Locale, Revision: in.Revision, Subject: in.Subject, Preheader: in.Preheader, Design: in.Design,
		HTMLBody: in.HTMLBody, TextBody: in.TextBody, Variables: in.Variables}, editor(c))
	if err != nil {
		response.FromError(c, err)
		return
	}
	if warnings == nil {
		warnings = []apperrors.FieldError{}
	}
	c.JSON(http.StatusOK, response.Response{Success: true, Data: newDraftView(d), Meta: gin.H{"warnings": warnings}})
}

type revisionInput struct {
	Locale   string `json:"locale"`
	Revision int    `json:"revision"`
}

// Publish is POST /templates/:id/publish (step-up; four-eyes when the
// tenant requires it).
func (h *TemplateHandler) Publish(c *gin.Context) {
	var in revisionInput
	if !bind(c, &in) {
		return
	}
	v, err := h.svc.Publish(c.Request.Context(), tenantOf(c), c.Param("id"), in.Locale, in.Revision, middleware.PrincipalFrom(c).Actor())
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Created(c, newVersionView(v))
}

// Versions is GET /templates/:id/versions?locale=en, newest first.
func (h *TemplateHandler) Versions(c *gin.Context) {
	list, err := h.svc.Versions(c.Request.Context(), tenantOf(c), c.Param("id"), c.Query("locale"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	out := make([]versionView, len(list))
	for i, v := range list {
		out[i] = newVersionView(v)
	}
	response.OK(c, out)
}

// ActiveVersion is GET /templates/:id/active-version?locale=en.
func (h *TemplateHandler) ActiveVersion(c *gin.Context) {
	v, err := h.svc.ActiveVersion(c.Request.Context(), tenantOf(c), c.Param("id"), c.Query("locale"))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, newVersionView(v))
}

// Restore is POST /templates/:id/versions/:version/restore.
func (h *TemplateHandler) Restore(c *gin.Context) {
	number, err := strconv.Atoi(c.Param("version"))
	if err != nil || number < 1 {
		response.FromError(c, apperrors.NotFound("template version not found"))
		return
	}
	var in revisionInput
	if !bind(c, &in) {
		return
	}
	d, err := h.svc.Restore(c.Request.Context(), tenantOf(c), c.Param("id"), number, in.Locale, in.Revision, editor(c))
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, newDraftView(d))
}

type previewInput struct {
	Locale   string         `json:"locale"`
	Subject  string         `json:"subject"`
	HTMLBody string         `json:"html_body"`
	TextBody string         `json:"text_body"`
	Data     map[string]any `json:"data"`
}

type previewView struct {
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text"`
}

// Preview is POST /templates/:id/preview (rate limited per user).
func (h *TemplateHandler) Preview(c *gin.Context) {
	var in previewInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.Preview(c.Request.Context(), tenantOf(c), c.Param("id"), apptemplate.PreviewInput{
		Locale: in.Locale, Subject: in.Subject, HTMLBody: in.HTMLBody, TextBody: in.TextBody, Data: in.Data})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, previewView{Subject: out.Subject, HTML: out.HTML, Text: out.Text})
}

type testSendInput struct {
	Locale    string         `json:"locale"`
	ToEmail   string         `json:"to_email"`
	FromName  string         `json:"from_name"`
	FromEmail string         `json:"from_email"`
	Data      map[string]any `json:"data"`
}

// TestSend is POST /templates/:id/test-send (rate limited per user): 202
// with the queued message.
func (h *TemplateHandler) TestSend(c *gin.Context) {
	var in testSendInput
	if !bind(c, &in) {
		return
	}
	id, status, err := h.svc.TestSend(c.Request.Context(), tenantOf(c), c.Param("id"), apptemplate.TestSendInput{
		Locale: in.Locale, ToEmail: in.ToEmail, FromName: in.FromName, FromEmail: in.FromEmail, Data: in.Data})
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.Accepted(c, gin.H{"message_id": id, "status": status})
}
