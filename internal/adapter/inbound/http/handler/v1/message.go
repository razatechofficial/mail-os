package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/internal/adapter/inbound/http/dto"
	"github.com/razatechofficial/mail-os/internal/core/message"
	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/pkg/httputil"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type MessageHandler struct {
	svc message.Service
}

func NewMessageHandler(svc message.Service) *MessageHandler {
	return &MessageHandler{svc: svc}
}

func (h *MessageHandler) Send(c *gin.Context) {
	var req dto.SendEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	out, err := h.svc.Send(c.Request.Context(), dto.SendEmailReqToInput(req, orgID))
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.Created(c, dto.SendEmailResponse{MessageID: out.MessageID, Status: out.Status})
}

func (h *MessageHandler) BatchSend(c *gin.Context) {
	var req dto.BatchSendEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httputil.FromError(c, err)
		return
	}
	orgID := httputil.OrgIDFromContext(c)
	inputs := make([]message.SendEmailInput, len(req.Messages))
	for i, r := range req.Messages {
		inputs[i] = dto.SendEmailReqToInput(r, orgID)
	}
	out, err := h.svc.BatchSend(c.Request.Context(), message.BatchSendInput{OrgID: orgID, Messages: inputs})
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	results := make([]dto.SendEmailResponse, len(out.Results))
	for i, r := range out.Results {
		results[i] = dto.SendEmailResponse{MessageID: r.MessageID, Status: r.Status}
	}
	httputil.Created(c, dto.BatchSendEmailResponse{
		Results:      results,
		SuccessCount: out.SuccessCount,
		FailCount:    out.FailCount,
	})
}

func (h *MessageHandler) GetByID(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.MessageID(c.Param("id"))
	msg, err := h.svc.GetByID(c.Request.Context(), orgID, id)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, dto.MessageToResponse(msg))
}

func (h *MessageHandler) List(c *gin.Context) {
	orgID := httputil.OrgIDFromContext(c)
	params := httputil.PaginationFromContext(c)
	listParams := message.MessageListParams{
		OrgID:  orgID,
		Status: c.Query("status"),
		Type:   c.Query("type"),
	}
	listParams.Params = params
	msgs, total, err := h.svc.List(c.Request.Context(), listParams)
	if err != nil {
		httputil.FromError(c, err)
		return
	}
	items := make([]dto.MessageResponse, len(msgs))
	for i, m := range msgs {
		items[i] = dto.MessageToResponse(m)
	}
	meta := pagination.NewMeta(params, total)
	httputil.List(c, items, meta)
}

func (h *MessageHandler) Cancel(c *gin.Context) {
	orgID := domain.OrganizationID(httputil.OrgIDFromContext(c))
	id := domain.MessageID(c.Param("id"))
	if err := h.svc.Cancel(c.Request.Context(), orgID, id); err != nil {
		httputil.FromError(c, err)
		return
	}
	httputil.OK(c, gin.H{"status": "cancelled"})
}
