package handler

import (
	"context"
	"time"

	"github.com/razatechofficial/mail-os/api/proto/v1"
	"github.com/razatechofficial/mail-os/internal/core/message"
	"github.com/razatechofficial/mail-os/internal/domain"
	grpcinterceptor "github.com/razatechofficial/mail-os/internal/adapter/inbound/grpc/interceptor"
	"github.com/razatechofficial/mail-os/pkg/pagination"
)

type MailService struct {
	v1.UnimplementedMailServiceServer
	svc message.Service
}

func NewMailService(svc message.Service) *MailService {
	return &MailService{svc: svc}
}

func (h *MailService) SendEmail(ctx context.Context, req *v1.SendEmailRequest) (*v1.SendEmailResponse, error) {
	orgID := grpcinterceptor.OrgIDFromContext(ctx)
	if orgID == "" {
		return nil, nil // auth interceptor should have rejected
	}
	input := protoSendEmailToInput(req, orgID)
	out, err := h.svc.Send(ctx, input)
	if err != nil {
		return nil, err
	}
	return &v1.SendEmailResponse{MessageId: out.MessageID, Status: out.Status}, nil
}

func (h *MailService) BatchSend(ctx context.Context, req *v1.BatchSendRequest) (*v1.BatchSendResponse, error) {
	orgID := grpcinterceptor.OrgIDFromContext(ctx)
	if orgID == "" {
		return nil, nil
	}
	inputs := make([]message.SendEmailInput, len(req.Messages))
	for i, m := range req.Messages {
		inputs[i] = protoSendEmailToInput(m, orgID)
	}
	out, err := h.svc.BatchSend(ctx, message.BatchSendInput{OrgID: orgID, Messages: inputs})
	if err != nil {
		return nil, err
	}
	results := make([]*v1.SendEmailResponse, len(out.Results))
	for i, r := range out.Results {
		results[i] = &v1.SendEmailResponse{MessageId: r.MessageID, Status: r.Status}
	}
	return &v1.BatchSendResponse{
		Results:     results,
		SuccessCount: int32(out.SuccessCount),
		FailCount:   int32(out.FailCount),
	}, nil
}

func (h *MailService) GetMessage(ctx context.Context, req *v1.GetMessageRequest) (*v1.Message, error) {
	orgID := domain.OrganizationID(grpcinterceptor.OrgIDFromContext(ctx))
	if orgID == "" {
		return nil, nil
	}
	msg, err := h.svc.GetByID(ctx, orgID, domain.MessageID(req.Id))
	if err != nil {
		return nil, err
	}
	return messageToProto(msg), nil
}

func (h *MailService) ListMessages(ctx context.Context, req *v1.ListMessagesRequest) (*v1.ListMessagesResponse, error) {
	orgID := grpcinterceptor.OrgIDFromContext(ctx)
	if orgID == "" {
		return nil, nil
	}
	params := message.MessageListParams{
		OrgID:  orgID,
		Status: req.Status,
		Type:   req.Type,
		Params: pagination.Params{Page: 1, Limit: 20},
	}
	if req.Pagination != nil {
		params.Page = int(req.Pagination.GetPage())
		params.Limit = int(req.Pagination.GetLimit())
		if params.Limit < 1 {
			params.Limit = 20
		}
		params.SortBy = req.Pagination.GetSortBy()
		params.SortOrder = req.Pagination.GetSortOrder()
	}
	if params.Page < 1 {
		params.Page = 1
	}
	msgs, total, err := h.svc.List(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]*v1.Message, len(msgs))
	for i, m := range msgs {
		items[i] = messageToProto(m)
	}
	limit := params.Limit
	if limit < 1 {
		limit = 20
	}
	totalPages := (total + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}
	meta := &v1.PaginationMeta{
		Page:       int32(params.Page),
		Limit:      int32(limit),
		TotalItems: int32(total),
		TotalPages: int32(totalPages),
	}
	return &v1.ListMessagesResponse{Messages: items, Meta: meta}, nil
}

func protoSendEmailToInput(req *v1.SendEmailRequest, orgID string) message.SendEmailInput {
	templateVars := make(map[string]any)
	for k, v := range req.TemplateVars {
		templateVars[k] = v
	}
	return message.SendEmailInput{
		OrgID:          orgID,
		FromName:       req.FromName,
		FromEmail:      req.FromEmail,
		ToEmail:        req.ToEmail,
		ToName:         req.ToName,
		Subject:        req.Subject,
		HTMLBody:       req.HtmlBody,
		TextBody:       req.TextBody,
		TemplateSlug:   req.TemplateSlug,
		TemplateVars:   templateVars,
		Tags:           req.Tags,
		Priority:       int(req.Priority),
		IdempotencyKey: req.IdempotencyKey,
	}
}

func messageToProto(m *domain.Message) *v1.Message {
	createdAt, updatedAt := "", ""
	if !m.CreatedAt.IsZero() {
		createdAt = m.CreatedAt.Format(time.RFC3339)
	}
	if !m.UpdatedAt.IsZero() {
		updatedAt = m.UpdatedAt.Format(time.RFC3339)
	}
	return &v1.Message{
		Id:        string(m.ID),
		OrgId:     string(m.OrgID),
		FromName:  m.FromName,
		FromEmail: m.FromEmail,
		ToEmail:   m.ToEmail,
		ToName:    m.ToName,
		Subject:   m.Subject,
		Type:      string(m.Type),
		Status:    string(m.Status),
		Priority:  int32(m.Priority),
		Tags:      m.Tags,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}
