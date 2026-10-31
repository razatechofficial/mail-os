// Package handler holds the gRPC service implementations.
package handler

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/razatechofficial/mail-os/api/proto/v1"
	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/pkg/pagination"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
)

// TenantEnsurer provisions a user's tenant on first use.
type TenantEnsurer interface {
	Ensure(ctx context.Context, tenantID string) error
}

// EventDispatcher accepts a service's domain event (the events slice).
type EventDispatcher interface {
	DispatchEvent(context.Context, *v1.DispatchEventRequest) (*v1.DispatchEventResponse, error)
}

// MailService is v1.MailService. Sends and reads are for console users
// with the matching MailOS permission; services publish events through
// DispatchEvent, which Events handles.
type MailService struct {
	v1.UnimplementedMailServiceServer
	Messages *appmsg.Service
	Tenants  TenantEnsurer
	// Events handles DispatchEvent; nil answers Unimplemented.
	Events EventDispatcher
}

var _ v1.MailServiceServer = (*MailService)(nil)

// user returns the calling user, refusing services and missing roles.
func (s *MailService) user(ctx context.Context, perm access.Permission) (access.Principal, error) {
	p, ok := access.FromContext(ctx)
	switch {
	case !ok:
		return p, status.Error(codes.Unauthenticated, "missing bearer token")
	case p.IsService():
		return p, status.Error(codes.PermissionDenied, "services publish events with DispatchEvent")
	case !p.Can(perm):
		return p, status.Error(codes.PermissionDenied, "Your MailOS role does not allow this action")
	}
	if s.Tenants != nil {
		if err := s.Tenants.Ensure(ctx, p.TenantID); err != nil {
			return p, grpctransport.Status(err)
		}
	}
	return p, nil
}

func sendInput(tenantID string, r *v1.SendEmailRequest) appmsg.SendInput {
	var data map[string]any
	if len(r.GetTemplateVars()) > 0 {
		data = make(map[string]any, len(r.GetTemplateVars()))
		for k, v := range r.GetTemplateVars() {
			data[k] = v
		}
	}
	return appmsg.SendInput{TenantID: tenantID, FromName: r.GetFromName(), FromEmail: r.GetFromEmail(), ToEmail: r.GetToEmail(),
		ToName: r.GetToName(), Subject: r.GetSubject(), HTML: r.GetHtmlBody(), Text: r.GetTextBody(), TemplateSlug: r.GetTemplateSlug(),
		TemplateData: data, Tags: r.GetTags(), Priority: int(r.GetPriority()), IdempotencyKey: r.GetIdempotencyKey()}
}

// SendEmail queues one message (messages:operate).
func (s *MailService) SendEmail(ctx context.Context, r *v1.SendEmailRequest) (*v1.SendEmailResponse, error) {
	p, err := s.user(ctx, access.PermMessagesOperate)
	if err != nil {
		return nil, err
	}
	res, err := s.Messages.Send(ctx, sendInput(p.TenantID, r))
	if err != nil {
		return nil, grpctransport.Status(err)
	}
	return &v1.SendEmailResponse{MessageId: res.MessageID, Status: res.Status}, nil
}

// BatchSend queues up to 100 messages (messages:operate).
func (s *MailService) BatchSend(ctx context.Context, r *v1.BatchSendRequest) (*v1.BatchSendResponse, error) {
	p, err := s.user(ctx, access.PermMessagesOperate)
	if err != nil {
		return nil, err
	}
	in := make([]appmsg.SendInput, len(r.GetMessages()))
	for i, m := range r.GetMessages() {
		in[i] = sendInput(p.TenantID, m)
	}
	res, err := s.Messages.Batch(ctx, p.TenantID, in)
	if err != nil {
		return nil, grpctransport.Status(err)
	}
	out := &v1.BatchSendResponse{SuccessCount: int32(res.SuccessCount), FailCount: int32(res.FailCount)}
	for _, item := range res.Results {
		out.Results = append(out.Results, &v1.SendEmailResponse{MessageId: item.MessageID, Status: item.Status})
	}
	return out, nil
}

func messageOf(v appmsg.View) *v1.Message {
	m := v.Message
	return &v1.Message{Id: m.ID, OrgId: m.OrgID, FromName: m.FromName, FromEmail: m.FromEmail, ToEmail: m.ToEmail, ToName: m.ToName,
		Subject: v.MaskedSubject, Type: string(m.Type), Status: string(m.Status), Priority: int32(m.Priority), Tags: m.Tags,
		CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: m.UpdatedAt.UTC().Format(time.RFC3339)}
}

// GetMessage returns one message without its body (messages:read).
func (s *MailService) GetMessage(ctx context.Context, r *v1.GetMessageRequest) (*v1.Message, error) {
	p, err := s.user(ctx, access.PermMessagesRead)
	if err != nil {
		return nil, err
	}
	v, err := s.Messages.Get(ctx, p.TenantID, r.GetId())
	if err != nil {
		return nil, grpctransport.Status(err)
	}
	return messageOf(v), nil
}

// ListMessages returns a page of messages (messages:read).
func (s *MailService) ListMessages(ctx context.Context, r *v1.ListMessagesRequest) (*v1.ListMessagesResponse, error) {
	p, err := s.user(ctx, access.PermMessagesRead)
	if err != nil {
		return nil, err
	}
	pg := pagination.NewParams(int(r.GetPagination().GetPage()), int(r.GetPagination().GetLimit()), "", "")
	list, total, err := s.Messages.List(ctx, appmsg.Filter{TenantID: p.TenantID, Status: r.GetStatus(), Type: r.GetType(),
		Limit: pg.Limit, Offset: pg.Offset})
	if err != nil {
		return nil, grpctransport.Status(err)
	}
	meta := pagination.NewMeta(pg, total)
	out := &v1.ListMessagesResponse{Meta: &v1.PaginationMeta{Page: int32(meta.Page), Limit: int32(meta.Limit),
		TotalItems: int32(meta.TotalItems), TotalPages: int32(meta.TotalPages)}}
	for _, v := range list {
		out.Messages = append(out.Messages, messageOf(v))
	}
	return out, nil
}

// DispatchEvent hands a service's event to the events slice.
func (s *MailService) DispatchEvent(ctx context.Context, r *v1.DispatchEventRequest) (*v1.DispatchEventResponse, error) {
	if s.Events == nil {
		return nil, status.Error(codes.Unimplemented, "event dispatch is not enabled")
	}
	return s.Events.DispatchEvent(ctx, r)
}
