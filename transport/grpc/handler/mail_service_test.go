package handler

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/razatechofficial/mail-os/api/proto/v1"
	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type oneMessage struct {
	appmsg.Repository
	m domainmsg.Message
}

func (r oneMessage) Get(_ context.Context, tenantID, id string) (domainmsg.Message, error) {
	if tenantID != r.m.OrgID || id != r.m.ID {
		return domainmsg.Message{}, apperrors.NotFound("message not found")
	}
	return r.m, nil
}

func ctxAs(p access.Principal) context.Context { return access.WithPrincipal(context.Background(), p) }

func TestMailServiceRefusesServicesAndMissingRoles(t *testing.T) {
	svc := &MailService{Messages: appmsg.NewService(appmsg.Deps{Repo: oneMessage{m: domainmsg.Message{ID: "m1", OrgID: "t1",
		Subject: "Code 482913", TemplateData: map[string]any{"code": "482913"}, SecretKeys: []string{"code"}}}}, appmsg.Config{})}
	cases := []struct {
		ctx  context.Context
		code codes.Code
	}{
		{context.Background(), codes.Unauthenticated},
		{ctxAs(access.Principal{Kind: access.KindService, ClientID: "iam"}), codes.PermissionDenied},
		{ctxAs(access.Principal{Kind: access.KindUser, TenantID: "t1"}), codes.PermissionDenied},
		{ctxAs(access.Principal{Kind: access.KindUser, TenantID: "t2", Roles: []access.Role{access.RoleViewer}}), codes.NotFound},
	}
	for i, c := range cases {
		if _, err := svc.GetMessage(c.ctx, &v1.GetMessageRequest{Id: "m1"}); status.Code(err) != c.code {
			t.Errorf("case %d: %v", i, err)
		}
	}
	m, err := svc.GetMessage(ctxAs(access.Principal{Kind: access.KindUser, TenantID: "t1", Roles: []access.Role{access.RoleViewer}}), &v1.GetMessageRequest{Id: "m1"})
	if err != nil || m.GetSubject() != "Code "+domainmsg.Mask {
		t.Fatal(m, err)
	}
	if _, err := svc.SendEmail(ctxAs(access.Principal{Kind: access.KindUser, TenantID: "t1", Roles: []access.Role{access.RoleViewer}}), &v1.SendEmailRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("viewer sent mail")
	}
	if _, err := svc.DispatchEvent(context.Background(), &v1.DispatchEventRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
}
