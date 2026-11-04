package handler

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	v1 "github.com/razatechofficial/mail-os/api/proto/v1"
	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/domain/access"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/suppression"
	domaintenant "github.com/razatechofficial/mail-os/domain/tenant"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
)

// msgStore keeps sent messages in memory.
type msgStore struct {
	appmsg.Repository
	mu   sync.Mutex
	msgs map[string]domainmsg.Message
}

func (s *msgStore) Create(_ context.Context, m domainmsg.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs[m.ID] = m
	return nil
}

func (s *msgStore) Get(_ context.Context, tenantID, id string) (domainmsg.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.msgs[id]; ok && m.OrgID == tenantID {
		return m, nil
	}
	return domainmsg.Message{}, apperrors.NotFound("message not found")
}

func (s *msgStore) ByIdempotencyKey(context.Context, string, string) (*domainmsg.Message, error) {
	return nil, nil
}

type msgTenants struct{ tenants }

func (msgTenants) Settings(_ context.Context, id string) (domaintenant.Settings, error) {
	return domaintenant.Settings{TenantID: id}, nil
}

type nopQueue struct{}

func (nopQueue) EnqueueSend(context.Context, domainmsg.Message) error { return nil }

type noSuppressions struct{}

func (noSuppressions) Blocks(context.Context, string, string, string, domainmsg.Type) (*suppression.Suppression, error) {
	return nil, nil
}
func (noSuppressions) RecordBounce(context.Context, string, string, string) error { return nil }

var attachmentLimits = domainmsg.AttachmentLimits{MaxBytes: 1 << 10, MaxTotalBytes: 2 << 10, MaxCount: 3}

// newMailClient serves MailService over bufconn behind the real auth
// interceptor, sending through a message service with small limits.
func newMailClient(t *testing.T) (*fakeiam.IAM, v1.MailServiceClient, *appmsg.Service, *msgStore) {
	t.Helper()
	iam, _ := fakeiam.NewServer(t)
	repo := &msgStore{msgs: map[string]domainmsg.Message{}}
	svc := appmsg.NewService(appmsg.Deps{Repo: repo, Queue: nopQueue{}, Suppressions: noSuppressions{}, Tenants: msgTenants{},
		Audit: &auditLog{}}, appmsg.Config{Attachments: attachmentLimits})
	auth := &grpctransport.Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"})}
	srv := grpclib.NewServer(grpclib.ChainUnaryInterceptor(auth.Unary()))
	v1.RegisterMailServiceServer(srv, &MailService{Messages: svc, Tenants: tenants{}})
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpclib.NewClient("passthrough:///bufnet",
		grpclib.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpclib.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return iam, v1.NewMailServiceClient(conn), svc, repo
}

func operatorToken(iam *fakeiam.IAM) context.Context {
	return withToken(iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{string(access.RoleOperator)}}))
}

func TestSendEmailWithAttachmentsOverGRPC(t *testing.T) {
	iam, client, _, repo := newMailClient(t)
	res, err := client.SendEmail(operatorToken(iam), &v1.SendEmailRequest{FromEmail: "noreply@bank.example", ToEmail: "ana@example.com",
		Subject: "Your statement", TextBody: "Attached.", Attachments: []*v1.Attachment{
			{Filename: "statement.pdf", Content: []byte("%PDF-1.7")},
			{Filename: "logo.png", ContentType: "image/png", ContentId: "<logo>", Inline: true, Content: []byte("png")},
		}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := repo.Get(context.Background(), tenant, res.GetMessageId())
	if err != nil || res.GetStatus() != string(domainmsg.StatusQueued) {
		t.Fatalf("%+v %v", res, err)
	}
	a := m.Attachments
	if len(a) != 2 || a[0].ContentType != "application/pdf" || string(a[0].Data) != "%PDF-1.7" ||
		a[1].ContentID != "logo" || !a[1].Inline || a[1].ContentType != "image/png" {
		t.Fatalf("stored %+v", a)
	}
}

// An attachment over the limits is refused over gRPC with the field errors
// the HTTP API returns in its 422 body for the same files.
func TestSendEmailAttachmentLimitsMatchHTTP(t *testing.T) {
	iam, client, svc, repo := newMailClient(t)
	big := make([]byte, 2<<10)
	cases := map[string][]*v1.Attachment{
		"too large": {{Filename: "big.pdf", Content: big}},
		"too many":  {{Filename: "a.txt", Content: []byte("a")}, {Filename: "b.txt", Content: []byte("b")}, {Filename: "c.txt", Content: []byte("c")}, {Filename: "d.txt", Content: []byte("d")}},
		"blocked":   {{Filename: "setup.exe", Content: []byte("MZ")}},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			req := &v1.SendEmailRequest{FromEmail: "noreply@bank.example", ToEmail: "ana@example.com", Subject: "s", TextBody: "t", Attachments: files}
			_, err := client.SendEmail(operatorToken(iam), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code %v", err)
			}
			// The HTTP handler renders the service's error: its message and
			// details are the 422 body.
			in := sendInput(tenant, req)
			_, httpErr := svc.Send(access.WithPrincipal(context.Background(), access.Principal{Kind: access.KindUser, Subject: "user-1", TenantID: tenant,
				Roles: []access.Role{access.RoleOperator}}), in)
			want := apperrors.DetailsOf(httpErr)
			if len(want) == 0 || !reflect.DeepEqual(grpctransport.FieldErrors(err), want) ||
				status.Convert(err).Message() != apperrors.UserMessage(httpErr) {
				t.Fatalf("gRPC %v %+v, HTTP %+v", err, grpctransport.FieldErrors(err), want)
			}
		})
	}
	if len(repo.msgs) != 0 {
		t.Fatalf("refused sends stored %d messages", len(repo.msgs))
	}
}
