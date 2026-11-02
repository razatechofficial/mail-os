package handler

import (
	"context"
	"net"
	"sync"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	v1 "github.com/razatechofficial/mail-os/api/proto/v1"
	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/application/inbound"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	grpctransport "github.com/razatechofficial/mail-os/transport/grpc"
)

const tenant = "8d3b1f7a-2c4e-4f6a-9b1d-3e5f7a9c1b2d"

type store struct {
	mu   sync.Mutex
	rows map[string]inbound.Record
}

func (s *store) Claim(_ context.Context, r inbound.Record) (inbound.Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.rows[r.TenantID+r.EventID]; ok {
		return p, false, nil
	}
	s.rows[r.TenantID+r.EventID] = r
	return inbound.Record{}, true, nil
}

func (s *store) Complete(context.Context, string, string, string) error { return nil }

type tx struct{}

func (tx) InTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

type tenants struct{}

func (tenants) Ensure(context.Context, string) error { return nil }

type auditLog struct {
	mu      sync.Mutex
	actions []string
	reasons []any
}

func (a *auditLog) Append(_ context.Context, _, _, action string, meta map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, action)
	a.reasons = append(a.reasons, meta["reason"])
	return nil
}

type dispatcher struct {
	mu   sync.Mutex
	sent []inbound.Delivery
}

func (d *dispatcher) Dispatch(_ context.Context, del inbound.Delivery) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, del)
	return "msg-1", nil
}

// mailService is the messaging slice's server in miniature: it delegates
// DispatchEvent to the EventHandler.
type mailService struct {
	v1.UnimplementedMailServiceServer
	events *EventHandler
}

func (m mailService) DispatchEvent(ctx context.Context, r *v1.DispatchEventRequest) (*v1.DispatchEventResponse, error) {
	return m.events.DispatchEvent(ctx, r)
}

func newClient(t *testing.T) (*fakeiam.IAM, v1.MailServiceClient, *dispatcher, *auditLog) {
	t.Helper()
	iam, _ := fakeiam.NewServer(t)
	disp, log := &dispatcher{}, &auditLog{}
	svc := inbound.NewService(appstest.New(appstest.Server("iam", tenant, "iam.*")), tenants{}, &store{rows: map[string]inbound.Record{}}, tx{}, disp, log)
	auth := &grpctransport.Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"})}
	srv := grpclib.NewServer(grpclib.ChainUnaryInterceptor(auth.Unary()))
	v1.RegisterMailServiceServer(srv, mailService{events: NewEventHandler(svc)})
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
	return iam, v1.NewMailServiceClient(conn), disp, log
}

func withToken(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
}

var resetData = []byte(`{"email":"amna@example.com","reset_link":"https://iam.example.com/reset/x"}`)

func TestDispatchEventOverGRPC(t *testing.T) {
	iam, client, disp, log := newClient(t)
	res, err := client.DispatchEvent(withToken(iam.ServiceToken("iam", tenant)),
		&v1.DispatchEventRequest{Type: "iam.auth.password_reset_requested", Source: "iam", Data: resetData})
	if err != nil {
		t.Fatalf("DispatchEvent: %v", err)
	}
	if !res.GetAccepted() || res.GetDeliveryId() != "msg-1" {
		t.Fatalf("response %+v", res)
	}
	if len(disp.sent) != 1 || disp.sent[0].TenantID != tenant || disp.sent[0].EventID == "" {
		t.Fatalf("dispatched %+v", disp.sent)
	}
	if len(log.actions) != 1 || log.actions[0] != inbound.AuditAccepted {
		t.Fatalf("audit %v", log.actions)
	}
}

func TestDispatchEventOverGRPCRefusals(t *testing.T) {
	iam, client, disp, log := newClient(t)
	req := &v1.DispatchEventRequest{Type: "iam.auth.password_reset_requested", Source: "iam", Data: resetData}
	for name, tc := range map[string]struct {
		ctx  context.Context
		req  *v1.DispatchEventRequest
		code codes.Code
	}{
		"no token":       {context.Background(), req, codes.Unauthenticated},
		"unknown client": {withToken(iam.ServiceToken("crm", tenant)), req, codes.PermissionDenied},
		"user token":     {withToken(iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_admin"}})), req, codes.PermissionDenied},
		"wrong topic": {withToken(iam.ServiceToken("iam", tenant)),
			&v1.DispatchEventRequest{Type: "mailos.campaign", Data: resetData}, codes.PermissionDenied},
		"not JSON": {withToken(iam.ServiceToken("iam", tenant)),
			&v1.DispatchEventRequest{Type: req.Type, Data: []byte("x")}, codes.InvalidArgument},
		"no recipient": {withToken(iam.ServiceToken("iam", tenant)),
			&v1.DispatchEventRequest{Type: req.Type, Data: []byte(`{"reset_link":"https://iam.example.com/r"}`)}, codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client.DispatchEvent(tc.ctx, tc.req)
			if status.Code(err) != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
		})
	}
	if len(disp.sent) != 0 {
		t.Fatalf("a refused event was dispatched: %+v", disp.sent)
	}
	refused := 0
	for _, a := range log.actions {
		if a == inbound.AuditRefused {
			refused++
		}
	}
	if refused != 3 {
		t.Fatalf("audited %v %v, want three event.refused", log.actions, log.reasons)
	}
}
