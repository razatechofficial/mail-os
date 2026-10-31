package grpc

import (
	"context"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
)

func TestUnaryAuth(t *testing.T) {
	iam, _ := fakeiam.NewServer(t)
	a := &Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos"})}
	var got access.Principal
	h := func(ctx context.Context, _ any) (any, error) { got, _ = access.FromContext(ctx); return "ok", nil }
	info := &grpclib.UnaryServerInfo{FullMethod: "/mailos.v1.MailService/DispatchEvent"}
	call := func(md metadata.MD) error {
		ctx := metadata.NewIncomingContext(context.Background(), md)
		_, err := a.Unary()(ctx, nil, info, h)
		return err
	}
	if err := call(metadata.MD{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	if err := call(metadata.Pairs("authorization", "Bearer forged.token.value")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("forged token: %v", err)
	}
	if err := call(metadata.Pairs("authorization", "static-shared-secret")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("static token accepted: %v", err)
	}
	tenant := "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"
	if err := call(metadata.Pairs("authorization", "Bearer "+iam.ServiceToken("mailos-iam", tenant))); err != nil {
		t.Fatalf("service token: %v", err)
	}
	if !got.IsService() || got.ClientID != "mailos-iam" || got.TenantID != tenant {
		t.Fatalf("principal %+v", got)
	}
	health := &grpclib.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}
	if _, err := a.Unary()(context.Background(), nil, health, h); err != nil {
		t.Fatalf("health needs no token: %v", err)
	}
}
