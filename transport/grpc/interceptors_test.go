package grpc

import (
	"context"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/razatechofficial/mail-os/application/applications/appstest"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func TestStatusCarriesValidationFields(t *testing.T) {
	err := Status(apperrors.Validation(
		apperrors.FieldError{Field: "attachments[0].content", Code: "too_large", Message: "the file is over 1 KiB"},
		apperrors.FieldError{Field: "attachments", Code: "too_many", Message: "at most 3 attachments"}))
	if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "validation failed" {
		t.Fatal(err)
	}
	f := FieldErrors(err)
	if len(f) != 2 || f[0] != (apperrors.FieldError{Field: "attachments[0].content", Code: "too_large", Message: "the file is over 1 KiB"}) ||
		f[1].Code != "too_many" {
		t.Fatalf("fields %+v", f)
	}
	if f := FieldErrors(Status(apperrors.Unavailable("down"))); len(f) != 0 {
		t.Fatalf("details on a non-validation error: %+v", f)
	}
}

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

// A user token issued to an application's client is refused over gRPC; a
// console user's is accepted.
func TestUnaryAuthRefusesApplicationUserTokens(t *testing.T) {
	iam, _ := fakeiam.NewServer(t)
	tenant := "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10"
	spa := appstest.Server("portal-web", tenant, "verify-email")
	spa.Kind = domainapp.KindSPA
	a := &Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, Audience: "mailos", ConsoleAudiences: []string{"mailos-console"}}),
		Apps: appstest.New(spa)}
	info := &grpclib.UnaryServerInfo{FullMethod: "/mailos.v1.MailService/SendEmail"}
	h := func(context.Context, any) (any, error) { return "ok", nil }
	call := func(tok string) error {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
		_, err := a.Unary()(ctx, nil, info, h)
		return err
	}
	browser := iam.UserToken(fakeiam.User{Tenant: tenant, ClientID: "portal-web", Roles: []string{"mailos_admin"},
		Extra: map[string]any{"scope": "mailos.send.self"}})
	if err := call(browser); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("spa user over gRPC: %v", err)
	}
	if err := call(iam.UserToken(fakeiam.User{Tenant: tenant, Roles: []string{"mailos_operator"}})); err != nil {
		t.Fatalf("console user: %v", err)
	}
}
