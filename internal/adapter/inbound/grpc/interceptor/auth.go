package interceptor

import (
	"context"
	"strings"

	"github.com/razatechofficial/mail-os/internal/core/apikey"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func AuthUnary(apiKeySvc apikey.Service) grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, handler grpclib.UnaryHandler) (any, error) {
		// Skip auth for health checks
		if strings.Contains(info.FullMethod, "Health") {
			return handler(ctx, req)
		}
		// Extract from metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		// Get authorization header
		authValues := md.Get("authorization")
		if len(authValues) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization")
		}
		token := strings.TrimPrefix(authValues[0], "Bearer ")
		key, err := apiKeySvc.ValidateKey(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid api key")
		}
		ctx = context.WithValue(ctx, orgIDKey{}, string(key.OrgID))
		return handler(ctx, req)
	}
}

type orgIDKey struct{}

func OrgIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(orgIDKey{}).(string); ok {
		return v
	}
	return ""
}
