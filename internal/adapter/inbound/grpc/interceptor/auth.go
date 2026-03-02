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
		token := extractAPIKey(md)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing authorization or x-api-key")
		}
		key, err := apiKeySvc.ValidateKey(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid api key")
		}
		ctx = context.WithValue(ctx, orgIDKey{}, string(key.OrgID))
		return handler(ctx, req)
	}
}

type orgIDKey struct{}

// extractAPIKey gets the API key from authorization (Bearer) or x-api-key metadata.
func extractAPIKey(md metadata.MD) string {
	if v := md.Get("authorization"); len(v) > 0 {
		return strings.TrimPrefix(strings.TrimSpace(v[0]), "Bearer ")
	}
	if v := md.Get("x-api-key"); len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

func OrgIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(orgIDKey{}).(string); ok {
		return v
	}
	return ""
}
