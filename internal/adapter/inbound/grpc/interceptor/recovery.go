package interceptor

import (
	"context"
	"runtime/debug"

	"github.com/razatechofficial/mail-os/pkg/logger"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func RecoveryUnary() grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, handler grpclib.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("gRPC panic recovered",
					logger.String("method", info.FullMethod),
					logger.Any("panic", r),
					logger.String("stack", string(debug.Stack())),
				)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()
		resp, err = handler(ctx, req)
		return resp, err
	}
}
