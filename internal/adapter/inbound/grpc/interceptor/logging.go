package interceptor

import (
	"context"
	"time"

	"github.com/razatechofficial/mail-os/pkg/logger"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func LoggingUnary() grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, handler grpclib.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		code := codes.Unknown
		if st, ok := status.FromError(err); ok {
			code = st.Code()
		}

		logger.Info("gRPC call",
			logger.String("method", info.FullMethod),
			logger.String("duration", duration.String()),
			logger.Int("code", int(code)),
		)
		return resp, err
	}
}
