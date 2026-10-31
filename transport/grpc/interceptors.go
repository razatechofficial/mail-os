package grpc

import (
	"context"
	"errors"
	"strings"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/metrics"
)

// TokenVerifier verifies IAM access tokens.
type TokenVerifier interface {
	Principal(ctx context.Context, raw string) (access.Principal, error)
}

// Auth verifies the bearer token of every call except the health service.
type Auth struct {
	Verifier TokenVerifier
}

const healthPrefix = "/grpc.health.v1.Health/"

// Unary is the unary interceptor.
func (a *Auth) Unary() grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, h grpclib.UnaryHandler) (any, error) {
		if strings.HasPrefix(info.FullMethod, healthPrefix) {
			return h(ctx, req)
		}
		ctx, err := a.authenticate(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
}

// Stream is the stream interceptor.
func (a *Auth) Stream() grpclib.StreamServerInterceptor {
	return func(srv any, ss grpclib.ServerStream, info *grpclib.StreamServerInfo, h grpclib.StreamHandler) error {
		if strings.HasPrefix(info.FullMethod, healthPrefix) {
			return h(srv, ss)
		}
		ctx, err := a.authenticate(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return h(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

func (a *Auth) authenticate(ctx context.Context, method string) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	raw := ""
	if v := md.Get("authorization"); len(v) == 1 {
		if s, t, ok := strings.Cut(strings.TrimSpace(v[0]), " "); ok && strings.EqualFold(s, "Bearer") {
			raw = strings.TrimSpace(t)
		}
	}
	if raw == "" {
		return nil, status.Error(codes.Unauthenticated, "missing bearer token")
	}
	p, err := a.Verifier.Principal(ctx, raw)
	if err != nil {
		if errors.Is(err, jwt.ErrUnavailable) {
			return nil, status.Error(codes.Unavailable, "the identity provider is unavailable")
		}
		logger.SecurityWarn("grpc token refused", logger.String("method", method), logger.Err(err))
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}
	return access.WithPrincipal(ctx, p), nil
}

type wrappedStream struct {
	grpclib.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// RecoveryUnary turns a panic into Internal.
func RecoveryUnary() grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, h grpclib.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("grpc panic", logger.String("method", info.FullMethod), logger.Any("panic", r))
				err = status.Error(codes.Internal, "an unexpected error occurred")
			}
		}()
		return h(ctx, req)
	}
}

// RecoveryStream turns a panic into Internal.
func RecoveryStream() grpclib.StreamServerInterceptor {
	return func(srv any, ss grpclib.ServerStream, info *grpclib.StreamServerInfo, h grpclib.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("grpc panic", logger.String("method", info.FullMethod), logger.Any("panic", r))
				err = status.Error(codes.Internal, "an unexpected error occurred")
			}
		}()
		return h(srv, ss)
	}
}

// LoggingUnary logs and counts each call.
func LoggingUnary() grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, h grpclib.UnaryHandler) (any, error) {
		resp, err := h(ctx, req)
		code := status.Code(err)
		metrics.ObserveGRPC(info.FullMethod, code.String())
		logger.FromContext(ctx).Info("grpc call", logger.String("method", info.FullMethod), logger.String("code", code.String()))
		return resp, err
	}
}

// Status maps an application error to a gRPC status with a client-safe
// message, as response.FromError does for HTTP.
func Status(err error) error {
	if err == nil {
		return nil
	}
	msg := apperrors.UserMessage(err)
	switch apperrors.KindOf(err) {
	case apperrors.KindNotFound:
		return status.Error(codes.NotFound, msg)
	case apperrors.KindAlreadyExists, apperrors.KindConflict:
		return status.Error(codes.AlreadyExists, msg)
	case apperrors.KindUnauthorized, apperrors.KindTokenInvalid:
		return status.Error(codes.Unauthenticated, msg)
	case apperrors.KindForbidden, apperrors.KindInactive, apperrors.KindStepUpRequired:
		return status.Error(codes.PermissionDenied, msg)
	case apperrors.KindInvalidInput, apperrors.KindBadRequest:
		return status.Error(codes.InvalidArgument, msg)
	case apperrors.KindRateLimited:
		return status.Error(codes.ResourceExhausted, msg)
	case apperrors.KindUnavailable:
		return status.Error(codes.Unavailable, msg)
	default:
		logger.Error("grpc internal error", logger.Err(err))
		return status.Error(codes.Internal, "an unexpected error occurred")
	}
}
