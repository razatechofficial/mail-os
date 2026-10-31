// Package grpc is the gRPC transport: TLS (optionally mutual TLS) on the
// listener, and unary and stream interceptors that verify the IAM service
// token in the authorization metadata of every call (contract §2).
package grpc

import (
	"net"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
)

// Server is the gRPC listener.
type Server struct {
	addr string
	srv  *grpclib.Server
	tls  bool
}

// NewServer builds the server with TLS when configured (config validation
// refuses insecure outside local and test) and the auth interceptors.
func NewServer(cfg config.GRPC, auth *Auth, tracing bool) (*Server, error) {
	opts := []grpclib.ServerOption{
		grpclib.ChainUnaryInterceptor(RecoveryUnary(), LoggingUnary(), auth.Unary()),
		grpclib.ChainStreamInterceptor(RecoveryStream(), auth.Stream()),
		grpclib.MaxRecvMsgSize(4 << 20),
	}
	if tracing {
		opts = append(opts, grpclib.StatsHandler(otelgrpc.NewServerHandler()))
	}
	if cfg.TLS.Enabled() {
		t := cfg.TLS
		tc, err := tlsconfig.NewServer(tlsconfig.Server{CertFile: t.CertFile, KeyFile: t.KeyFile,
			ClientCAFile: t.ClientCAFile, ClientAuth: t.ClientAuth, MinVersion: t.MinVersion})
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpclib.Creds(credentials.NewTLS(tc)))
	}
	srv := grpclib.NewServer(opts...)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	return &Server{addr: cfg.Addr(), srv: srv, tls: cfg.TLS.Enabled()}, nil
}

// Registrar is where services register.
func (s *Server) Registrar() *grpclib.Server { return s.srv }

// Start serves until Stop.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	logger.Info("grpc listening", logger.String("addr", s.addr), logger.Bool("tls", s.tls))
	return s.srv.Serve(ln)
}

// Stop drains calls in flight.
func (s *Server) Stop() { s.srv.GracefulStop() }
