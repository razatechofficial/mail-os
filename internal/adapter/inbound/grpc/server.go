package grpc

import (
	"fmt"
	"net"

	"github.com/razatechofficial/mail-os/pkg/logger"
	grpclib "google.golang.org/grpc"
)

type Server struct {
	server *grpclib.Server
	addr   string
}

func NewServer(addr string, opts ...grpclib.ServerOption) *Server {
	return &Server{
		server: grpclib.NewServer(opts...),
		addr:   addr,
	}
}

func (s *Server) GRPCServer() *grpclib.Server { return s.server }

func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpc.Start: %w", err)
	}
	logger.Info("gRPC server starting", logger.String("addr", s.addr))
	return s.server.Serve(lis)
}

func (s *Server) Shutdown() {
	logger.Info("gRPC server shutting down")
	s.server.GracefulStop()
}
