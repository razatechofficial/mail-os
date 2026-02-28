package http

import (
	"context"
	"fmt"
	nethttp "net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

type Server struct {
	engine     *gin.Engine
	httpServer *nethttp.Server
}

func NewServer(addr string, readTimeout, writeTimeout, idleTimeout time.Duration) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	return &Server{
		engine: engine,
		httpServer: &nethttp.Server{
			Addr:         addr,
			Handler:      engine,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
	}
}

func (s *Server) Engine() *gin.Engine { return s.engine }

func (s *Server) Start() error {
	logger.Info("HTTP server starting", logger.String("addr", s.httpServer.Addr))
	if err := s.httpServer.ListenAndServe(); err != nil && err != nethttp.ErrServerClosed {
		return fmt.Errorf("http.Start: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	logger.Info("HTTP server shutting down")
	return s.httpServer.Shutdown(ctx)
}
