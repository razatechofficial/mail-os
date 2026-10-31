package http

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
)

// Server is the REST listener. It serves TLS (optionally mutual TLS)
// whenever a certificate is configured; config validation refuses a
// plaintext listener outside local and test (contract §2).
type Server struct {
	srv *http.Server
	tls bool
}

// NewServer builds the listener for handler.
func NewServer(cfg config.HTTP, handler http.Handler) (*Server, error) {
	s := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 16,
	}
	if cfg.TLS.Enabled() {
		tc, err := tlsconfig.NewServer(ServerTLS(cfg.TLS))
		if err != nil {
			return nil, err
		}
		s.TLSConfig = tc
	}
	return &Server{srv: s, tls: cfg.TLS.Enabled()}, nil
}

// ServerTLS converts the config to tlsconfig's input.
func ServerTLS(t config.ServerTLS) tlsconfig.Server {
	return tlsconfig.Server{CertFile: t.CertFile, KeyFile: t.KeyFile, ClientCAFile: t.ClientCAFile, ClientAuth: t.ClientAuth, MinVersion: t.MinVersion}
}

// Start listens until Shutdown.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	logger.Info("http listening", logger.String("addr", s.srv.Addr), logger.Bool("tls", s.tls))
	if s.tls {
		err = s.srv.Serve(tls.NewListener(ln, s.srv.TLSConfig))
	} else {
		err = s.srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown drains in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }
