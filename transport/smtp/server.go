package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	gosmtp "github.com/emersion/go-smtp"
	"golang.org/x/sync/errgroup"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/tlsconfig"
)

// maxLineLength fits an IAM access token in a SASL initial response; the
// RFC 5321 limit (1000) is too short for one.
const maxLineLength = 32 << 10

// Server is the SMTP submission listener: STARTTLS on Port, implicit TLS
// on ImplicitTLSPort when set.
type Server struct {
	cfg  config.SMTPSubmission
	deps Deps
	tls  *tls.Config
	srv  *gosmtp.Server

	mu        sync.Mutex
	listeners []net.Listener
}

// NewServer builds the listener from its settings (config validation has
// required a certificate) and its ports.
func NewServer(cfg config.SMTPSubmission, deps Deps) (*Server, error) {
	if deps.Tokens == nil || deps.Apps == nil || deps.Messages == nil || deps.Counter == nil {
		return nil, errors.New("smtp submission: tokens, applications, messages and counter are required")
	}
	tc, err := tlsconfig.NewServer(tlsconfig.Server{CertFile: cfg.CertFile, KeyFile: cfg.KeyFile, MinVersion: cfg.MinTLSVersion})
	if err != nil {
		return nil, fmt.Errorf("smtp submission tls: %w", err)
	}
	s := &Server{cfg: cfg, deps: deps, tls: tc}
	srv := gosmtp.NewServer(&backend{srv: s})
	srv.Domain = cfg.Hostname
	srv.TLSConfig = tc
	srv.MaxMessageBytes = cfg.MaxMessageBytes
	srv.MaxRecipients = cfg.MaxRecipients
	srv.MaxLineLength = maxLineLength
	srv.ReadTimeout, srv.WriteTimeout = cfg.ReadTimeout, cfg.WriteTimeout
	// AUTH is never advertised before TLS (AuthMechanisms is empty there)
	// and the session answers it 530; letting the library pass it through
	// is what gives that reply instead of the library's own.
	srv.AllowInsecureAuth = true
	srv.ErrorLog = errorLog{}
	s.srv = srv
	return s, nil
}

// passwords reports whether AUTH PLAIN and LOGIN are offered.
func (s *Server) passwords() bool { return s.cfg.PasswordAuth && s.deps.Credentials != nil }

// Listen binds the listeners; Serve then accepts on them. Start does both.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ln, err := net.Listen("tcp", s.cfg.Addr())
	if err != nil {
		return err
	}
	s.listeners = append(s.listeners, newLimitListener(ln, "starttls", s.cfg.MaxConnections, s.cfg.MaxConnectionsPerIP,
		s.cfg.MaxSessionDuration, true))
	if addr := s.cfg.ImplicitAddr(); addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			_ = s.listeners[0].Close()
			return err
		}
		limited := newLimitListener(ln, "implicit_tls", s.cfg.MaxConnections, s.cfg.MaxConnectionsPerIP,
			s.cfg.MaxSessionDuration, false)
		s.listeners = append(s.listeners, tls.NewListener(limited, s.tls))
	}
	return nil
}

// Addrs are the bound addresses: STARTTLS first, then implicit TLS.
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]net.Addr, len(s.listeners))
	for i, l := range s.listeners {
		out[i] = l.Addr()
	}
	return out
}

// Serve accepts until Shutdown.
func (s *Server) Serve() error {
	s.mu.Lock()
	listeners := append([]net.Listener(nil), s.listeners...)
	s.mu.Unlock()
	var g errgroup.Group
	for _, l := range listeners {
		logger.Info("smtp submission listening", logger.String("addr", l.Addr().String()))
		g.Go(func() error {
			if err := s.srv.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) {
				return err
			}
			return nil
		})
	}
	return g.Wait()
}

// Start binds and serves until Shutdown.
func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Shutdown stops accepting and waits for open sessions to end; at the
// deadline it closes them (a client then sees the connection drop before
// its DATA was acknowledged, and retries).
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		_ = s.srv.Close()
	}
	if errors.Is(err, gosmtp.ErrServerClosed) {
		return nil
	}
	return err
}

// errorLog sends the library's connection errors to the logger.
type errorLog struct{}

func (errorLog) Printf(format string, v ...any) {
	logger.Debug("smtp connection", logger.String("detail", fmt.Sprintf(format, v...)))
}

func (errorLog) Println(v ...any) {
	logger.Debug("smtp connection", logger.String("detail", fmt.Sprint(v...)))
}
