package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// SMTPConfig is one SMTP relay.
type SMTPConfig struct {
	Host string
	Port int
	// TLSMode is starttls, implicit or none (provider.TLS*).
	TLSMode  string
	Username string
	Password string
	// From is the default sender.
	From message.Address
}

// SMTP sends through an SMTP relay, one connection per message.
// STARTTLS is required when the mode says so: a server that does not
// offer it is refused, never used in plaintext.
type SMTP struct {
	cfg  SMTPConfig
	opts Options
	// guard refuses addresses the relay must not reach; nil for the
	// platform relay.
	guard func(network, address string, _ syscall.RawConn) error
}

// NewSMTP returns a sender for a tenant relay: private and loopback
// addresses are refused unless opts allow them.
func NewSMTP(cfg SMTPConfig, opts Options) (*SMTP, error) {
	s, err := newSMTP(cfg, opts)
	if err != nil {
		return nil, err
	}
	s.guard = dialGuard(s.opts)
	return s, nil
}

// NewPlatformSMTP returns the platform relay from config, or nil when it
// is disabled. The relay is operator-configured, so it may be on a
// private network or loopback (a sidecar MTA).
func NewPlatformSMTP(cfg config.SMTP, allowPlaintext bool, opts Options) (*SMTP, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts.AllowPlaintext = allowPlaintext
	return newSMTP(SMTPConfig{
		Host: cfg.Host, Port: cfg.Port, TLSMode: cfg.TLSMode,
		Username: cfg.Username, Password: cfg.Password,
		From: message.Address{Name: cfg.FromName, Email: cfg.FromAddr},
	}, opts)
}

func newSMTP(cfg SMTPConfig, opts Options) (*SMTP, error) {
	opts = opts.withDefaults()
	invalid := func(detail string) error {
		return message.NewSendError(string(provider.KindSMTP), message.ReasonConfig, 0, detail)
	}
	if cfg.Host == "" || cfg.Port < 1 || cfg.Port > 65535 {
		return nil, invalid("the SMTP host and port are required")
	}
	switch cfg.TLSMode {
	case "":
		cfg.TLSMode = provider.TLSStartTLS
	case provider.TLSStartTLS, provider.TLSImplicit:
	case provider.TLSNone:
		if !opts.AllowPlaintext {
			return nil, invalid("plaintext SMTP is refused outside local and test")
		}
	default:
		return nil, invalid("the SMTP TLS mode must be starttls, implicit or none")
	}
	if cfg.Password != "" && cfg.Username == "" {
		return nil, invalid("an SMTP password needs a username")
	}
	return &SMTP{cfg: cfg, opts: opts}, nil
}

// dialGuard refuses link-local (cloud metadata), unspecified and
// multicast addresses always, and loopback and private ones unless
// allowed. It runs on the resolved address, so DNS cannot sidestep it.
func dialGuard(opts Options) func(network, address string, _ syscall.RawConn) error {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("refusing to connect to %s", host)
		}
		ip = ip.Unmap()
		switch {
		case !ip.IsValid(), ip.IsUnspecified(), ip.IsMulticast(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
			return fmt.Errorf("refusing to connect to %s", host)
		case ip.IsLoopback():
			if !opts.AllowLoopback {
				return fmt.Errorf("refusing to connect to loopback address %s", host)
			}
		case ip.IsPrivate() || cgnat.Contains(ip):
			if !opts.AllowPrivateNetworks {
				return fmt.Errorf("refusing to connect to private address %s", host)
			}
		}
		return nil
	}
}

// SMTP stages, for classifying replies.
const (
	stageConnect = "connect"
	stageHello   = "hello"
	stageTLS     = "starttls"
	stageAuth    = "auth"
	stageMail    = "mail"
	stageRcpt    = "rcpt"
	stageData    = "data"
)

// classifySMTP maps an SMTP failure to a send error. 5xx replies are
// permanent (RFC 5321 §4.2.1): at RCPT the recipient is refused, at AUTH
// the credentials; 4xx replies are transient.
func classifySMTP(ctx context.Context, stage string, err error) *message.SendError {
	kind := string(provider.KindSMTP)
	var te *textproto.Error
	if !errors.As(err, &te) {
		if strings.Contains(err.Error(), "unencrypted connection") || strings.Contains(err.Error(), "wrong host name") {
			return &message.SendError{Provider: kind, Reason: message.ReasonConfig, Err: err, Detail: "the server would receive the password without TLS"}
		}
		e := classifyNetwork(ctx, provider.KindSMTP, err)
		if stage == stageTLS && e.Reason == message.ReasonNetwork && ctx.Err() == nil {
			e.Reason, e.Detail = message.ReasonConfig, "the STARTTLS handshake failed"
		}
		return e
	}
	e := &message.SendError{Provider: kind, Status: te.Code, Err: err,
		Detail: fmt.Sprintf("the server answered %d at %s: %s", te.Code, stage, truncate(te.Msg, 200))}
	switch {
	case te.Code >= 500:
		switch stage {
		case stageAuth:
			e.Reason = message.ReasonAuth
		case stageRcpt:
			e.Reason = message.ReasonInvalidRecipient
			if te.Code == 552 || te.Code == 554 {
				// Mailbox full or a policy refusal: the address exists.
				e.Reason = message.ReasonRejected
			}
		case stageMail, stageData:
			e.Reason = message.ReasonRejected
		default:
			e.Reason = message.ReasonConfig
		}
	case te.Code == 421 || strings.Contains(strings.ToLower(te.Msg), "rate") || strings.HasPrefix(te.Msg, "4.7."):
		e.Reason = message.ReasonRateLimited
	default:
		e.Reason = message.ReasonUnavailable
	}
	return e
}

// Send delivers out over one SMTP session, signing it with out.DKIM when
// the sender's domain is aligned with the key.
func (s *SMTP) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	out = out.WithDefaultFrom(s.cfg.From)
	if err := out.Validate(); err != nil {
		return Result{}, withProvider(err, provider.KindSMTP)
	}
	raw, msgID := buildMIME(out, time.Now())
	if out.DKIM != nil {
		signed, err := signDKIM(raw, out.From.Email, *out.DKIM)
		if err != nil {
			return Result{}, &message.SendError{Provider: string(provider.KindSMTP), Reason: message.ReasonConfig, Err: err, Detail: "the DKIM key cannot be used"}
		}
		raw = signed
	}

	conn, err := s.dial(ctx)
	if err != nil {
		return Result{}, classifySMTP(ctx, stageConnect, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(s.opts.Timeout))

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return Result{}, classifySMTP(ctx, stageConnect, err)
	}
	defer c.Close()
	if err := c.Hello(s.opts.HELOName); err != nil {
		return Result{}, classifySMTP(ctx, stageHello, err)
	}
	if s.cfg.TLSMode == provider.TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return Result{}, message.NewSendError(string(provider.KindSMTP), message.ReasonConfig, 0, "the server does not offer STARTTLS")
		}
		if err := c.StartTLS(s.opts.tlsConfig(s.cfg.Host)); err != nil {
			return Result{}, classifySMTP(ctx, stageTLS, err)
		}
	}
	if s.cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return Result{}, message.NewSendError(string(provider.KindSMTP), message.ReasonConfig, 0, "the server does not offer authentication")
		}
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return Result{}, classifySMTP(ctx, stageAuth, err)
		}
	}
	if err := c.Mail(out.From.Email); err != nil {
		return Result{}, classifySMTP(ctx, stageMail, err)
	}
	if err := c.Rcpt(out.To.Email); err != nil {
		return Result{}, classifySMTP(ctx, stageRcpt, err)
	}
	w, err := c.Data()
	if err != nil {
		return Result{}, classifySMTP(ctx, stageData, err)
	}
	if _, err := w.Write(raw); err != nil {
		return Result{}, classifySMTP(ctx, stageData, err)
	}
	if err := w.Close(); err != nil {
		return Result{}, classifySMTP(ctx, stageData, err)
	}
	// The message is accepted; a failed QUIT changes nothing.
	_ = c.Quit()
	return Result{ProviderMessageID: strings.Trim(msgID, "<>")}, nil
}

func (s *SMTP) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: min(s.opts.Timeout, 15*time.Second)}
	if s.guard != nil {
		d.Control = s.guard
	}
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	if s.cfg.TLSMode == provider.TLSImplicit {
		td := &tls.Dialer{NetDialer: d, Config: s.opts.tlsConfig(s.cfg.Host)}
		return td.DialContext(ctx, "tcp", addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

// withProvider stamps the provider kind on a send error.
func withProvider(err error, kind provider.Kind) error {
	if se, ok := message.AsSendError(err); ok && se.Provider == "" {
		se.Provider = string(kind)
	}
	return err
}
