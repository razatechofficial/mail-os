package mailer

import (
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // CRAM-MD5 is defined with HMAC-MD5 (RFC 2195)
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"slices"
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
	TLSMode string
	// Auth is the mechanism (provider.Auth*). Empty is PLAIN when a
	// username is set and none otherwise.
	Auth     string
	Username string
	Password string
	// Token supplies XOAUTH2 access tokens.
	Token *tokenSource
	// CACertPEM is trusted for the relay's certificate in addition to the
	// system roots (or Options.RootCAs).
	CACertPEM string
	// ClientCert is presented for mutual TLS.
	ClientCert *tls.Certificate
	// HELOName overrides Options.HELOName.
	HELOName string
	// From is the default sender.
	From message.Address
}

// SMTP sends through an SMTP relay, one connection per message.
// STARTTLS is required when the mode says so: a server that does not
// offer it is refused, never used in plaintext.
type SMTP struct {
	cfg   SMTPConfig
	opts  Options
	roots *x509.CertPool
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

// NewSMTPProvider returns the sender of a tenant's SMTP provider.
func NewSMTPProvider(s provider.Settings, c provider.Credentials, opts Options) (*SMTP, error) {
	invalid := func(d string) error {
		return message.NewSendError(string(provider.KindSMTP), message.ReasonConfig, 0, d)
	}
	cfg := SMTPConfig{
		Host: s.Host, Port: s.Port, TLSMode: s.TLSMode, Auth: s.AuthMechanism, Username: s.Username, Password: c.Password,
		CACertPEM: s.CACert, HELOName: s.HELOName, From: message.Address{Name: s.FromName, Email: s.FromEmail},
	}
	// An empty mechanism is left for newSMTP: PLAIN with a username, none
	// without one.
	if s.ClientCert != "" || c.ClientKey != "" {
		pair, err := tls.X509KeyPair([]byte(s.ClientCert), []byte(c.ClientKey))
		if err != nil {
			return nil, invalid("the client certificate and its private key do not form a pair")
		}
		cfg.ClientCert = &pair
	}
	if cfg.Auth == provider.AuthXOAUTH2 {
		var err error
		switch s.OAuthProvider {
		case provider.OAuthMicrosoft:
			cfg.Token, err = microsoftTokens(provider.KindSMTP, s, c, scopeOutlookSMTP, opts)
		case provider.OAuthGoogle:
			cfg.Token, err = googleTokens(provider.KindSMTP, c.ServiceAccountJSON, s.Username, scopeGmailSMTP, opts)
		default:
			err = invalid("XOAUTH2 needs an identity platform (microsoft or google)")
		}
		if err != nil {
			return nil, err
		}
	}
	return NewSMTP(cfg, opts)
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
	if cfg.Auth == "" {
		cfg.Auth = provider.AuthNone
		if cfg.Username != "" {
			cfg.Auth = provider.AuthPlain
		}
	}
	switch cfg.Auth {
	case provider.AuthNone:
		if cfg.Password != "" {
			return nil, invalid("an SMTP password needs a username and a mechanism")
		}
	case provider.AuthPlain, provider.AuthLogin, provider.AuthCRAMMD5:
		if cfg.Username == "" {
			return nil, invalid("SMTP authentication needs a username")
		}
	case provider.AuthXOAUTH2:
		if cfg.Username == "" || cfg.Token == nil {
			return nil, invalid("XOAUTH2 needs the mailbox as username and an OAuth application")
		}
	default:
		return nil, invalid("the SMTP authentication must be none, plain, login, cram-md5 or xoauth2")
	}
	s := &SMTP{cfg: cfg, opts: opts, roots: opts.RootCAs}
	if cfg.CACertPEM != "" {
		pool := opts.RootCAs
		if pool == nil {
			if sys, err := x509.SystemCertPool(); err == nil {
				pool = sys
			}
		}
		if pool == nil {
			pool = x509.NewCertPool()
		} else {
			pool = pool.Clone()
		}
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, invalid("the trusted CA certificates cannot be read")
		}
		s.roots = pool
	}
	return s, nil
}

func (s *SMTP) tlsConfig() *tls.Config {
	cfg := s.opts.tlsConfig(s.cfg.Host)
	cfg.RootCAs = s.roots
	if s.cfg.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*s.cfg.ClientCert}
	}
	return cfg
}

func (s *SMTP) heloName() string {
	if s.cfg.HELOName != "" {
		return s.cfg.HELOName
	}
	return s.opts.HELOName
}

// DialGuard is the tenant address rule as a net.Dialer Control, for other
// outbound callers that reach tenant-chosen hosts (webhooks).
func DialGuard(allowPrivateNetworks, allowLoopback bool) func(network, address string, _ syscall.RawConn) error {
	return dialGuard(Options{AllowPrivateNetworks: allowPrivateNetworks, AllowLoopback: allowLoopback})
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

// noSTARTTLS is the refusal of a relay without STARTTLS.
const noSTARTTLS = "the server does not offer STARTTLS"

// classifySMTP maps an SMTP failure to a send error. 5xx replies are
// permanent (RFC 5321 §4.2.1): at AUTH the credentials are refused, at
// MAIL, RCPT and DATA classifyPermanent reads the reply for what it
// refuses; 4xx replies are transient.
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
		case stageMail, stageRcpt, stageData:
			// Only a reply naming the recipient bounces (and suppresses);
			// a refused sender or relay is the provider's configuration.
			e.Reason = classifyPermanent(stage, te.Code, te.Msg)
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

// Check connects, negotiates TLS and authenticates, then quits without
// sending.
func (s *SMTP) Check(ctx context.Context, p *Probe) error {
	c, done, err := s.open(ctx, p)
	if err != nil {
		return err
	}
	defer done()
	_ = c.Quit()
	return nil
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
	c, done, err := s.open(ctx, nil)
	if err != nil {
		return Result{}, err
	}
	defer done()
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

// open runs a session up to an authenticated client: token, connect,
// EHLO, STARTTLS, AUTH, each a step of p. done closes it.
func (s *SMTP) open(ctx context.Context, p *Probe) (*smtp.Client, func(), error) {
	var token string
	if s.cfg.Auth == provider.AuthXOAUTH2 {
		var err error
		if p != nil {
			role := ""
			if s.cfg.Token.platform == oauthMicrosoft {
				role = "SMTP.SendAsApp"
			}
			token, err = s.cfg.Token.step(ctx, p, role)
		} else {
			token, err = s.cfg.Token.Token(ctx)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	label := "Connect to " + addr
	if s.cfg.TLSMode == provider.TLSImplicit {
		label += " with TLS"
	}
	var conn net.Conn
	err := p.Step("connect", label, func() (string, error) {
		var err error
		if conn, err = s.dial(ctx); err != nil {
			return "", classifySMTP(ctx, stageConnect, err)
		}
		if tc, ok := conn.(*tls.Conn); ok {
			return tlsSummary(p, tc.ConnectionState()), nil
		}
		return "connected", nil
	})
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(s.opts.Timeout))
	var c *smtp.Client
	done := func() {
		stop()
		if c != nil {
			_ = c.Close()
		} else {
			_ = conn.Close()
		}
	}
	fail := func(err error) (*smtp.Client, func(), error) {
		done()
		return nil, nil, err
	}

	if err := p.Step("hello", "Greet the server as "+s.heloName(), func() (string, error) {
		var err error
		if c, err = smtp.NewClient(conn, s.cfg.Host); err != nil {
			return "", classifySMTP(ctx, stageConnect, err)
		}
		if err := c.Hello(s.heloName()); err != nil {
			return "", classifySMTP(ctx, stageHello, err)
		}
		return "", nil
	}); err != nil {
		return fail(err)
	}
	if s.cfg.TLSMode == provider.TLSStartTLS {
		if err := p.Step("tls", "Start TLS", func() (string, error) {
			if ok, _ := c.Extension("STARTTLS"); !ok {
				return "", message.NewSendError(string(provider.KindSMTP), message.ReasonConfig, 0, noSTARTTLS)
			}
			if err := c.StartTLS(s.tlsConfig()); err != nil {
				return "", classifySMTP(ctx, stageTLS, err)
			}
			st, _ := c.TLSConnectionState()
			return tlsSummary(p, st), nil
		}); err != nil {
			return fail(err)
		}
	}
	if s.cfg.Auth != provider.AuthNone {
		mech := strings.ToUpper(s.cfg.Auth)
		if err := p.Step("auth", "Authenticate as "+s.cfg.Username+" with "+mech, func() (string, error) {
			ok, offered := c.Extension("AUTH")
			if !ok {
				return "", message.NewSendError(string(provider.KindSMTP), message.ReasonConfig, 0, "the server does not offer authentication")
			}
			if !slices.Contains(strings.Fields(strings.ToUpper(offered)), mech) {
				return "", message.NewSendError(string(provider.KindSMTP), message.ReasonConfig, 0,
					"the server does not offer AUTH "+mech+" (it offers "+truncate(offered, 100)+")")
			}
			if err := c.Auth(s.auth(token)); err != nil {
				if s.cfg.Token != nil {
					s.cfg.Token.Invalidate()
				}
				return "", classifySMTP(ctx, stageAuth, err)
			}
			return "authenticated", nil
		}); err != nil {
			return fail(err)
		}
	}
	return c, done, nil
}

func (s *SMTP) auth(token string) smtp.Auth {
	switch s.cfg.Auth {
	case provider.AuthLogin:
		return &loginAuth{user: s.cfg.Username, pass: s.cfg.Password, host: s.cfg.Host}
	case provider.AuthCRAMMD5:
		return &cramMD5Auth{user: s.cfg.Username, secret: s.cfg.Password}
	case provider.AuthXOAUTH2:
		return &xoauth2Auth{user: s.cfg.Username, token: token, host: s.cfg.Host}
	}
	return smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
}

// tlsSummary describes a TLS session and warns about a certificate close
// to expiry.
func tlsSummary(p *Probe, st tls.ConnectionState) string {
	d := tls.VersionName(st.Version)
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		d += ", certificate " + leaf.Subject.CommonName + " valid until " + leaf.NotAfter.UTC().Format("2006-01-02")
		if left := time.Until(leaf.NotAfter); left < 30*24*time.Hour {
			p.Warn(fmt.Sprintf("The relay's certificate expires in %d days (%s).", int(left.Hours()/24), leaf.NotAfter.UTC().Format("2006-01-02")))
		}
	}
	return d
}

// secureFor applies net/smtp's rule for sending a secret: only over TLS,
// or to localhost, and only to the host configured.
func secureFor(server *smtp.ServerInfo, host string) error {
	if !server.TLS && !isLocalhost(server.Name) {
		return errors.New("unencrypted connection")
	}
	if server.Name != host {
		return errors.New("wrong host name")
	}
	return nil
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

// loginAuth is AUTH LOGIN: the username and password as answers to the
// server's two challenges.
type loginAuth struct {
	user, pass, host string
	step             int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if err := secureFor(server, a.host); err != nil {
		return "", nil, err
	}
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.user), nil
	case 2:
		return []byte(a.pass), nil
	}
	return nil, errors.New("unexpected LOGIN challenge")
}

// cramMD5Auth is AUTH CRAM-MD5 (RFC 2195): the password never crosses the
// wire, so it is allowed before TLS like net/smtp's.
type cramMD5Auth struct{ user, secret string }

func (a *cramMD5Auth) Start(*smtp.ServerInfo) (string, []byte, error) { return "CRAM-MD5", nil, nil }

func (a *cramMD5Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	mac := hmac.New(md5.New, []byte(a.secret))
	mac.Write(fromServer)
	return []byte(a.user + " " + hex.EncodeToString(mac.Sum(nil))), nil
}

// xoauth2Auth is AUTH XOAUTH2 (Google and Microsoft): the user and a
// bearer token. On failure the server sends a JSON challenge, answered
// empty to get the final reply.
type xoauth2Auth struct{ user, token, host string }

func (a *xoauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if err := secureFor(server, a.host); err != nil {
		return "", nil, err
	}
	return "XOAUTH2", []byte("user=" + a.user + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
}

func (a *xoauth2Auth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return []byte{}, nil
	}
	return nil, nil
}

func (s *SMTP) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: min(s.opts.Timeout, 15*time.Second)}
	if s.guard != nil {
		d.Control = s.guard
	}
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	if s.cfg.TLSMode == provider.TLSImplicit {
		td := &tls.Dialer{NetDialer: d, Config: s.tlsConfig()}
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
