package smtp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
	"github.com/razatechofficial/mail-os/infrastructure/audit"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/pkg/metrics"
)

// maxAuthFailures is how many failed AUTH exchanges one connection may
// make before it is closed.
const maxAuthFailures = 3

// commandTimeout bounds the work behind one command (lookups, sends).
const commandTimeout = 30 * time.Second

// Replies the session gives (RFC 3207, RFC 4954, RFC 5321, RFC 3463).
var (
	errNeedTLS = &gosmtp.SMTPError{Code: 530, EnhancedCode: gosmtp.EnhancedCode{5, 7, 0},
		Message: "Must issue a STARTTLS command first"}
	errNeedAuth = &gosmtp.SMTPError{Code: 530, EnhancedCode: gosmtp.EnhancedCode{5, 7, 0},
		Message: "Authentication required"}
	errMechanism = &gosmtp.SMTPError{Code: 504, EnhancedCode: gosmtp.EnhancedCode{5, 5, 4},
		Message: "Unrecognized authentication type"}
	errTooManyAuth = &gosmtp.SMTPError{Code: 421, EnhancedCode: gosmtp.EnhancedCode{4, 7, 0},
		Message: "Too many authentication failures, closing connection"}
	errReauth = &gosmtp.SMTPError{Code: 421, EnhancedCode: gosmtp.EnhancedCode{4, 7, 0},
		Message: "Authentication expired; reconnect and authenticate again"}
	errBadRecipient = &gosmtp.SMTPError{Code: 553, EnhancedCode: gosmtp.EnhancedCode{5, 1, 3},
		Message: "Recipient address is not valid"}
	errTemporary = &gosmtp.SMTPError{Code: 451, EnhancedCode: gosmtp.EnhancedCode{4, 3, 0},
		Message: "Temporary failure, try again later"}
)

// backend opens a session per connection.
type backend struct{ srv *Server }

func (b *backend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	s := &session{srv: b.srv, conn: c, id: id.New(), ip: hostOf(c.Conn().RemoteAddr())}
	return s, nil
}

// session is one connection's state. Commands of one connection run one
// at a time.
type session struct {
	srv  *Server
	conn *gosmtp.Conn
	id   string
	ip   string

	who      *identity
	failures int

	from  string
	rcpts []string
}

var _ gosmtp.AuthSession = (*session)(nil)

func (s *session) tls() bool {
	_, ok := s.conn.TLSConnectionState()
	return ok
}

// ctx is the context of one command: the request metadata the audit
// trail records (client address, session id) and, once authenticated, the
// application's principal and tenant.
func (s *session) ctx() (context.Context, context.CancelFunc) {
	ctx := audit.WithRequestMeta(context.Background(), audit.RequestMeta{IP: s.ip,
		UserAgent: "smtp " + s.conn.Hostname(), RequestID: s.id})
	ctx = logger.WithRequestIDContext(ctx, s.id)
	if s.who != nil {
		ctx = access.WithPrincipal(ctx, s.who.principal)
		ctx = audit.WithTenant(ctx, s.who.principal.TenantID)
	}
	return context.WithTimeout(ctx, commandTimeout)
}

// closeAfterReply ends the connection once the current reply is written.
func (s *session) closeAfterReply() { closeAfterWrite(s.conn.Conn()) }

// AuthMechanisms are advertised only over TLS (RFC 4954 §4: no AUTH on an
// unprotected connection): IAM tokens always, passwords when on.
func (s *session) AuthMechanisms() []string {
	if !s.tls() {
		return nil
	}
	mechs := []string{MechOAuthBearer, MechXOAuth2}
	if s.srv.passwords() {
		mechs = append(mechs, MechPlain, MechLogin)
	}
	return mechs
}

// Auth starts an exchange: refused before TLS (530), after too many
// failures on this connection (421, closed) or from this address (454).
func (s *session) Auth(mech string) (sasl.Server, error) {
	if !s.tls() {
		return nil, errNeedTLS
	}
	if s.failures >= maxAuthFailures {
		s.closeAfterReply()
		return nil, errTooManyAuth
	}
	if !slices.Contains(s.AuthMechanisms(), mech) {
		return nil, errMechanism
	}
	if err := s.throttled(); err != nil {
		metrics.SMTPAuth(mech, "throttled")
		return nil, err
	}
	switch mech {
	case MechPlain:
		return &plainServer{check: s.passwordCheck(mech)}, nil
	case MechLogin:
		return &loginServer{check: s.passwordCheck(mech)}, nil
	default:
		return &bearerServer{mech: mech, check: s.tokenCheck(mech)}, nil
	}
}

// throttled refuses AUTH from an address with too many recent failures,
// counted across replicas; without the counter, AUTH is refused (fail
// closed).
func (s *session) throttled() error {
	ctx, cancel := s.ctx()
	defer cancel()
	cfg := s.srv.cfg
	n, err := s.srv.deps.Counter.Peek(ctx, failKey(s.ip, cfg.AuthFailureWindow, time.Now()))
	if err != nil {
		logger.FromContext(ctx).Warn("smtp auth throttle unavailable", logger.Err(err))
		return errAuthTemp
	}
	if n >= int64(cfg.AuthFailuresPerIP) {
		return errAuthTemp
	}
	return nil
}

func (s *session) passwordCheck(mech string) passwordCheck {
	return func(username, password string) error {
		ctx, cancel := s.ctx()
		defer cancel()
		who, err := s.srv.deps.fromPassword(ctx, mech, username, password, s.ip)
		return s.authenticated(ctx, mech, username, who, err)
	}
}

func (s *session) tokenCheck(mech string) tokenCheck {
	return func(token string) error {
		ctx, cancel := s.ctx()
		defer cancel()
		who, err := s.srv.deps.fromToken(ctx, mech, token)
		return s.authenticated(ctx, mech, "", who, err)
	}
}

// authenticated settles an exchange: the session's identity, or a failure
// counted, audited (smtp.auth_failed with its reason) and answered 535.
// A failure of MailOS itself (IAM's keys or the database unreachable) is
// 454: the client tries again later.
func (s *session) authenticated(ctx context.Context, mech, username string, who *identity, err error) error {
	var af *authFailure
	switch {
	case err == nil:
		s.who = who
		ctx = access.WithPrincipal(ctx, who.principal)
		ctx = audit.WithTenant(ctx, who.principal.TenantID)
		meta := map[string]any{"mechanism": mech, "method": who.method(), "application_id": who.app.ID}
		if who.cred.Username != "" {
			meta["smtp_username"] = who.cred.Username
		}
		s.audit(ctx, "smtp_session", s.id, "smtp.authenticated", meta)
		metrics.SMTPAuth(mech, "ok")
		return nil
	case errors.As(err, &af):
		s.failures++
		meta := map[string]any{"mechanism": mech, "reason": af.reason}
		if username != "" {
			meta["smtp_username"] = safeUsername(username)
		}
		s.audit(ctx, "smtp_session", s.id, "smtp.auth_failed", meta)
		cfg := s.srv.cfg
		if _, cerr := s.srv.deps.Counter.Take(ctx, failKey(s.ip, cfg.AuthFailureWindow, time.Now()), 1, 1<<31,
			2*cfg.AuthFailureWindow); cerr != nil {
			logger.FromContext(ctx).Warn("smtp auth failure not counted", logger.Err(cerr))
		}
		logger.SecurityWarn("smtp authentication refused", logger.String("reason", af.reason),
			logger.String("mechanism", mech), logger.String("ip", s.ip))
		metrics.SMTPAuth(mech, "failed")
		return errAuthFailed
	default:
		logger.FromContext(ctx).Error("smtp authentication unavailable", logger.String("mechanism", mech), logger.Err(err))
		metrics.SMTPAuth(mech, "error")
		return errAuthTemp
	}
}

// safeUsername is what the audit trail records of a refused username: a
// generated username as it is; anything else (perhaps a password typed
// into the wrong field) only as "other".
func safeUsername(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if len(u) == len("smtp_")+24 && strings.HasPrefix(u, "smtp_") {
		return u
	}
	return "other"
}

func (s *session) audit(ctx context.Context, typ, id, action string, meta map[string]any) {
	if s.srv.deps.Audit == nil {
		return
	}
	if err := s.srv.deps.Audit.Append(ctx, typ, id, action, meta); err != nil {
		logger.FromContext(ctx).Error("smtp audit", logger.String("action", action), logger.Err(err))
	}
}

// Mail starts a transaction: only over TLS and authenticated (never an
// open relay), with the identity decided again and the envelope sender
// one of the application's senders on a verified domain.
func (s *session) Mail(from string, _ *gosmtp.MailOptions) error {
	if !s.tls() {
		return errNeedTLS
	}
	if s.who == nil {
		return errNeedAuth
	}
	ctx, cancel := s.ctx()
	defer cancel()
	who, err := s.srv.deps.recheck(ctx, s.who)
	if err != nil {
		var af *authFailure
		if !errors.As(err, &af) {
			logger.FromContext(ctx).Error("smtp session check failed", logger.Err(err))
			return errTemporary
		}
		s.audit(ctx, "smtp_session", s.id, "smtp.session_refused", map[string]any{"reason": af.reason})
		metrics.SMTPMessage(af.reason, 0)
		s.closeAfterReply()
		return errReauth
	}
	s.who = who
	ctx = access.WithPrincipal(ctx, who.principal)
	if err := s.srv.deps.Apps.AuthorizeSubmission(ctx, who.app.ID, from); err != nil {
		return s.refusal(ctx, err)
	}
	s.from = domainapp.NormalizeAddress(from)
	return nil
}

// Rcpt adds a recipient with a valid address; duplicates count once.
func (s *session) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	if s.who == nil {
		return errNeedAuth
	}
	to = domainapp.NormalizeAddress(to)
	if !provider.ValidEmail(to) {
		return errBadRecipient
	}
	if !slices.Contains(s.rcpts, to) {
		s.rcpts = append(s.rcpts, to)
	}
	return nil
}

// Data reads the message (within SIZE), parses it, and queues one message
// per recipient through the pipeline of POST /messages/send: message
// type raw, the header From among the application's senders, stream,
// limits, suppressions, sandbox capture; the worker then signs with the
// domain's DKIM key and writes MailOS's Message-ID.
//
// SMTP has one reply for the whole transaction. If a recipient fails after
// others were queued, the reply is the failure; the client's retry is then
// deduplicated by its Message-ID, so the queued recipients get it once.
func (s *session) Data(r io.Reader) error {
	if s.who == nil {
		return errNeedAuth
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		var se *gosmtp.SMTPError
		if errors.As(err, &se) {
			metrics.SMTPMessage("too_large", 0)
			return se
		}
		return errTemporary
	}
	ctx, cancel := s.ctx()
	defer cancel()
	msg, err := parseMessage(raw)
	if err != nil {
		return s.refusal(ctx, err)
	}
	app := s.who.app
	if app.Stream == domainapp.StreamBroadcast && msg.Headers["List-Unsubscribe"] == "" {
		return s.refusal(ctx, &contentError{reason: "list_unsubscribe_required", reply: &gosmtp.SMTPError{Code: 550,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message:      "Broadcast mail needs a List-Unsubscribe header, with one-click unsubscribe (RFC 8058)"}})
	}
	fromName, fromEmail := "", s.from
	if msg.From != nil {
		fromName, fromEmail = oneLine(msg.From.Name), msg.From.Address
	}
	queued := []string{}
	for _, to := range s.rcpts {
		in := appmsg.SendInput{TenantID: s.who.principal.TenantID, FromName: fromName, FromEmail: fromEmail, ToEmail: to,
			ToName: msg.Names[to], ReplyTo: msg.ReplyTo, Subject: msg.Subject, HTML: msg.HTML, Text: msg.Text,
			Type: domainmsg.TypeTransactional, Headers: msg.Headers, Attachments: msg.Attachments,
			Metadata:       map[string]any{"source": "smtp", "smtp_session": s.id, "smtp_auth": s.who.method()},
			IdempotencyKey: idempotencyKey(app.ID, msg.MessageID, to, raw)}
		if msg.MessageID != "" {
			in.Metadata["smtp_message_id"] = msg.MessageID
		}
		res, err := s.srv.deps.Messages.Send(ctx, in)
		if err != nil {
			if len(queued) > 0 {
				logger.FromContext(ctx).Warn("smtp transaction failed after some recipients were queued",
					logger.Int("queued", len(queued)), logger.Int("recipients", len(s.rcpts)), logger.Err(err))
			}
			return s.refusal(ctx, err)
		}
		queued = append(queued, res.MessageID)
	}
	metrics.SMTPMessage("queued", len(queued))
	return &gosmtp.SMTPError{Code: 250, EnhancedCode: gosmtp.EnhancedCode{2, 0, 0},
		Message: "OK: queued as " + strings.Join(queued, " ")}
}

// idempotencyKey makes a retried transaction send nothing twice: the
// client's Message-ID and the exact message, per application and
// recipient. A client that reuses a Message-ID for other content still
// sends each; without a Message-ID each transaction is new.
func idempotencyKey(applicationID, messageID, to string, raw []byte) string {
	if messageID == "" {
		return ""
	}
	body := sha256.Sum256(raw)
	sum := sha256.Sum256([]byte(applicationID + "\x00" + messageID + "\x00" + to + "\x00" + hex.EncodeToString(body[:])))
	return "smtp:" + hex.EncodeToString(sum[:])
}

// refusal turns a refused transaction into its reply, counted in the
// metrics (the application registry has already audited its own
// refusals; content refusals are audited here).
func (s *session) refusal(ctx context.Context, err error) error {
	reply, reason := replyFor(err)
	var ce *contentError
	if errors.As(err, &ce) {
		meta := map[string]any{"reason": ce.reason}
		if s.who != nil {
			meta["application_id"] = s.who.app.ID
		}
		s.audit(ctx, "smtp_session", s.id, "smtp.message_refused", meta)
	}
	if reply.Code == errTemporary.Code && reason == "error" {
		logger.FromContext(ctx).Error("smtp submission failed", logger.Err(err))
	}
	metrics.SMTPMessage(reason, 0)
	return reply
}

// replyFor maps an error to its SMTP reply and a reason for the metrics:
//
//	sender, raw content, stream, suspension   550 5.7.1
//	per-minute rate                           451 4.7.1
//	daily quota                               452 4.7.1
//	message content                           554 5.6.x
//	invalid fields (subject, addresses)       554 5.6.0
//	MailOS unavailable (counters, database)   451 4.3.0
func replyFor(err error) (*gosmtp.SMTPError, string) {
	var ce *contentError
	if errors.As(err, &ce) {
		return ce.reply, ce.reason
	}
	switch {
	case errors.Is(err, domainapp.ErrRateLimited):
		return &gosmtp.SMTPError{Code: 451, EnhancedCode: gosmtp.EnhancedCode{4, 7, 1},
			Message: "The application's per-minute sending rate is exceeded, try again later"}, "rate_limited"
	case errors.Is(err, domainapp.ErrQuotaExceeded):
		return &gosmtp.SMTPError{Code: 452, EnhancedCode: gosmtp.EnhancedCode{4, 7, 1},
			Message: "The application's daily quota is used up, try again tomorrow"}, "quota_exceeded"
	}
	if reason := domainapp.Reason(err); reason != "" {
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message: "Not allowed: " + domainReasonMessage(err)}, reason
	}
	switch apperrors.KindOf(err) {
	case apperrors.KindInvalidInput:
		return &gosmtp.SMTPError{Code: 554, EnhancedCode: gosmtp.EnhancedCode{5, 6, 0},
			Message: "Message refused: " + validationMessage(err)}, "invalid"
	case apperrors.KindForbidden:
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message: "Not allowed: " + apperrors.UserMessage(err)}, "forbidden"
	case apperrors.KindRateLimited, apperrors.KindUnavailable:
		return errTemporary, "unavailable"
	}
	return errTemporary, "error"
}

// domainReasonMessage is the refusal's own sentence, which names no
// secret: "the sender is not one of the application's senders".
func domainReasonMessage(err error) string {
	for _, e := range []error{domainapp.ErrSenderNotAllowed, domainapp.ErrSenderUnverified, domainapp.ErrSenderRequired,
		domainapp.ErrRawNotAllowed, domainapp.ErrStreamMismatch, domainapp.ErrSuspended, domainapp.ErrTypeNotAllowed} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "this application may not send this message"
}

func validationMessage(err error) string {
	if d := apperrors.DetailsOf(err); len(d) > 0 {
		return d[0].Message
	}
	return apperrors.UserMessage(err)
}

// Reset ends the transaction; the authentication stays.
func (s *session) Reset() {
	s.from, s.rcpts = "", nil
}

// Logout ends the session.
func (s *session) Logout() error { return nil }
