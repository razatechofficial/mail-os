package applications

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/domain/access"
	domain "github.com/razatechofficial/mail-os/domain/application"
	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// AuditSendRefused is the action of a refused send.
const AuditSendRefused = "message.refused"

func quotaKey(appID string, now time.Time) string {
	return "mailos:app:quota:" + appID + ":" + now.UTC().Format("20060102")
}

func rateKey(appID string, now time.Time) string {
	return "mailos:app:rate:" + appID + ":" + strconv.FormatInt(now.Unix()/60, 10)
}

func userRateKey(appID, subject string, now time.Time) string {
	return "mailos:app:user:" + appID + ":" + subject + ":" + strconv.FormatInt(now.Unix()/3600, 10)
}

// lookup finds the application of an IAM client.
func (s *Service) lookup(ctx context.Context, clientID string) (domain.Application, error) {
	if clientID == "" {
		return domain.Application{}, domain.ErrUnknownClient
	}
	a, err := s.repo.ByClientID(ctx, clientID)
	if errors.Is(err, ErrNotFound) {
		return domain.Application{}, domain.ErrUnknownClient
	}
	return a, err
}

// sameTenant refuses a tenant named by a token or event that is not the
// application's: the application decides the tenant, never the caller.
func sameTenant(a domain.Application, named string) error {
	if named != "" && !strings.EqualFold(named, a.TenantID) {
		return domain.ErrTenantMismatch
	}
	return nil
}

// ResolveService returns the application a service token's client is,
// and the principal acting for it: the application's tenant, its id. An
// unknown client, a suspended or spa application, or a token naming
// another tenant is refused with the domain error.
func (s *Service) ResolveService(ctx context.Context, p access.Principal) (domain.Application, access.Principal, error) {
	if !p.IsService() {
		return domain.Application{}, p, domain.ErrNotService
	}
	a, err := s.lookup(ctx, p.ClientID)
	if err != nil {
		return domain.Application{}, p, err
	}
	if a.Kind != domain.KindServer {
		return a, p, domain.ErrKindMismatch
	}
	if !a.Active() {
		return a, p, domain.ErrSuspended
	}
	if err := sameTenant(a, p.TenantID); err != nil {
		return a, p, err
	}
	p.TenantID, p.ApplicationID = strings.ToLower(a.TenantID), a.ID
	return a, p, nil
}

// ResolveBrowser decides what a user token issued to an application's
// client may do. ok is false when the client is no application (a console
// user). A spa application's user becomes a self-service principal, its
// roles ignored, and needs the mailos.send.self scope; a server
// application's client presenting a user token is refused, because a
// server calls with client credentials.
func (s *Service) ResolveBrowser(ctx context.Context, p access.Principal) (domain.Application, access.Principal, bool, error) {
	if p.IsService() || p.ClientID == "" {
		return domain.Application{}, p, false, nil
	}
	a, err := s.repo.ByClientID(ctx, p.ClientID)
	if errors.Is(err, ErrNotFound) {
		return domain.Application{}, p, false, nil
	}
	if err != nil {
		return domain.Application{}, p, true, err
	}
	switch {
	case a.Kind != domain.KindSPA:
		return a, p, true, domain.ErrKindMismatch
	case !a.Active():
		return a, p, true, domain.ErrSuspended
	case !p.HasScope(domain.SelfSendScope):
		return a, p, true, domain.ErrScopeMissing
	}
	if err := sameTenant(a, p.TenantID); err != nil {
		return a, p, true, err
	}
	p.Roles, p.SelfService, p.ApplicationID, p.TenantID = nil, true, a.ID, strings.ToLower(a.TenantID)
	return a, p, true, nil
}

// AuthorizeEvent decides whether p's application may publish topic for
// the tenant the event names (possibly empty), whatever the transport.
func (s *Service) AuthorizeEvent(ctx context.Context, p access.Principal, topic, tenant string) (domain.Application, access.Principal, error) {
	a, p, err := s.ResolveService(ctx, p)
	if err != nil {
		return a, p, err
	}
	if err := sameTenant(a, tenant); err != nil {
		return a, p, err
	}
	if !a.AllowsType(topic) {
		return a, p, domain.ErrTypeNotAllowed
	}
	return a, p, nil
}

// Ask is one message an application wants to send.
type Ask struct {
	// Keys are the message's topic and template slug; empty for written
	// content (Raw).
	Keys      []string
	Raw       bool
	FromEmail string
	FromName  string
	ReplyTo   string
	Type      domainmsg.Type
	// To is the recipient, for the audit record (masked).
	To string
}

// Grant is what an allowed send goes out as.
type Grant struct {
	ApplicationID string
	FromEmail     string
	FromName      string
	ReplyTo       string
	Type          domainmsg.Type
	Stream        domain.Stream
	Sandbox       bool
}

// AuthorizeSend applies the application's rules to one message, in order:
// active, message type (or raw content), sender (one of its senders, on a
// domain still verified; its default when none is named), stream, then
// the per-minute rate and the daily quota. A refusal is audited as
// message.refused with its reason and returned; a limit is 429.
func (s *Service) AuthorizeSend(ctx context.Context, applicationID string, ask Ask) (Grant, error) {
	p, _ := access.FromContext(ctx)
	a, err := s.repo.Get(ctx, p.TenantID, applicationID)
	if err != nil {
		return Grant{}, err
	}
	g, err := s.authorizeSend(ctx, a, ask)
	if err != nil {
		return Grant{}, s.refuse(ctx, a, ask, err)
	}
	return g, nil
}

func (s *Service) authorizeSend(ctx context.Context, a domain.Application, ask Ask) (Grant, error) {
	if !a.Active() {
		return Grant{}, domain.ErrSuspended
	}
	if ask.Raw {
		if !a.AllowsRaw() {
			return Grant{}, domain.ErrRawNotAllowed
		}
	} else if !a.AllowsType(ask.Keys...) {
		return Grant{}, domain.ErrTypeNotAllowed
	}

	g := Grant{ApplicationID: a.ID, FromEmail: domain.NormalizeAddress(ask.FromEmail), FromName: strings.TrimSpace(ask.FromName),
		ReplyTo: strings.TrimSpace(ask.ReplyTo), Type: ask.Type, Stream: a.Stream, Sandbox: a.Sandbox()}
	if g.FromEmail == "" {
		g.FromEmail = a.DefaultFromEmail
		if g.FromName == "" {
			g.FromName = a.DefaultFromName
		}
	}
	if g.ReplyTo == "" {
		g.ReplyTo = a.DefaultReplyTo
	}
	switch {
	case g.FromEmail == "" && !a.System:
		return Grant{}, domain.ErrSenderRequired
	case g.FromEmail != "":
		if !a.AllowsSender(g.FromEmail) {
			return Grant{}, domain.ErrSenderNotAllowed
		}
		ok, err := s.domains.VerifiedFrom(ctx, a.TenantID, g.FromEmail)
		if err != nil {
			return Grant{}, err
		}
		if !ok {
			return Grant{}, domain.ErrSenderUnverified
		}
	}

	switch a.Stream {
	case domain.StreamTransactional:
		if g.Type == domainmsg.TypeMarketing {
			return Grant{}, domain.ErrStreamMismatch
		}
	case domain.StreamBroadcast:
		// Broadcast mail is marketing: unsubscribes are honoured.
		g.Type = domainmsg.TypeMarketing
	}
	if err := s.take(ctx, a); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// take counts one message against the daily quota and the per-minute
// rate. The counters fail closed: without them nothing is sent (503).
func (s *Service) take(ctx context.Context, a domain.Application) error {
	now := s.now()
	if a.DailyQuota > 0 {
		ok, err := s.counter.Take(ctx, quotaKey(a.ID, now), 1, int64(a.DailyQuota), 48*time.Hour)
		if err != nil {
			return apperrors.Unavailable("sending limits cannot be checked; try again shortly")
		}
		if !ok {
			return domain.ErrQuotaExceeded
		}
	}
	if a.RatePerMinute > 0 {
		ok, err := s.counter.Take(ctx, rateKey(a.ID, now), 1, int64(a.RatePerMinute), 2*time.Minute)
		if err != nil {
			return apperrors.Unavailable("sending limits cannot be checked; try again shortly")
		}
		if !ok {
			if a.DailyQuota > 0 {
				// The message is not sent: give its quota back.
				_, _ = s.counter.Take(ctx, quotaKey(a.ID, now), -1, int64(a.DailyQuota), 48*time.Hour)
			}
			return domain.ErrRateLimited
		}
	}
	return nil
}

// SelfSend is a browser user's send to themselves.
type SelfSend struct {
	TemplateSlug string
	// Origin is the request's Origin header.
	Origin string
}

// AuthorizeSelfSend checks a spa user's send before the template is
// resolved: the request origin, the template marked browser_allowed, the
// token's verified address, and the per-user hourly limit. It returns the
// recipient: always the signed-in user's own address.
func (s *Service) AuthorizeSelfSend(ctx context.Context, in SelfSend) (string, error) {
	p, _ := access.FromContext(ctx)
	if !p.SelfService || p.ApplicationID == "" {
		return "", apperrors.Forbidden("only a browser user of a spa application sends to themselves")
	}
	a, err := s.repo.Get(ctx, p.TenantID, p.ApplicationID)
	if err != nil {
		return "", err
	}
	ask := Ask{Keys: []string{in.TemplateSlug}, To: p.Email}
	if err := s.authorizeSelf(ctx, a, p, in); err != nil {
		return "", s.refuse(ctx, a, ask, err)
	}
	return domain.NormalizeAddress(p.Email), nil
}

func (s *Service) authorizeSelf(ctx context.Context, a domain.Application, p access.Principal, in SelfSend) error {
	switch {
	case !a.Active():
		return domain.ErrSuspended
	case a.Kind != domain.KindSPA:
		return domain.ErrKindMismatch
	case !a.AllowsOrigin(in.Origin):
		return domain.ErrOrigin
	case !a.AllowsBrowserTemplate(strings.ToLower(strings.TrimSpace(in.TemplateSlug))):
		return domain.ErrNotBrowserTemplate
	case strings.TrimSpace(p.Email) == "" || !p.EmailVerified:
		return domain.ErrNoVerifiedEmail
	}
	ok, err := s.counter.Take(ctx, userRateKey(a.ID, p.Subject, s.now()), 1, int64(a.UserRatePerHour), 2*time.Hour)
	if err != nil {
		return apperrors.Unavailable("sending limits cannot be checked; try again shortly")
	}
	if !ok {
		return domain.ErrUserRateLimited
	}
	return nil
}

// refuse audits a refused send and returns the error the API answers:
// 429 for a limit, 403 for the rest, with the refusal wrapped so the
// reason stays readable.
func (s *Service) refuse(ctx context.Context, a domain.Application, ask Ask, err error) error {
	reason := domain.Reason(err)
	if reason == "" {
		return err // not a refusal: a failure (unavailable counters, storage)
	}
	meta := map[string]any{"reason": reason, "application_id": a.ID, "client_id": a.ClientID}
	if len(ask.Keys) > 0 {
		meta["message_type"] = strings.Join(nonEmpty(ask.Keys), ",")
	}
	if ask.Raw {
		meta["message_type"] = domain.RawType
	}
	if ask.FromEmail != "" {
		meta["from"] = ask.FromEmail
	}
	if ask.To != "" {
		meta["to"] = logger.MaskEmail(ask.To)
	}
	if aerr := s.audit.Append(ctx, "application", a.ID, AuditSendRefused, meta); aerr != nil {
		return aerr
	}
	if domain.IsLimit(err) {
		retry := 60
		if errors.Is(err, domain.ErrQuotaExceeded) {
			retry = secondsToMidnight(s.now())
		} else if errors.Is(err, domain.ErrUserRateLimited) {
			retry = 3600 - int(s.now().Unix()%3600)
		}
		e := apperrors.NewRateLimitedError(err.Error(), retry)
		e.Err = err
		return e
	}
	return apperrors.Wrap(err, apperrors.KindForbidden, apperrors.CodeForbidden, err.Error())
}

func secondsToMidnight(now time.Time) int {
	next := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	return int(next.Sub(now.UTC()).Seconds())
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
