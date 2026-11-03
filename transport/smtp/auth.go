package smtp

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	appmsg "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/application/smtpcred"
	"github.com/razatechofficial/mail-os/domain/access"
	domainapp "github.com/razatechofficial/mail-os/domain/application"
	"github.com/razatechofficial/mail-os/domain/smtpcredential"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
)

// TokenVerifier verifies IAM access tokens (infrastructure/jwt.Verifier),
// the same verifier the HTTP and gRPC transports use.
type TokenVerifier interface {
	Principal(ctx context.Context, raw string) (access.Principal, error)
}

// Applications is the application registry (applications.Service).
type Applications interface {
	ResolveService(ctx context.Context, p access.Principal) (domainapp.Application, access.Principal, error)
	AuthorizeSubmission(ctx context.Context, applicationID, from string) error
}

// Credentials checks SMTP credentials (smtpcred.Service).
type Credentials interface {
	Authenticate(ctx context.Context, username, password, remoteIP string) (smtpcredential.Credential, domainapp.Application, error)
	Check(ctx context.Context, c smtpcredential.Credential) (domainapp.Application, error)
}

// Messages queues messages (message.Service): the pipeline of POST
// /messages/send with written content.
type Messages interface {
	Send(ctx context.Context, in appmsg.SendInput) (appmsg.Result, error)
}

// Counter keeps fixed-window counters (Redis): failed AUTH attempts per
// client address, shared by every replica.
type Counter interface {
	Take(ctx context.Context, key string, n, limit int64, ttl time.Duration) (bool, error)
	Peek(ctx context.Context, key string) (int64, error)
}

// Auditor records authentications and refusals.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Deps are the listener's ports. Credentials may be nil: then only IAM
// tokens are accepted.
type Deps struct {
	Tokens      TokenVerifier
	Apps        Applications
	Credentials Credentials
	Messages    Messages
	Counter     Counter
	Audit       Auditor
}

// identity is who a session authenticated as: an application, through
// its IAM client's token or one of its SMTP credentials.
type identity struct {
	mech      string
	principal access.Principal
	app       domainapp.Application
	// token is the IAM access token, verified again at each transaction.
	token string
	// cred is the SMTP credential, checked again at each transaction.
	cred smtpcredential.Credential
}

// method names how the session authenticated, for the message metadata
// and the audit trail.
func (id *identity) method() string {
	if id.token != "" {
		return "iam_token"
	}
	return "smtp_credential"
}

// authFailure is a refused authentication: Reason goes to the audit
// trail, the client only hears 535.
type authFailure struct{ reason string }

func (e *authFailure) Error() string { return "authentication refused: " + e.reason }

func refusedAs(reason string) error { return &authFailure{reason: reason} }

// fromToken authenticates an IAM access token exactly as the HTTP API
// does (signature against IAM's JWKS, iss, aud mailos, exp), then resolves
// the application of its client: a client-credentials token of an active
// server application of its tenant. A sender-constrained (DPoP) token is
// refused: SMTP cannot carry the proof, and the token must not work
// without it.
func (d Deps) fromToken(ctx context.Context, mech, token string) (*identity, error) {
	p, err := d.Tokens.Principal(ctx, token)
	if err != nil {
		if errors.Is(err, jwt.ErrUnavailable) {
			return nil, err
		}
		return nil, refusedAs("invalid_token")
	}
	switch {
	case p.DPoPThumbprint != "":
		return nil, refusedAs("dpop_bound_token")
	case !p.IsService():
		return nil, refusedAs("not_service_token")
	}
	a, rp, err := d.Apps.ResolveService(ctx, p)
	if err != nil {
		if r := domainapp.Reason(err); r != "" {
			return nil, refusedAs(r)
		}
		return nil, err
	}
	return &identity{mech: mech, principal: rp, app: a, token: token}, nil
}

// fromPassword authenticates an SMTP credential of an application opted
// in to them.
func (d Deps) fromPassword(ctx context.Context, mech, username, password, ip string) (*identity, error) {
	if d.Credentials == nil {
		return nil, refusedAs("password_auth_off")
	}
	c, a, err := d.Credentials.Authenticate(ctx, username, password, ip)
	if err != nil {
		var ae *smtpcred.AuthError
		if errors.As(err, &ae) {
			return nil, refusedAs(ae.Reason)
		}
		return nil, err
	}
	return &identity{mech: mech, principal: credentialPrincipal(c, a), app: a, cred: c}, nil
}

// credentialPrincipal is the principal an SMTP credential acts as: its
// application, as a service of the application's tenant. ClientID is the
// application's IAM client, so the audit trail and the message log group
// it with the application's other calls; Subject names the credential.
func credentialPrincipal(c smtpcredential.Credential, a domainapp.Application) access.Principal {
	return access.Principal{Kind: access.KindService, Subject: "smtp:" + c.Username, ClientID: a.ClientID,
		TenantID: strings.ToLower(a.TenantID), ApplicationID: a.ID}
}

// recheck decides again, at each transaction, whether the session may
// still send: the token has not expired and its application is still
// active; the credential is not revoked and its application still opted
// in. SMTP sessions are long; a revocation or suspension takes effect at
// the next MAIL FROM.
func (d Deps) recheck(ctx context.Context, id *identity) (*identity, error) {
	if id.token != "" {
		return d.fromToken(ctx, id.mech, id.token)
	}
	if d.Credentials == nil {
		return nil, refusedAs("password_auth_off")
	}
	a, err := d.Credentials.Check(ctx, id.cred)
	if err != nil {
		var ae *smtpcred.AuthError
		if errors.As(err, &ae) {
			return nil, refusedAs(ae.Reason)
		}
		return nil, err
	}
	next := *id
	next.app, next.principal = a, credentialPrincipal(id.cred, a)
	return &next, nil
}

// failKey counts an address's failed AUTH attempts in its window.
func failKey(ip string, window time.Duration, now time.Time) string {
	return "mailos:smtp:authfail:" + ip + ":" + strconv.FormatInt(now.Unix()/int64(window.Seconds()), 10)
}
