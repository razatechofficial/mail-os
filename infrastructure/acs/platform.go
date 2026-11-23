package acs

import (
	"context"
	"errors"
	"time"

	"github.com/razatechofficial/mail-os/domain/platformrole"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// Platform is MailOS's module in ACS's platform scope: the roles and
// permissions on mailos/platform:global. Its errors are apperrors, so the
// transport maps them: Unavailable (503) when ACS did not answer, BadRequest
// (400) when ACS refused a write, with ACS's reason.
//
// With Tokens set, every write remembers ACS's ZedToken for the person and
// every check and read for that person is answered at least as fresh as
// it, so an ended role stops at once on every MailOS replica instead of
// after ACS's cache window. Without Tokens, ACS's default applies.
type Platform struct {
	Client *Client
	Tokens Freshness
}

// Freshness keeps the newest ZedToken of a person's platform relationships
// (shared by every MailOS replica). An error makes the caller fail closed.
type Freshness interface {
	Token(ctx context.Context, subject string) (string, error)
	Remember(ctx context.Context, subject, token string) error
}

// fresh is ctx answering at least as fresh as subject's last write.
func (p Platform) fresh(ctx context.Context, subject string) (context.Context, error) {
	if p.Tokens == nil {
		return ctx, nil
	}
	tok, err := p.Tokens.Token(ctx, subject)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.KindUnavailable, apperrors.CodeUnavailable, "the authorization service is unavailable; try again shortly")
	}
	return AtLeastAsFresh(ctx, tok), nil
}

// write applies updates for subject and remembers the write's token.
func (p Platform) write(ctx context.Context, subject string, updates []Update, idempotencyKey string) error {
	tok, err := p.Client.Write(ctx, PlatformTenant, updates, idempotencyKey)
	if err != nil {
		return translate(err)
	}
	if p.Tokens == nil || tok == "" {
		return nil
	}
	if err := p.Tokens.Remember(ctx, subject, tok); err != nil {
		// The write stands; failing lets the IAM deliver again (idempotent),
		// so the token is remembered before anyone relies on the change.
		return apperrors.Wrap(err, apperrors.KindUnavailable, apperrors.CodeUnavailable, "the authorization service is unavailable; try again shortly")
	}
	return nil
}

var platformObject = Object{Type: platformrole.ObjectType, ID: platformrole.ObjectID}

func translate(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrUnavailable) {
		return apperrors.Wrap(err, apperrors.KindUnavailable, apperrors.CodeUnavailable, "the authorization service is unavailable; try again shortly")
	}
	if r := Reason(err); r != "" {
		return apperrors.Wrap(err, apperrors.KindBadRequest, apperrors.CodeBadRequest, "the authorization service refused the change ("+r+")")
	}
	return err
}

// Allowed checks one permission for a platform account.
func (p Platform) Allowed(ctx context.Context, subject string, perm platformrole.Permission) (bool, error) {
	ctx, err := p.fresh(ctx, subject)
	if err != nil {
		return false, err
	}
	ok, err := p.Client.Check(ctx, PlatformTenant, platformObject, string(perm), User(subject))
	return ok, translate(err)
}

// AllowedEach checks each permission, in one call.
func (p Platform) AllowedEach(ctx context.Context, subject string, perms []platformrole.Permission) ([]bool, error) {
	ctx, err := p.fresh(ctx, subject)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(perms))
	for i, x := range perms {
		names[i] = string(x)
	}
	out, err := p.Client.CheckEach(ctx, PlatformTenant, platformObject, names, User(subject))
	return out, translate(err)
}

// Holdings lists the person's active roles and the roles they are eligible
// for. ACS never returns an expired relationship.
func (p Platform) Holdings(ctx context.Context, subject string) (active []platformrole.Holding, eligible []platformrole.Role, err error) {
	if ctx, err = p.fresh(ctx, subject); err != nil {
		return nil, nil, err
	}
	rels, err := p.Client.Read(ctx, PlatformTenant, Filter{ResourceType: platformObject.Type, ResourceID: platformObject.ID, Subject: User(subject)})
	if err != nil {
		return nil, nil, translate(err)
	}
	for _, r := range rels {
		role, isEligibility, ok := platformrole.RoleOfRelation(r.Relation)
		switch {
		case !ok:
		case isEligibility:
			eligible = append(eligible, role)
		default:
			active = append(active, platformrole.Holding{Role: role, ExpiresAt: r.ExpiresAt})
		}
	}
	return active, eligible, nil
}

// Eligible reports whether the person is eligible for role.
func (p Platform) Eligible(ctx context.Context, subject string, role platformrole.Role) (bool, error) {
	ctx, err := p.fresh(ctx, subject)
	if err != nil {
		return false, err
	}
	rels, err := p.Client.Read(ctx, PlatformTenant, Filter{ResourceType: platformObject.Type, ResourceID: platformObject.ID,
		Relation: role.EligibleRelation(), Subject: User(subject)})
	return len(rels) > 0, translate(err)
}

// Activate writes the activation, expiring at until.
func (p Platform) Activate(ctx context.Context, subject string, role platformrole.Role, until time.Time, idempotencyKey string) error {
	return p.write(ctx, subject, []Update{Touch(platformObject, role.Relation(), User(subject), until)}, idempotencyKey)
}

// End removes the activation.
func (p Platform) End(ctx context.Context, subject string, role platformrole.Role) error {
	return p.write(ctx, subject, []Update{Delete(platformObject, role.Relation(), User(subject))}, "")
}

// AddEligibility writes the eligibility.
func (p Platform) AddEligibility(ctx context.Context, subject string, role platformrole.Role) error {
	return p.write(ctx, subject, []Update{Touch(platformObject, role.EligibleRelation(), User(subject), time.Time{})}, "")
}

// RemoveEligibility removes the eligibility and any activation of it, in
// one write.
func (p Platform) RemoveEligibility(ctx context.Context, subject string, role platformrole.Role) error {
	return p.write(ctx, subject, []Update{
		Delete(platformObject, role.EligibleRelation(), User(subject)),
		Delete(platformObject, role.Relation(), User(subject)),
	}, "")
}
