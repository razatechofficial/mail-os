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
type Platform struct{ Client *Client }

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
	ok, err := p.Client.Check(ctx, PlatformTenant, platformObject, string(perm), User(subject))
	return ok, translate(err)
}

// AllowedEach checks each permission, in one call.
func (p Platform) AllowedEach(ctx context.Context, subject string, perms []platformrole.Permission) ([]bool, error) {
	names := make([]string, len(perms))
	for i, x := range perms {
		names[i] = string(x)
	}
	out, err := p.Client.CheckEach(ctx, PlatformTenant, platformObject, names, User(subject))
	return out, translate(err)
}

// Holding is an active role and when it ends.
type Holding struct {
	Role      platformrole.Role
	ExpiresAt time.Time
}

// Holdings lists the person's active roles and the roles they are eligible
// for. ACS never returns an expired relationship.
func (p Platform) Holdings(ctx context.Context, subject string) (active []Holding, eligible []platformrole.Role, err error) {
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
			active = append(active, Holding{Role: role, ExpiresAt: r.ExpiresAt})
		}
	}
	return active, eligible, nil
}

// Eligible reports whether the person is eligible for role.
func (p Platform) Eligible(ctx context.Context, subject string, role platformrole.Role) (bool, error) {
	rels, err := p.Client.Read(ctx, PlatformTenant, Filter{ResourceType: platformObject.Type, ResourceID: platformObject.ID,
		Relation: role.EligibleRelation(), Subject: User(subject)})
	return len(rels) > 0, translate(err)
}

// Activate writes the activation, expiring at until.
func (p Platform) Activate(ctx context.Context, subject string, role platformrole.Role, until time.Time, idempotencyKey string) error {
	return translate(p.Client.Write(ctx, PlatformTenant, []Update{Touch(platformObject, role.Relation(), User(subject), until)}, idempotencyKey))
}

// End removes the activation.
func (p Platform) End(ctx context.Context, subject string, role platformrole.Role) error {
	return translate(p.Client.Write(ctx, PlatformTenant, []Update{Delete(platformObject, role.Relation(), User(subject))}, ""))
}

// AddEligibility writes the eligibility.
func (p Platform) AddEligibility(ctx context.Context, subject string, role platformrole.Role) error {
	return translate(p.Client.Write(ctx, PlatformTenant, []Update{Touch(platformObject, role.EligibleRelation(), User(subject), time.Time{})}, ""))
}

// RemoveEligibility removes the eligibility and any activation of it, in
// one write.
func (p Platform) RemoveEligibility(ctx context.Context, subject string, role platformrole.Role) error {
	return translate(p.Client.Write(ctx, PlatformTenant, []Update{
		Delete(platformObject, role.EligibleRelation(), User(subject)),
		Delete(platformObject, role.Relation(), User(subject)),
	}, ""))
}
