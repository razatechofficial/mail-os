// Package platformroles applies the IAM's privileged-access decisions for
// MailOS platform roles (ADR 0001 §3.4, contract C5). The IAM cannot write
// MailOS's ACS types; it signs an attestation with its ACS approval key and
// delivers it to MailOS, which verifies it and writes the relationship in
// ACS's platform scope: an activation as mailos/platform:global#<role>
// expiring at the attested end, an eligibility as #eligible_<role>.
//
// An attestation is a credential presented once: its jti is claimed before
// it is applied, so a second presentation changes nothing (answered as
// done, since the IAM retries a delivery whose answer it lost). A record the
// IAM closed (an activation ended, an eligibility removed) is remembered for
// longer than any attestation lives, so a delayed "activate" or "add" for
// it cannot undo the close.
package platformroles

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/domain/platformrole"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Attestation format (contract C5).
const (
	// Type is the JWS typ of the IAM's ACS approval attestations.
	Type = "acs-approval+jwt"
	// Audience is the aud an attestation for MailOS carries.
	Audience = "mailos"
	// MaxLifetime bounds exp - iat.
	MaxLifetime = 10 * time.Minute

	OpActivation  = "mailos.role_activation"
	OpEligibility = "mailos.role_eligibility"

	ActionActivate = "activate"
	ActionEnd      = "end"
	ActionAdd      = "add"
	ActionRemove   = "remove"
)

// closedFor is how long a closed record is remembered: longer than any
// attestation for it can live.
const closedFor = MaxLifetime + 5*time.Minute

// Verifier checks an attestation's signature against the IAM's approval
// keys and its times (infrastructure/jwt.Verifier on the approval JWKS).
type Verifier interface {
	Verify(ctx context.Context, raw string, wantTypes ...string) (map[string]any, error)
	CheckTimes(claims map[string]any) error
	Issuer() string
	Now() time.Time
}

// Roles is ACS's platform scope for MailOS's module (infrastructure/acs).
// Errors are apperrors: Unavailable when ACS did not answer.
type Roles interface {
	Eligible(ctx context.Context, subject string, role platformrole.Role) (bool, error)
	Activate(ctx context.Context, subject string, role platformrole.Role, until time.Time, idempotencyKey string) error
	End(ctx context.Context, subject string, role platformrole.Role) error
	AddEligibility(ctx context.Context, subject string, role platformrole.Role) error
	// RemoveEligibility removes the eligibility and any activation of it.
	RemoveEligibility(ctx context.Context, subject string, role platformrole.Role) error
}

// Replay remembers keys for a while (Redis). Claim reports whether this
// call recorded the key first.
type Replay interface {
	ClaimOnce(ctx context.Context, key string, ttl time.Duration) (bool, error)
	Forget(ctx context.Context, key string) error
	Seen(ctx context.Context, key string) (bool, error)
}

// Auditor records what was applied.
type Auditor interface {
	Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error
}

// Service verifies and applies attestations.
type Service struct {
	verifier Verifier
	roles    Roles
	replay   Replay
	audit    Auditor
}

// New builds the service.
func New(v Verifier, roles Roles, replay Replay, audit Auditor) *Service {
	return &Service{verifier: v, roles: roles, replay: replay, audit: audit}
}

// Attestation is a verified attestation's claims.
type Attestation struct {
	ID          string // jti
	Op, Action  string
	Subject     string
	Role        platformrole.Role
	ActiveUntil time.Time // activate only
	// RecordID is the IAM's activation or eligibility record.
	RecordID    string
	RequestedBy string
	ApprovedBy  string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Result is what Apply did.
type Result struct {
	Attestation
	// Replayed means the attestation was presented before (or its record
	// was closed) and nothing changed.
	Replayed bool
}

// Refusals. A bad credential is 401; a well-signed attestation MailOS will
// not apply is 400; an activation for a person not eligible is 403.
var (
	ErrNotEligible = apperrors.Forbidden("the subject is not eligible for this platform role")
)

func unauthorized(reason string) error {
	return apperrors.NewAppError(apperrors.KindUnauthorized, apperrors.CodeUnauthorized, "the attestation is not valid: "+reason)
}

func badRequest(format string, args ...any) error {
	return apperrors.BadRequest("the attestation cannot be applied: " + fmt.Sprintf(format, args...))
}

func unavailable(what string) error {
	return apperrors.Unavailable(what + " is unavailable; try again shortly")
}

func uuidClaim(claims map[string]any, name string) (string, error) {
	v := jwt.String(claims, name)
	if uuid.Validate(v) != nil {
		return "", badRequest("%s must be a UUID", name)
	}
	return strings.ToLower(v), nil
}

// Verify checks raw and returns its claims; it does not apply it.
func (s *Service) Verify(ctx context.Context, raw string) (Attestation, error) {
	claims, err := s.verifier.Verify(ctx, raw, Type)
	if err != nil {
		if errors.Is(err, jwt.ErrUnavailable) {
			return Attestation{}, unavailable("the IAM's approval key set")
		}
		logger.SecurityWarn("role attestation refused", logger.Err(err))
		return Attestation{}, unauthorized("signature")
	}
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != s.verifier.Issuer() {
		return Attestation{}, unauthorized("issuer")
	}
	if aud := jwt.Audiences(claims); len(aud) != 1 || aud[0] != Audience {
		return Attestation{}, unauthorized("audience")
	}
	if err := s.verifier.CheckTimes(claims); err != nil {
		return Attestation{}, unauthorized("expired or not yet valid")
	}
	a := Attestation{ID: jwt.String(claims, "jti"), Op: jwt.String(claims, "op"), Action: jwt.String(claims, "action")}
	a.IssuedAt, _ = jwt.NumericDate(claims, "iat")
	a.ExpiresAt, _ = jwt.NumericDate(claims, "exp")
	if a.ExpiresAt.Sub(a.IssuedAt) > MaxLifetime {
		return Attestation{}, unauthorized("lives longer than 10 minutes")
	}
	if a.ID == "" || len(a.ID) > 200 {
		return Attestation{}, unauthorized("no jti")
	}
	if a.Subject, err = uuidClaim(claims, "sub"); err != nil {
		return Attestation{}, err
	}
	role, ok := platformrole.Parse(jwt.String(claims, "role"))
	if !ok {
		return Attestation{}, badRequest("role %q is not a MailOS platform role", jwt.String(claims, "role"))
	}
	a.Role = role
	switch a.Op {
	case OpActivation:
		if a.Action != ActionActivate && a.Action != ActionEnd {
			return Attestation{}, badRequest("action %q is not activate or end", a.Action)
		}
		if a.RecordID, err = uuidClaim(claims, "activation_id"); err != nil {
			return Attestation{}, err
		}
	case OpEligibility:
		if a.Action != ActionAdd && a.Action != ActionRemove {
			return Attestation{}, badRequest("action %q is not add or remove", a.Action)
		}
		if a.RecordID, err = uuidClaim(claims, "eligibility_id"); err != nil {
			return Attestation{}, err
		}
	default:
		return Attestation{}, badRequest("op %q is not a MailOS role operation", a.Op)
	}
	if a.RequestedBy = jwt.String(claims, "requested_by"); a.RequestedBy != "" {
		if a.RequestedBy, err = uuidClaim(claims, "requested_by"); err != nil {
			return Attestation{}, err
		}
	}
	if a.ApprovedBy = jwt.String(claims, "approved_by"); a.ApprovedBy != "" {
		if a.ApprovedBy, err = uuidClaim(claims, "approved_by"); err != nil {
			return Attestation{}, err
		}
	}
	if a.Action != ActionActivate {
		return a, nil
	}
	until, ok := jwt.NumericDate(claims, "active_until")
	switch {
	case !ok:
		return Attestation{}, badRequest("an activation needs active_until")
	case !until.After(s.verifier.Now()):
		return Attestation{}, badRequest("active_until is in the past")
	case until.After(a.IssuedAt.Add(role.MaxActivation())):
		return Attestation{}, badRequest("active_until is past the %s an activation of %s may last", role.MaxActivation(), role)
	}
	a.ActiveUntil = until
	if a.RequestedBy == "" {
		return Attestation{}, badRequest("an activation needs requested_by")
	}
	if role.NeedsSecondApprover() && (a.ApprovedBy == "" || a.ApprovedBy == a.RequestedBy) {
		return Attestation{}, badRequest("%s needs a second approver who is not the requester", role)
	}
	return a, nil
}

// Apply verifies raw and writes it to ACS.
func (s *Service) Apply(ctx context.Context, raw string) (Result, error) {
	a, err := s.Verify(ctx, raw)
	if err != nil {
		return Result{}, err
	}
	res := Result{Attestation: a}
	jtiKey := "mailos:platform:attestation:jti:" + a.ID
	first, err := s.replay.ClaimOnce(ctx, jtiKey, time.Until(a.ExpiresAt)+time.Minute)
	if err != nil {
		return Result{}, unavailable("the replay guard")
	}
	if !first {
		res.Replayed = true
		logger.SecurityWarn("role attestation presented again; nothing changed", logger.String("jti", a.ID), logger.String("op", a.Op))
		return res, nil
	}
	replayed, err := s.apply(ctx, a)
	if err != nil {
		// Not applied: let the IAM deliver it again.
		if ferr := s.replay.Forget(context.WithoutCancel(ctx), jtiKey); ferr != nil {
			logger.Error("forget a role attestation that was not applied", logger.Err(ferr))
		}
		return Result{}, err
	}
	res.Replayed = replayed
	s.record(ctx, a, replayed)
	return res, nil
}

func closedKey(recordID string) string { return "mailos:platform:attestation:closed:" + recordID }

// apply makes the change; true means the record was closed before and
// nothing changed.
func (s *Service) apply(ctx context.Context, a Attestation) (bool, error) {
	switch a.Action {
	case ActionActivate, ActionAdd:
		closed, err := s.replay.Seen(ctx, closedKey(a.RecordID))
		if err != nil {
			return false, unavailable("the replay guard")
		}
		if closed {
			return true, nil
		}
	}
	var err error
	switch a.Action {
	case ActionActivate:
		var eligible bool
		if eligible, err = s.roles.Eligible(ctx, a.Subject, a.Role); err == nil && !eligible {
			logger.SecurityWarn("activation of a platform role for a person not eligible", logger.String("role", string(a.Role)))
			return false, ErrNotEligible
		}
		if err == nil {
			// ACS's horizon is from its own clock: never past it, even by
			// the iat skew (the IAM's end is kept or shortened, never
			// extended).
			until := a.ActiveUntil
			if ceiling := s.verifier.Now().Add(platformrole.MaxActivationCeiling); until.After(ceiling) {
				until = ceiling
			}
			err = s.roles.Activate(ctx, a.Subject, a.Role, until, a.ID)
		}
	case ActionEnd:
		err = s.roles.End(ctx, a.Subject, a.Role)
	case ActionAdd:
		err = s.roles.AddEligibility(ctx, a.Subject, a.Role)
	case ActionRemove:
		err = s.roles.RemoveEligibility(ctx, a.Subject, a.Role)
	}
	if err != nil {
		return false, err
	}
	if a.Action == ActionEnd || a.Action == ActionRemove {
		if _, err := s.replay.ClaimOnce(ctx, closedKey(a.RecordID), closedFor); err != nil {
			logger.Error("remember a closed platform role record", logger.Err(err))
		}
	}
	return false, nil
}

func (s *Service) record(ctx context.Context, a Attestation, replayed bool) {
	if s.audit == nil {
		return
	}
	action := map[string]string{ActionActivate: "platform_role.activated", ActionEnd: "platform_role.ended",
		ActionAdd: "platform_role.eligibility_added", ActionRemove: "platform_role.eligibility_removed"}[a.Action]
	meta := map[string]any{"role": string(a.Role), "subject": a.Subject, "record_id": a.RecordID, "attestation_id": a.ID,
		"requested_by": a.RequestedBy, "approved_by": a.ApprovedBy}
	if !a.ActiveUntil.IsZero() {
		meta["active_until"] = a.ActiveUntil.UTC().Format(time.RFC3339)
	}
	if replayed {
		meta["unchanged"] = "the record was already closed"
	}
	if err := s.audit.Append(ctx, "platform_role", a.Subject, action, meta); err != nil {
		logger.Error("audit "+action, logger.Err(err))
	}
}
