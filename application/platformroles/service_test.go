package platformroles_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/mail-os/application/platformroles"
	"github.com/razatechofficial/mail-os/domain/platformrole"
	"github.com/razatechofficial/mail-os/infrastructure/acs"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeacs"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeiam"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

type memReplay struct {
	mu   sync.Mutex
	keys map[string]bool
	fail bool
}

func (m *memReplay) ClaimOnce(_ context.Context, key string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return false, errors.New("redis down")
	}
	if m.keys[key] {
		return false, nil
	}
	m.keys[key] = true
	return true, nil
}

func (m *memReplay) Forget(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, key)
	return nil
}

func (m *memReplay) Seen(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[key], nil
}

type auditLog struct {
	mu      sync.Mutex
	actions []string
}

func (a *auditLog) Append(_ context.Context, _, _, action string, _ map[string]any) error {
	a.mu.Lock()
	a.actions = append(a.actions, action)
	a.mu.Unlock()
	return nil
}

type env struct {
	iam    *fakeiam.IAM
	acs    *fakeacs.ACS
	roles  acs.Platform
	replay *memReplay
	audit  *auditLog
	svc    *platformroles.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	iam, _ := fakeiam.NewServer(t)
	f, conn := fakeacs.Dial(t)
	e := &env{iam: iam, acs: f, roles: acs.Platform{Client: acs.New(conn, time.Second)}, replay: &memReplay{keys: map[string]bool{}}, audit: &auditLog{}}
	v := jwt.NewVerifier(jwt.Config{Issuer: iam.Issuer, JWKSURL: iam.ApprovalJWKSURL(), MinRefresh: time.Millisecond})
	e.svc = platformroles.New(v, e.roles, e.replay, e.audit)
	return e
}

var (
	alice     = "0d6f3a7e-5b1c-4c55-9f61-2f8f1c9b6a11"
	requester = alice
	approver  = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

func activation(role platformrole.Role, d time.Duration, extra map[string]any) map[string]any {
	c := map[string]any{"op": platformroles.OpActivation, "action": "activate", "sub": alice, "role": string(role),
		"active_until": time.Now().Add(d).Unix(), "activation_id": uuid.NewString(), "requested_by": requester}
	if role.NeedsSecondApprover() {
		c["approved_by"] = approver
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func eligibility(role platformrole.Role, action string, id string) map[string]any {
	return map[string]any{"op": platformroles.OpEligibility, "action": action, "sub": alice, "role": string(role),
		"eligibility_id": id, "requested_by": approver, "approved_by": approver}
}

func (e *env) allowed(t *testing.T, perm platformrole.Permission) bool {
	t.Helper()
	ok, err := e.roles.Allowed(context.Background(), alice, perm)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// Eligibility, then an activation, grants; ending it takes it away; the
// relationships are written in ACS's platform scope with the attested end.
func TestEligibilityActivationAndEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Apply(ctx, e.iam.Attestation(eligibility(platformrole.Operator, "add", uuid.NewString()))); err != nil {
		t.Fatal(err)
	}
	if e.allowed(t, platformrole.ViewTenants) {
		t.Fatal("eligibility alone grants")
	}
	act := activation(platformrole.Operator, 2*time.Hour, nil)
	res, err := e.svc.Apply(ctx, e.iam.Attestation(act))
	if err != nil || res.Replayed || res.Role != platformrole.Operator || res.Subject != alice {
		t.Fatalf("activate: %+v %v", res, err)
	}
	if !e.allowed(t, platformrole.ViewTenants) || e.allowed(t, platformrole.ManageKeys) {
		t.Fatal("operator's permissions")
	}
	active, _, err := e.roles.Holdings(ctx, alice)
	if err != nil || len(active) != 1 || active[0].ExpiresAt.Unix() != act["active_until"] {
		t.Fatalf("activation in ACS: %+v %v", active, err)
	}
	end := map[string]any{"op": platformroles.OpActivation, "action": "end", "sub": alice, "role": "platform_operator", "activation_id": act["activation_id"]}
	if _, err := e.svc.Apply(ctx, e.iam.Attestation(end)); err != nil {
		t.Fatal(err)
	}
	if e.allowed(t, platformrole.ViewTenants) {
		t.Fatal("an ended activation still grants")
	}
	want := []string{"platform_role.eligibility_added", "platform_role.activated", "platform_role.ended"}
	if len(e.audit.actions) != 3 || e.audit.actions[0] != want[0] || e.audit.actions[1] != want[1] || e.audit.actions[2] != want[2] {
		t.Fatalf("audit %v", e.audit.actions)
	}
	for _, c := range e.acs.Calls() {
		if c[len(c)-9:] != " platform" {
			t.Fatalf("call outside the platform scope: %s", c)
		}
	}
}

// An activation for someone not eligible is refused and writes nothing.
func TestActivationNeedsEligibility(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.Apply(context.Background(), e.iam.Attestation(activation(platformrole.Auditor, time.Hour, nil)))
	if !errors.Is(err, platformroles.ErrNotEligible) || apperrors.KindOf(err) != apperrors.KindForbidden {
		t.Fatalf("not eligible: %v", err)
	}
	if rels := e.acs.Relationships(); len(rels) != 0 {
		t.Fatalf("written: %v", rels)
	}
	// Refused, it may be delivered again once the person is eligible.
	raw := e.iam.Attestation(activation(platformrole.Auditor, time.Hour, nil))
	if _, err := e.svc.Apply(context.Background(), raw); err == nil {
		t.Fatal("accepted")
	}
	if _, err := e.svc.Apply(context.Background(), e.iam.Attestation(eligibility(platformrole.Auditor, "add", uuid.NewString()))); err != nil {
		t.Fatal(err)
	}
	if res, err := e.svc.Apply(context.Background(), raw); err != nil || res.Replayed {
		t.Fatalf("retried after eligibility: %+v %v", res, err)
	}
}

// A second presentation of an attestation changes nothing (answered as
// done); a delayed activation for an activation the IAM already ended does
// not bring it back; removing eligibility ends the activation.
func TestReplayAndClosedRecords(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	elig := uuid.NewString()
	if _, err := e.svc.Apply(ctx, e.iam.Attestation(eligibility(platformrole.Support, "add", elig))); err != nil {
		t.Fatal(err)
	}
	act := activation(platformrole.Support, time.Hour, nil)
	raw := e.iam.Attestation(act)
	if _, err := e.svc.Apply(ctx, raw); err != nil {
		t.Fatal(err)
	}
	end := e.iam.Attestation(map[string]any{"op": platformroles.OpActivation, "action": "end", "sub": alice, "role": "platform_support", "activation_id": act["activation_id"]})
	if _, err := e.svc.Apply(ctx, end); err != nil {
		t.Fatal(err)
	}
	if res, err := e.svc.Apply(ctx, raw); err != nil || !res.Replayed {
		t.Fatalf("replayed activation: %+v %v", res, err)
	}
	if e.allowed(t, platformrole.ViewTenants) {
		t.Fatal("a replayed activation granted again")
	}
	// The same record re-signed (a new jti) after its end: still closed.
	if res, err := e.svc.Apply(ctx, e.iam.Attestation(act)); err != nil || !res.Replayed {
		t.Fatalf("activation of an ended record: %+v %v", res, err)
	}
	if e.allowed(t, platformrole.ViewTenants) {
		t.Fatal("an ended activation came back")
	}

	if _, err := e.svc.Apply(ctx, e.iam.Attestation(activation(platformrole.Support, time.Hour, nil))); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, e.iam.Attestation(eligibility(platformrole.Support, "remove", elig))); err != nil {
		t.Fatal(err)
	}
	if e.allowed(t, platformrole.ViewTenants) {
		t.Fatal("removing eligibility left the activation")
	}
	if res, err := e.svc.Apply(ctx, e.iam.Attestation(eligibility(platformrole.Support, "add", elig))); err != nil || !res.Replayed {
		t.Fatalf("a removed eligibility re-added under the same record: %+v %v", res, err)
	}
}

// Bad credentials are 401, well-signed attestations MailOS will not apply
// 400; nothing reaches ACS for either.
func TestRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := time.Now()
	ok := activation(platformrole.Operator, time.Hour, nil)
	with := func(kv ...any) map[string]any {
		c := map[string]any{}
		for k, v := range ok {
			c[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			c[kv[i].(string)] = kv[i+1]
		}
		return c
	}
	tokenKeySigned := e.iam.Sign(e.iam.Keys[0], fakeiam.AttestationType, with("iss", e.iam.Issuer, "aud", "mailos",
		"iat", now.Unix(), "exp", now.Add(time.Minute).Unix(), "jti", "x"))
	unauthorized := map[string]string{
		"signed with the token key": tokenKeySigned,
		"wrong typ":                 e.iam.Sign(e.iam.Approval, "JWT", with("iss", e.iam.Issuer, "aud", "mailos", "iat", now.Unix(), "exp", now.Add(time.Minute).Unix(), "jti", "y")),
		"other issuer":              e.iam.Attestation(with("iss", "https://evil.example")),
		"other audience":            e.iam.Attestation(with("aud", "acs")),
		"two audiences":             e.iam.Attestation(with("aud", []string{"mailos", "acs"})),
		"expired":                   e.iam.Attestation(with("iat", now.Add(-20*time.Minute).Unix(), "exp", now.Add(-10*time.Minute).Unix())),
		"lives too long":            e.iam.Attestation(with("exp", now.Add(11*time.Minute).Unix())),
		"no exp":                    e.iam.Attestation(with("exp", nil)),
		"no jti":                    e.iam.Attestation(with("jti", nil)),
		"not a JWS":                 "not.a.jws",
	}
	for name, raw := range unauthorized {
		if _, err := e.svc.Apply(ctx, raw); apperrors.KindOf(err) != apperrors.KindUnauthorized {
			t.Errorf("%s: %v, want unauthorized", name, err)
		}
	}
	bad := map[string]map[string]any{
		"wrong op":                          with("op", "acs.tenant.bind"),
		"activation op, eligibility action": with("action", "add"),
		"eligibility op, activation action": with("op", platformroles.OpEligibility, "eligibility_id", uuid.NewString()),
		"unknown role":                      with("role", "mailos_admin"),
		"sub not a UUID":                    with("sub", "alice"),
		"no activation id":                  with("activation_id", nil),
		"no active_until":                   with("active_until", nil),
		"active_until in the past":          with("active_until", now.Add(-time.Minute).Unix()),
		"past the role's 8 h":               with("active_until", now.Add(8*time.Hour+time.Minute).Unix()),
		"owner past 4 h":                    with("role", "platform_owner", "approved_by", approver, "active_until", now.Add(4*time.Hour+time.Minute).Unix()),
		"owner without a second approver":   with("role", "platform_owner", "approved_by", ""),
		"publisher approving themselves":    with("role", "platform_template_publisher", "approved_by", requester),
		"no requester":                      with("requested_by", nil),
	}
	for name, c := range bad {
		if c["activation_id"] == nil {
			delete(c, "activation_id")
		}
		if _, err := e.svc.Apply(ctx, e.iam.Attestation(c)); apperrors.KindOf(err) != apperrors.KindBadRequest {
			t.Errorf("%s: %v, want bad request", name, err)
		}
	}
	if calls := e.acs.Calls(); len(calls) != 0 {
		t.Fatalf("ACS called for refused attestations: %v", calls)
	}
}

// A 4 h role may be activated for 4 h with a second approver.
func TestFourHourRoles(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, r := range []platformrole.Role{platformrole.Owner, platformrole.TemplatePublisher, platformrole.KeyCustodian} {
		if _, err := e.svc.Apply(ctx, e.iam.Attestation(eligibility(r, "add", uuid.NewString()))); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Apply(ctx, e.iam.Attestation(activation(r, 4*time.Hour-time.Minute, nil))); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
	if !e.allowed(t, platformrole.ManageKeys) || !e.allowed(t, platformrole.PublishTemplates) {
		t.Fatal("4 h roles not active")
	}
}

// ACS or the replay guard down: 503, and the attestation may be delivered
// again.
func TestUnavailable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	raw := e.iam.Attestation(eligibility(platformrole.Auditor, "add", uuid.NewString()))
	e.acs.SetUnavailable(true)
	if _, err := e.svc.Apply(ctx, raw); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("ACS down: %v", err)
	}
	e.acs.SetUnavailable(false)
	if res, err := e.svc.Apply(ctx, raw); err != nil || res.Replayed {
		t.Fatalf("redelivered: %+v %v", res, err)
	}
	e.replay.fail = true
	if _, err := e.svc.Apply(ctx, e.iam.Attestation(eligibility(platformrole.Auditor, "remove", uuid.NewString()))); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("replay guard down: %v", err)
	}
}

// The IAM may end an activation it never delivered, and sends an
// eligibility removal of its own (no requester, no approver): both are
// applied (deleting what is not there is success), and the ended record
// stays closed if its activation arrives late.
func TestEndWithoutActivateAndUnattributedRemoval(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id := uuid.NewString()
	end := map[string]any{"op": platformroles.OpActivation, "action": "end", "sub": alice, "role": "platform_operator", "activation_id": id}
	if res, err := e.svc.Apply(ctx, e.iam.Attestation(end)); err != nil || res.Replayed {
		t.Fatalf("end before activate: %+v %v", res, err)
	}
	if _, err := e.svc.Apply(ctx, e.iam.Attestation(eligibility(platformrole.Operator, "add", uuid.NewString()))); err != nil {
		t.Fatal(err)
	}
	late := activation(platformrole.Operator, time.Hour, map[string]any{"activation_id": id})
	if res, err := e.svc.Apply(ctx, e.iam.Attestation(late)); err != nil || !res.Replayed {
		t.Fatalf("late activation of an ended record: %+v %v", res, err)
	}
	if e.allowed(t, platformrole.ViewTenants) {
		t.Fatal("a late activation granted")
	}
	remove := map[string]any{"op": platformroles.OpEligibility, "action": "remove", "sub": alice, "role": "platform_operator",
		"eligibility_id": uuid.NewString(), "requested_by": "", "approved_by": ""}
	if _, err := e.svc.Apply(ctx, e.iam.Attestation(remove)); err != nil {
		t.Fatalf("removal without requester or approver: %v", err)
	}
}
